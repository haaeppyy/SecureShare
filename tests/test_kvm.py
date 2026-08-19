"""Engine-level KVM tests: a fake InputPlatform drives two real Nodes over loopback.

The control flow is an acknowledged handoff, never a direct takeover:

    controller:  chord/edge -> requesting -> (READY) -> controlling -> (ACTIVE)
    target:      (REQUEST) -> remote_preparing -> remote

Local input is suppressed only after CONTROL_ACTIVE: the controller's
platform delegation stays "local" until the remote confirmed.

Ownership policy: the edge-seam handoff is the primary takeover (the
cursor crosses the shared edge and control jumps), re-enabled by default
after the explicit-ownership stage. The Ctrl+Alt+Space chord and the
per-device menu both request control (when idle) and release it (when
active); physical input on the controlled device NEVER hands control
back - only the chord, the menu, the lease (6 s without renewal), or a
disconnect does.
"""

import base64
import json
import os
import socket
import struct
import threading
import time

import pytest

from core import crypto
from core.kvm import KVMEngine, KvmChannel
from core.kvm_events import (
    KIND_ALL_KEYS_UP,
    KIND_CONTROL_REVERT,
    unpack_frame,
)
from core.kvm_events import (
    KIND_CONTROL_BEGIN,
    KIND_CONTROL_REQUEST,
    KIND_KEY_DOWN,
    KIND_MOUSE_MOVE_REL,
    encode_control_request,
    encode_key,
    pack_frame,
    unpack_frame,
)
from core.kvm_geometry import Monitor, ScreenLayout
from core.kvm_keymap import mac_vk_to_hid
from core.transfer import recv_frame, send_frame
from core.trust_store import TrustStore


class FakePlatform:
    """In-memory InputPlatform; simulates the OS cursor and records injections."""

    def __init__(self, name, monitors=None, on_display_change=None):
        self.name = name
        self.monitors = monitors or [{"x": 0, "y": 0, "w": 1440, "h": 900, "scale": 1.0}]
        self.on_display_change = on_display_change
        self.engine = None
        self.delegation = "local"
        self.cursor = (700, 450)
        self.cursor_hidden = False
        self.injected = []
        self.permissions_ok = True
        self.delegation_fails = False
        self.delegation_calls = []
        self.restarts = 0

    def start(self, engine):
        self.engine = engine
        self.restarts += 1

    def stop(self):
        pass

    def permission_ok(self):
        return self.permissions_ok

    def screen_layout(self):
        return ScreenLayout([Monitor(**m) for m in self.monitors], primary=0)

    def cursor_position(self):
        return self.cursor

    def warp_cursor(self, x, y):
        self.cursor = (x, y)

    def hide_cursor(self):
        self.cursor_hidden = True

    def show_cursor(self):
        self.cursor_hidden = False

    def set_delegation(self, state):
        self.delegation_calls.append(state)
        if self.delegation_fails:
            return False
        self.delegation = state
        return True

    def inject_move_rel(self, dx, dy):
        self.injected.append(("rel", dx, dy))
        self.cursor = (self.cursor[0] + dx, self.cursor[1] + dy)

    def inject_move_abs(self, x, y):
        self.injected.append(("abs", x, y))
        self.cursor = (x, y)

    def inject_button(self, button, down):
        self.injected.append(("button", button, down))

    def inject_wheel(self, dy, dx):
        self.injected.append(("wheel", dy, dx))

    def inject_key(self, hid, down):
        self.injected.append(("key", hid, down))

    # -- simulated physical input ----------------------------------------------
    # The platform is the dispatcher: observation is always reported
    # (seam/chord), transmission only while controlling.

    def move(self, dx, dy):
        x, y = self.cursor
        nx, ny = x + dx, y + dy
        self.cursor = (nx, ny)
        self.engine.observe_local_mouse(dx, dy, nx, ny)
        if self.delegation == "controlling":
            self.engine.send_controlled_mouse(dx, dy)

    def press(self, hid):
        self.engine.observe_local_key(hid, True)
        if self.delegation == "controlling":
            self.engine.send_controlled_key(hid, True)

    def release(self, hid):
        self.engine.observe_local_key(hid, False)
        if self.delegation == "controlling":
            self.engine.send_controlled_key(hid, False)

    def click(self, button, down):
        self.engine.observe_local_button(button, down)
        if self.delegation == "controlling":
            self.engine.send_controlled_button(button, down)

    def scroll(self, dy, dx=0):
        self.engine.observe_local_wheel(dy, dx)
        if self.delegation == "controlling":
            self.engine.send_controlled_wheel(dy, dx)

    def edge(self, side, x, y):
        self.engine.on_remote_edge(side, x, y)


def wait_for(predicate, timeout=10.0, interval=0.05):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def make_pair(tmp_path, b_width=1920, b_height=1080):
    plat_a = FakePlatform("AlphaScreen", [{"x": 0, "y": 0, "w": 1440, "h": 900, "scale": 1.0}])
    plat_b = FakePlatform(
        "BetaScreen", [{"x": 0, "y": 0, "w": b_width, "h": b_height, "scale": 1.0}]
    )
    from tests.conftest import NodePair

    pair = NodePair(str(tmp_path), kvm_platforms={"a": plat_a, "b": plat_b}).start()
    pair.pair()
    fp_a = pair.b.store.fingerprint()
    fp_b = pair.a.store.fingerprint()
    pair.a.store.set_peer_kvm_allowed(fp_a, True)
    pair.b.store.set_peer_kvm_allowed(fp_b, True)
    pair.a.store.set_peer_kvm_side(fp_a, "right")
    pair.b.store.set_peer_kvm_side(fp_b, "left")
    pair.a.kvm.set_enabled(True)
    pair.b.kvm.set_enabled(True)
    return pair, plat_a, plat_b


def wait_linked(pair):
    ok = wait_for(lambda: pair.a.kvm._channels and pair.b.kvm._channels)
    assert ok, "KVM channels did not open"
    ok = wait_for(lambda: pair.b.kvm._peer_layouts and pair.a.kvm._peer_layouts)
    assert ok, "screen info was not exchanged"


def wait_injected(plat, item, timeout=5.0):
    ok = wait_for(lambda: item in plat.injected, timeout=timeout)
    assert ok, f"{item!r} never reached {plat.name}; got {plat.injected!r}"


def chord(plat, release=True):
    """Press Ctrl+Alt+Space (the ownership chord) on a platform."""
    for hid in (0x94, 0x96):  # left ctrl + left alt
        plat.press(hid)
    plat.press(0x2C)  # space completes ctrl+alt+space
    if release:
        plat.release(0x2C)
        for hid in (0x94, 0x96):
            plat.release(hid)


def take_control(pair, plat_a, plat_b):
    """Drive the full acknowledged handoff A -> B and return when active.

    A presses the ownership chord (Ctrl+Alt+Space), which requests control
    of the single ready peer; the handshake completes when B is remote and
    A's delegation is "controlling" (input suppressed on A only after
    ACTIVE).
    """
    fp_b = pair.b.store.fingerprint()
    chord(plat_a)
    ok = wait_for(lambda: pair.a.kvm._state.get(fp_b) == "requesting")
    assert ok, f"A never entered requesting; got {pair.a.kvm._state}"
    ok = wait_for(lambda: pair.a.kvm._state.get(fp_b) == "controlling")
    assert ok, "A never got READY -> controlling"
    ok = wait_for(lambda: pair.b.kvm._state.get(pair.a.store.fingerprint()) == "remote")
    assert ok, "B never entered remote"
    ok = wait_for(lambda: pair.a.kvm.platform.delegation == "controlling")
    assert ok, "A never suppressed input (ACTIVE never arrived)"
    return fp_b


def test_link_and_screen_info(node_pair_ctx):
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    assert pair.a.kvm._topology_ok[pair.b.store.fingerprint()] is True
    assert pair.b.kvm._topology_ok[pair.a.store.fingerprint()] is True
    assert pair.a.kvm._peer_layouts[pair.b.store.fingerprint()].right() == 1920
    assert pair.a.kvm.link_status(pair.b.store.fingerprint()) == "ready"
    assert pair.b.kvm.link_status(pair.a.store.fingerprint()) == "ready"
    assert pair.a.kvm.control_state(pair.b.store.fingerprint()) == "local"


@pytest.fixture
def node_pair_ctx(tmp_path):
    pair, plat_a, plat_b = make_pair(tmp_path)
    yield pair, plat_a, plat_b
    pair.stop()


def test_take_control_and_drive(node_pair_ctx):
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    fp_b = take_control(pair, plat_a, plat_b)
    assert plat_b.delegation == "remote"

    # The handoff parks at B's screen center (the chord request has no seam).
    assert ("abs", 960, 540) in plat_b.injected

    # relative moves stream across
    plat_a.move(10, 20)
    wait_injected(plat_b, ("rel", 10, 20))

    # key press streams across
    hid = mac_vk_to_hid(0x00)
    plat_a.press(hid)
    plat_a.release(hid)
    wait_injected(plat_b, ("key", hid, True))
    wait_injected(plat_b, ("key", hid, False))

    # wheel streams across
    plat_a.scroll(120, 0)
    wait_injected(plat_b, ("wheel", 120, 0))

    # buttons stream across
    plat_a.click(1, True)
    plat_a.click(1, False)
    wait_injected(plat_b, ("button", 1, True))
    wait_injected(plat_b, ("button", 1, False))

    # input from the local target must NOT be forwarded (it is suppressed)
    assert ("rel", 5, 5) not in plat_b.injected


def test_key_autorepeat_forwarded_to_target(node_pair_ctx):
    """Held keys repeat on the target: every controller key-down (initial
    and autorepeat) is injected, and the key-up exactly once. The Windows
    SendInput injector does not auto-repeat, so repeats must travel."""
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    fp_b = take_control(pair, plat_a, plat_b)
    hid = mac_vk_to_hid(0x33)  # Backspace
    for _ in range(3):
        pair.a.kvm.observe_local_key(hid, True)
        pair.a.kvm.send_controlled_key(hid, True)
    pair.a.kvm.observe_local_key(hid, False)
    pair.a.kvm.send_controlled_key(hid, False)
    ok = wait_for(
        lambda: sum(1 for i in plat_b.injected if i == ("key", hid, True)) >= 3,
        timeout=5,
    )
    assert ok, f"repeated key-downs never reached B; got {plat_b.injected}"
    assert sum(1 for i in plat_b.injected if i == ("key", hid, False)) == 1
    assert pair.a.kvm._state.get(fp_b) == "controlling"
    assert plat_b.delegation == "remote"


def test_no_suppression_before_active(node_pair_ctx, monkeypatch):
    """The controller must not swallow local input before CONTROL_ACTIVE."""
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    fp_b = pair.b.store.fingerprint()
    original_begin = pair.b.kvm._on_control_begin
    pending_begin = []

    def stalled_begin(channel, body):
        pending_begin.append((channel, body))  # swallow BEGIN: no ACTIVE yet

    monkeypatch.setattr(pair.b.kvm, "_on_control_begin", stalled_begin)
    chord(plat_a)  # request starts
    ok = wait_for(lambda: pair.a.kvm._state.get(fp_b) == "requesting")
    assert ok
    # READY arrived: A is "controlling" (waiting_active), cursor parked, but
    # delegation must still be local because ACTIVE has not arrived yet
    ok = wait_for(
        lambda: pair.a.kvm._handoffs.get(fp_b, {}).get("stage") == "waiting_active"
    )
    assert ok, "handoff never reached waiting_active"
    assert pair.a.kvm._state.get(fp_b) == "controlling"
    assert pair.a.kvm.platform.delegation == "local"
    assert plat_a.cursor_hidden, "cursor should be parked once READY arrived"
    # input pressed while waiting must not reach the peer
    hid = mac_vk_to_hid(0x00)
    plat_a.press(hid)
    assert ("key", hid, True) not in plat_b.injected
    plat_a.release(hid)
    # un-stall: the genuine ACTIVE completes the handoff; nothing was lost
    monkeypatch.setattr(pair.b.kvm, "_on_control_begin", original_begin)
    for channel, body in pending_begin:
        pair.b.kvm.handle_event(channel, KIND_CONTROL_BEGIN, body)
    ok = wait_for(lambda: pair.a.kvm.platform.delegation == "controlling")
    assert ok, "handoff never completed after un-stalling"


def test_physical_input_on_target_does_not_hand_back(node_pair_ctx):
    """Stage 1 explicit ownership: a real pointer move on the controlled
    device must NOT end sharing. Only the chord (or lease/disconnect) does.
    """
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    fp_b = take_control(pair, plat_a, plat_b)
    plat_b.move(1, 0)  # physical pointer move on the controlled device
    time.sleep(0.3)  # give the old auto-revert policy time to (wrongly) fire
    assert pair.a.kvm._state.get(fp_b) == "controlling"
    assert pair.b.kvm.control_state(pair.a.store.fingerprint()) == "remote"
    assert plat_b.delegation == "remote"
    assert pair.b.kvm._stats.get("reverts_sent", 0) == 0
    # the chord still hands control back, restoring A's cursor at the seam
    chord(plat_b)
    ok = wait_for(lambda: pair.a.kvm._state.get(fp_b) == "local", timeout=5)
    assert ok, "A never handed back control"
    assert plat_b.delegation == "local"
    assert plat_a.cursor[0] == 1435  # restored on A's seam, inset past jump zone
    assert abs(plat_a.cursor[1] - 450) <= 1  # mirrored y (fraction 0.5)
    assert plat_a.cursor_hidden is False


def test_handback_blocks_former_controller_edge(node_pair_ctx):
    """A target-driven revert must latch the former controller's edge.

    B's chord hands control back; A's edge stays blocked while the
    cursor remains near it (LATCH_ZONE), so residual motion cannot start a
    fresh CONTROL_REQUEST.  Leaving the edge clears the latch, and a
    deliberate re-entry is allowed again (seam handoff re-enabled here to
    exercise the latch machinery).
    """
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    fp_b = pair.b.store.fingerprint()
    pair.a.kvm.edge_handoff_enabled = True
    take_control(pair, plat_a, plat_b)
    chord(plat_b)  # B reclaims explicitly
    ok = wait_for(lambda: pair.a.kvm._state.get(fp_b) == "local", timeout=5)
    assert ok, "A never handed back control"
    assert pair.b.kvm.control_state(pair.a.store.fingerprint()) == "local"
    assert plat_b.delegation == "local"
    assert pair.a.kvm._blocked_edge.get(fp_b) == "right", "revert must latch the edge"
    # A wiggles at the restored seam position: no fresh request, A stays local.
    plat_a.move(2, 0)  # (1435, 450) -> (1437, 450): inside the 3 px jump zone
    assert pair.a.kvm._state.get(fp_b) == "local", "edge latch did not hold"
    assert pair.a.kvm._handoffs.get(fp_b) is None
    assert pair.b.kvm.control_state(pair.a.store.fingerprint()) == "local"
    # Still close to the edge: more movement must not clear the latch.
    plat_a.move(-1, 0)  # (1436, 450) -> still in the latch zone
    assert pair.a.kvm._state.get(fp_b) == "local"
    # Clearly leave the edge: the latch clears.
    plat_a.move(-16, 0)  # -> (1420, 450): outside LATCH_ZONE
    ok = wait_for(lambda: pair.a.kvm._blocked_edge.get(fp_b) is None, timeout=5)
    assert ok, "leaving the edge must clear the latch"
    assert pair.a.kvm._state.get(fp_b) == "local"
    # Deliberate re-entry is a fresh handoff.
    plat_a.move(20, 0)  # -> (1440, 450): back on the seam
    ok = wait_for(lambda: pair.a.kvm._state.get(fp_b) == "requesting", timeout=5)
    assert ok, "deliberate re-entry must be allowed after the latch cleared"
    assert pair.a.kvm.diagnostics()["blocked_edges"].get(fp_b) is None


def test_revert_sequence_recorded_in_diagnostics(node_pair_ctx):
    """A matched target-originated revert records accepted -> completed in
    the revert log, walks controlling -> reverting -> local, clears the
    handoff, and leaves the former-controller edge latch set."""
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    fp_b = pair.b.store.fingerprint()
    take_control(pair, plat_a, plat_b)
    chord(plat_b)  # B reclaims explicitly
    ok = wait_for(lambda: pair.a.kvm._state.get(fp_b) == "local", timeout=5)
    assert ok, "A never handed back control"
    # structured revert log: accepted then completed
    phases = [r["phase"] for r in pair.a.kvm._revert_log]
    assert phases[-2:] == ["accepted", "completed"], phases
    assert pair.a.kvm._last_revert["state"] == "local"
    assert pair.a.kvm._last_revert["id"] == pair.a.kvm._revert_log[-1]["id"]
    # transition sequence: controlling -> reverting -> local
    states = [t[2] for t in pair.a.kvm.recent_transitions() if t[1] == fp_b]
    assert "reverting" in states
    assert states[-1] == "local"
    # handoff cleared, former-controller latch set
    assert fp_b not in pair.a.kvm._handoffs
    assert pair.a.kvm._blocked_edge.get(fp_b) == "right"
    assert pair.a.kvm.diagnostics()["blocked_edges"].get(fp_b) == "right"
    # diagnostics expose the new fields
    diag = pair.a.kvm.diagnostics()
    assert "last_revert" in diag and "revert_log" in diag
    assert "last_request" in diag and "request_log" in diag
    assert "handoffs" in diag and "denial_latch" in diag


def test_revert_grace_expires_allowing_edge_retake(node_pair_ctx):
    """The former-controller latch must be time-bounded for reverts: while
    the grace window is active the restored cursor position cannot re-take
    control; once it expires, moving back to the edge does."""
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    fp_b = pair.b.store.fingerprint()
    pair.a.kvm.edge_handoff_enabled = True
    take_control(pair, plat_a, plat_b)
    chord(plat_b)  # B reclaims explicitly
    ok = wait_for(lambda: pair.a.kvm._state.get(fp_b) == "local", timeout=5)
    assert ok
    assert pair.a.kvm._blocked_edge.get(fp_b) == "right"
    # Inside the grace window the restored cursor (4 px inside the seam,
    # inside LATCH_ZONE) cannot re-take, even at the seam.
    plat_a.move(4, 0)  # (1440, 450): exactly on the seam
    assert pair.a.kvm._state.get(fp_b) == "local", "grace window did not hold"
    # Expire the grace: the same deliberate move now re-takes control.
    pair.a.kvm._blocked_until[fp_b] = time.monotonic() - 1
    plat_a.move(1, 0)
    ok = wait_for(lambda: pair.a.kvm._state.get(fp_b) == "controlling", timeout=5)
    assert ok, "re-take after the grace window failed"
    assert fp_b not in pair.a.kvm._blocked_edge


def test_refusal_latch_never_expires(node_pair_ctx):
    """Refusals stay spatial-only: the blocked edge must not silently
    expire while the cursor sits on the rejected seam (no refusal-toast
    spam every REVERT_GRACE seconds)."""
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    pair.b.store.set_peer_kvm_allowed(pair.a.store.fingerprint(), False)
    fp_b = pair.b.store.fingerprint()
    pair.a.kvm.edge_handoff_enabled = True
    plat_a.move(740, 0)
    ok = wait_for(lambda: pair.a.kvm._blocked_edge.get(fp_b) is not None, timeout=5)
    assert ok, "A should have been refused"
    # refusals get no grace deadline: the latch must stay spatial-only
    assert pair.a.kvm._blocked_until.get(fp_b, float("inf")) == float("inf")
    plat_a.move(1, 0)  # wiggle on the edge
    assert pair.a.kvm._state.get(fp_b) == "local", "refusal latch must not expire"
    assert pair.a.kvm._blocked_edge.get(fp_b) == "right"


def test_reverse_direction_handoff_after_handback(node_pair_ctx):
    """After B takes its control back, B can immediately cross to its own
    edge and control A: the former-controller latch must not block the new
    controller."""
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    fp_b = pair.b.store.fingerprint()
    fp_a = pair.a.store.fingerprint()
    take_control(pair, plat_a, plat_b)
    chord(plat_b)  # B reclaims explicitly
    ok = wait_for(lambda: pair.a.kvm._state.get(fp_b) == "local", timeout=5)
    assert ok
    assert pair.a.kvm._blocked_edge.get(fp_b) == "right"
    # B crosses its own seam to control A (seam handoff re-enabled for B).
    pair.b.kvm.edge_handoff_enabled = True
    plat_b.cursor = (700, 540)
    plat_b.move(-700, 0)  # -> (0, 540): B's left jump zone
    ok = wait_for(lambda: pair.b.kvm._state.get(fp_a) == "controlling", timeout=5)
    assert ok, "B never took control of A"
    ok = wait_for(lambda: pair.a.kvm._state.get(fp_b) == "remote", timeout=5)
    assert ok, "A never entered remote"
    # A's former-controller latch for B was still set while B's inbound
    # request was accepted: the latch must not block incoming takeovers.
    assert pair.b.kvm._last_request["decision"] == "accepted"
    assert pair.a.kvm._last_request is None or pair.a.kvm._last_request["decision"] in (
        "accepted",
        "ignored",
    )
    assert plat_b.delegation == "controlling"
    assert plat_a.delegation == "remote"


def test_escape_latches_until_edge_exit_then_retake(node_pair_ctx):
    """The escape chord restores both sides to local and latches the
    former controller's edge too; a new handoff works after edge
    exit/re-entry."""
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    fp_b = pair.b.store.fingerprint()
    pair.a.kvm.edge_handoff_enabled = True
    take_control(pair, plat_a, plat_b)
    chord(plat_a)  # A releases via the chord
    ok = wait_for(lambda: pair.a.kvm._state.get(fp_b) == "local", timeout=5)
    assert ok
    assert wait_for(lambda: plat_b.delegation == "local", timeout=5)
    assert pair.a.kvm._blocked_edge.get(fp_b) == "right", "escape must latch the edge"
    # Residual wiggle at the seam must not re-acquire.
    plat_a.move(2, 0)
    assert pair.a.kvm._state.get(fp_b) == "local"
    # Exit the latch zone, then deliberately re-enter: handoff completes.
    plat_a.move(-16, 0)  # -> (1421, 450)
    ok = wait_for(lambda: pair.a.kvm._blocked_edge.get(fp_b) is None, timeout=5)
    assert ok
    plat_a.move(19, 0)  # -> (1440, 450)
    ok = wait_for(lambda: pair.a.kvm._state.get(fp_b) == "requesting", timeout=5)
    assert ok
    ok = wait_for(lambda: pair.a.kvm.platform.delegation == "controlling", timeout=5)
    assert ok, "new handoff never completed after escape + exit/re-entry"


def test_channel_loss_does_not_latch_and_recovers(node_pair_ctx):
    """Channel loss must not leave a latch: it tears the per-peer state
    down, so a fresh link can hand off again immediately."""
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    fp_b = pair.b.store.fingerprint()
    take_control(pair, plat_a, plat_b)
    pair.a.kvm._channels[fp_b].close()
    ok = wait_for(lambda: pair.a.kvm._state.get(fp_b) is None, timeout=5)
    assert ok
    assert pair.a.kvm._blocked_edge.get(fp_b) is None, "channel loss must not latch"
    assert plat_a.delegation == "local"
    # Re-link and complete a fresh handoff.
    ok = wait_for(
        lambda: fp_b in pair.a.kvm._channels and pair.a.store.fingerprint() in pair.b.kvm._channels,
        timeout=20,
    )
    assert ok, "channel must re-establish after teardown"
    ok = wait_for(lambda: pair.a.kvm.link_status(fp_b) == "ready", timeout=5)
    assert ok, "screen info must be exchanged again before a fresh handoff"
    chord(plat_a)
    ok = wait_for(lambda: pair.a.kvm._state.get(fp_b) == "controlling", timeout=5)
    assert ok, "fresh handoff after channel loss failed"
    assert plat_b.delegation == "remote"


def test_controller_delegation_single_association_until_revert(node_pair_ctx):
    """Problem A seam: the controller enters delegation exactly once and
    stays there (no local re-association) while controlling; physical
    movement is swallowed and forwarded only, never treated as a handback;
    the single local restore happens on revert."""
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    fp_b = pair.b.store.fingerprint()
    base = len(plat_a.delegation_calls)  # ignore pre-takeover link-setup calls
    take_control(pair, plat_a, plat_b)
    assert plat_a.delegation_calls[base:] == ["controlling"], (
        f"expected exactly one controlling delegation, got {plat_a.delegation_calls[base:]}"
    )
    # Physical movement while controlling is forwarded, never a handback.
    for _ in range(5):
        plat_a.move(2, 0)
    wait_injected(plat_b, ("rel", 10, 0))  # coalesced into one frame
    assert plat_a.delegation_calls[base:] == ["controlling"], (
        "delegation must not change while controlling"
    )
    assert pair.a.kvm.control_state(fp_b) == "controlling"
    # Peer revert (chord on B): exactly one local restore.
    chord(plat_b)
    ok = wait_for(lambda: pair.a.kvm._state.get(fp_b) == "local", timeout=5)
    assert ok
    assert plat_a.delegation_calls[base:] == ["controlling", "local"], (
        f"revert must restore local exactly once, got {plat_a.delegation_calls[base:]}"
    )


def test_sustained_relative_motion_does_not_handback(node_pair_ctx):
    """A sustained, coalesced stream of relative motion while the target is
    remote must keep both state machines active and never emit a revert:
    relative injection is sentinel-tagged transport, not physical input."""
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    fp_b = take_control(pair, plat_a, plat_b)
    fp_a = pair.a.store.fingerprint()
    for _ in range(300):
        plat_a.move(3, 2)
    ok = wait_for(
        lambda: sum(r[1] for r in plat_b.injected if r[0] == "rel") >= 900, timeout=10
    )
    assert ok, f"sustained motion never reached B; got {plat_b.injected[-5:]}"
    assert sum(r[1] for r in plat_b.injected if r[0] == "rel") == 900
    assert sum(r[2] for r in plat_b.injected if r[0] == "rel") == 600
    assert pair.a.kvm._state.get(fp_b) == "controlling"
    assert pair.b.kvm._state.get(fp_a) == "remote"
    assert pair.b.kvm._stats.get("reverts_sent", 0) == 0, (
        "relative injection must never look like physical input"
    )
    assert pair.a.kvm.platform.delegation == "controlling"


def test_hand_back_releases_pressed_keys(node_pair_ctx):
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    take_control(pair, plat_a, plat_b)
    hid = mac_vk_to_hid(0x0F)  # T
    plat_a.press(hid)  # key still held when control is handed back
    wait_injected(plat_b, ("key", hid, True))  # B must apply it before reverting
    chord(plat_b)  # B reclaims explicitly
    ok = wait_for(
        lambda: pair.a.kvm._state[pair.b.store.fingerprint()] == "local",
        timeout=5,
    )
    assert ok
    wait_injected(plat_b, ("key", hid, True))
    wait_injected(plat_b, ("key", hid, False))  # released on the far side


def test_remote_rejects_without_consent(node_pair_ctx):
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    pair.b.store.set_peer_kvm_allowed(pair.a.store.fingerprint(), False)
    fp_b = pair.b.store.fingerprint()
    chord(plat_a)
    ok = wait_for(lambda: pair.a.kvm._blocked_edge.get(fp_b) is not None, timeout=5)
    assert ok, "A should have been refused"
    assert pair.a.kvm._state.get(fp_b) == "local"
    assert pair.a.kvm.platform.delegation == "local"
    assert plat_b.delegation == "local"
    assert pair.b.kvm._last_request["decision"] == "rejected"
    assert pair.b.kvm._last_request["reason"] == "denied"
    # the refusal latch clears once the pointer leaves the seam (mid-screen
    # here): a fresh chord is answered again and refused again
    plat_a.move(-20, 0)
    ok = wait_for(lambda: pair.a.kvm._blocked_edge.get(fp_b) is None, timeout=5)
    assert ok, "refusal latch must clear once the pointer leaves the edge"
    chord(plat_a)
    ok = wait_for(lambda: pair.b.kvm._last_request["decision"] == "rejected", timeout=5)
    assert ok
    ok = wait_for(lambda: pair.a.kvm._state.get(fp_b) == "local", timeout=5)
    assert ok, "A must return to local after the second refusal"
    assert plat_b.delegation == "local"


def test_denial_deduplicated_until_edge_left(node_pair_ctx):
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    pair.b.store.set_peer_kvm_allowed(pair.a.store.fingerprint(), False)
    fp_a = pair.a.store.fingerprint()
    fp_b = pair.b.store.fingerprint()
    chord(plat_a)
    ok = wait_for(lambda: fp_a in pair.b.kvm._denial_latch, timeout=5)
    assert ok, "target never latched a denial"
    # while the target's denial latch is set, a repeat request is ignored
    # (deduplicated), not re-refused
    chord(plat_a)
    ok = wait_for(
        lambda: pair.b.kvm._last_request["decision"] == "ignored"
        and pair.b.kvm._last_request["reason"] == "denial_latch",
        timeout=5,
    )
    assert ok, "denial must be deduplicated while the latch is set"
    # no CANCEL comes back for an ignored request: A times out on its own
    ok = wait_for(lambda: pair.a.kvm._state.get(fp_b) == "local", timeout=10)
    assert ok, "ignored request must expire locally"
    # once the controller's pointer leaves the edge, the edge-left cancel
    # clears the latch and a fresh chord is refused again
    plat_a.move(-20, 0)
    ok = wait_for(lambda: fp_a not in pair.b.kvm._denial_latch, timeout=5)
    assert ok, "denial latch was never cleared after leaving the edge"
    assert pair.a.kvm._blocked_edge.get(fp_b) is None
    chord(plat_a)
    ok = wait_for(lambda: pair.b.kvm._last_request["decision"] == "rejected", timeout=5)
    assert ok, "fresh request after latch clear must be refused, not ignored"


def test_remote_side_change_breaks_takeover(node_pair_ctx):
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    pair.a.store.set_peer_kvm_side(pair.b.store.fingerprint(), "top")
    pair.b.store.set_peer_kvm_side(pair.a.store.fingerprint(), "top")
    pair.a.kvm._send_screen_info(pair.a.kvm._channels[pair.b.store.fingerprint()])
    pair.b.kvm._send_screen_info(pair.b.kvm._channels[pair.a.store.fingerprint()])
    ok = wait_for(
        lambda: pair.a.kvm._topology_ok.get(pair.b.store.fingerprint()) is False
        and pair.b.kvm._topology_ok.get(pair.a.store.fingerprint()) is False
    )
    assert ok
    chord(plat_a)
    assert pair.a.kvm._state.get(pair.b.store.fingerprint()) != "controlling"
    assert plat_b.delegation == "local"


def test_control_request_decision_records(node_pair_ctx):
    """Every incoming CONTROL_REQUEST records a structured decision for F6
    diagnostics: accepted, or rejected/ignored with its reason."""
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    fp_a = pair.a.store.fingerprint()
    ch = pair.b.kvm._channels[fp_a]

    def request(hid, channel=ch):
        pair.b.kvm._on_control_request(channel, encode_control_request(hid, 200, 450, 0))

    # accepted: request becomes the in-flight handoff
    request(101)
    assert pair.b.kvm._last_request["decision"] == "accepted"
    assert pair.b.kvm._last_request["id"] == 101
    assert pair.b.kvm._state.get(fp_a) == "remote_preparing"
    # cleanup: cancel the accepted handoff back to local
    pair.b.kvm._revert_remote(ch, "test cleanup")
    assert pair.b.kvm._state.get(fp_a) == "local"

    # duplicate of the in-flight attempt
    request(102)
    assert pair.b.kvm._last_request["decision"] == "accepted"
    request(102)
    assert pair.b.kvm._last_request["decision"] == "ignored"
    assert pair.b.kvm._last_request["reason"] == "duplicate"
    pair.b.kvm._revert_remote(ch, "test cleanup")

    # denial latch: silent while the pointer stays on the rejected edge
    pair.b.kvm._denial_latch[fp_a] = "denied"
    request(103)
    assert pair.b.kvm._last_request["decision"] == "ignored"
    assert pair.b.kvm._last_request["reason"] == "denial_latch"
    del pair.b.kvm._denial_latch[fp_a]

    # denied: no consent
    pair.b.store.set_peer_kvm_allowed(fp_a, False)
    request(104)
    assert pair.b.kvm._last_request["decision"] == "rejected"
    assert pair.b.kvm._last_request["reason"] == "denied"
    pair.b.store.set_peer_kvm_allowed(fp_a, True)
    del pair.b.kvm._denial_latch[fp_a]

    # topology: seam sides disagree
    pair.b.kvm._topology_ok[fp_a] = False
    request(105)
    assert pair.b.kvm._last_request["decision"] == "rejected"
    assert pair.b.kvm._last_request["reason"] == "topology"
    del pair.b.kvm._topology_ok[fp_a]
    del pair.b.kvm._denial_latch[fp_a]

    # busy: another active handoff is in flight
    pair.b.kvm._state["other"] = "remote"
    request(106)
    assert pair.b.kvm._last_request["decision"] == "rejected"
    assert pair.b.kvm._last_request["reason"] == "busy"
    del pair.b.kvm._state["other"]

    # unavailable: no input platform
    pair.b.kvm.platform = None
    request(107)
    assert pair.b.kvm._last_request["decision"] == "rejected"
    assert pair.b.kvm._last_request["reason"] == "unavailable"
    pair.b.kvm.platform = plat_b

    # closed: channel is gone
    class ClosedChannel:
        peer_fp = fp_a
        peer_name = "BetaBox"
        closed = True

    request(108, ClosedChannel())
    assert pair.b.kvm._last_request["decision"] == "rejected"
    assert pair.b.kvm._last_request["reason"] == "closed"
    # nothing was created for the closed path
    assert fp_a not in pair.b.kvm._handoffs
    assert pair.b.kvm._state.get(fp_a) == "local"


def test_simultaneous_takeover(fp_pair):
    pair, plat_a, plat_b = fp_pair
    wait_linked(pair)
    # both sides press the ownership chord at once: each requests the other
    for hid in (0x94, 0x96):
        plat_a.press(hid)
        plat_b.press(hid)
    plat_a.press(0x2C)
    plat_b.press(0x2C)
    fp_b = pair.b.store.fingerprint()  # A's peer / B's own fp
    fp_a = pair.a.store.fingerprint()  # B's peer / A's own fp

    def a_sees_b():
        return pair.a.kvm._state.get(fp_b)

    def b_sees_a():
        return pair.b.kvm._state.get(fp_a)

    winner_is_a = fp_a > fp_b
    want = (
        ("controlling", "remote") if winner_is_a else ("remote", "controlling")
    )
    ok = wait_for(
        lambda: a_sees_b() == want[0] and b_sees_a() == want[1]
    )
    assert ok, f"no consistent winner: A sees {a_sees_b()}, B sees {b_sees_a()}"
    assert pair.a.kvm.platform.delegation == want[0]
    assert pair.b.kvm.platform.delegation == want[1]


@pytest.fixture
def fp_pair(tmp_path):
    pair, plat_a, plat_b = make_pair(tmp_path)
    yield pair, plat_a, plat_b
    pair.stop()


def test_escape_chord_reverts_controller(node_pair_ctx):
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    fp_b = take_control(pair, plat_a, plat_b)
    for hid in (0x94, 0x96):  # left ctrl + left alt
        plat_a.press(hid)
    plat_a.press(0x2C)  # space completes ctrl+alt+space
    ok = wait_for(
        lambda: pair.a.kvm._state.get(fp_b) == "local",
        timeout=5,
    )
    assert ok
    assert wait_for(lambda: plat_b.delegation == "local", timeout=5)


def test_escape_chord_reverts_remote(node_pair_ctx):
    """The escape hatch works on the *controlled* machine too."""
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    take_control(pair, plat_a, plat_b)
    fp_a = pair.a.store.fingerprint()
    for hid in (0x94, 0x96):  # left ctrl + left alt on B
        plat_b.press(hid)
    plat_b.press(0x2C)
    ok = wait_for(
        lambda: pair.b.kvm._state.get(fp_a) == "local",
        timeout=5,
    )
    assert ok, "B's escape chord did not revert"
    assert wait_for(lambda: pair.a.kvm._state.get(pair.b.store.fingerprint()) == "local")
    assert plat_b.delegation == "local"


def test_key_press_on_controlled_device_does_not_release_control(node_pair_ctx):
    """Stage 1 explicit ownership: a physical key on the controlled device
    must NOT end sharing. Only the chord (or lease/disconnect) does."""
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    take_control(pair, plat_a, plat_b)
    fp_a = pair.a.store.fingerprint()

    plat_b.press(mac_vk_to_hid(0x00))  # physical A key on the controlled device
    time.sleep(0.3)  # give the old auto-revert policy time to (wrongly) fire
    assert pair.b.kvm._state.get(fp_a) == "remote", "physical key must not revert"
    assert pair.a.kvm._state.get(pair.b.store.fingerprint()) == "controlling"
    assert plat_b.delegation == "remote"
    plat_b.release(mac_vk_to_hid(0x00))

    # the explicit chord on the controlled device still releases
    chord(plat_b)
    assert wait_for(lambda: pair.b.kvm._state.get(fp_a) == "local", timeout=5)
    assert wait_for(lambda: pair.a.kvm._state.get(pair.b.store.fingerprint()) == "local", timeout=5)


def test_request_timeout_when_target_silent(node_pair_ctx, monkeypatch):
    """If the target never answers, the request expires and stays local."""
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    fp_b = pair.b.store.fingerprint()
    pair.a.kvm.handoff_timeout = 0.3
    monkeypatch.setattr(pair.b.kvm, "_on_control_request", lambda channel, body: None)
    chord(plat_a)  # request starts; B never answers
    ok = wait_for(lambda: pair.a.kvm._state.get(fp_b) == "requesting")
    assert ok
    ok = wait_for(lambda: pair.a.kvm._state.get(fp_b) == "local", timeout=5)
    assert ok, "request never timed out"
    assert pair.a.kvm.platform.delegation == "local"
    assert plat_a.cursor_hidden is False  # never parked (no READY)


def test_timeout_while_waiting_active(node_pair_ctx, monkeypatch):
    """Timeout after READY but before ACTIVE reverts the controller."""
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    fp_b = pair.b.store.fingerprint()
    pair.a.kvm.handoff_timeout = 0.3
    # B never confirms: BEGIN is received but no ACTIVE is sent back
    monkeypatch.setattr(pair.b.kvm, "_on_control_begin", lambda channel, body: None)
    chord(plat_a)
    ok = wait_for(lambda: pair.a.kvm._state.get(fp_b) == "controlling")
    assert ok
    ok = wait_for(lambda: pair.a.kvm._state.get(fp_b) == "local", timeout=5)
    assert ok, "waiting_active never timed out"
    assert plat_b.delegation == "local"
    ok = wait_for(lambda: plat_a.cursor_hidden is False, timeout=5)
    assert ok, "controller cursor never shown again"


def test_disconnect_while_controlling_releases_keys(node_pair_ctx):
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    take_control(pair, plat_a, plat_b)
    hid = mac_vk_to_hid(0x04)  # A
    plat_a.press(hid)
    wait_injected(plat_b, ("key", hid, True))
    pair.a.kvm._channels[pair.b.store.fingerprint()].close()
    ok = wait_for(
        lambda: pair.a.kvm._state.get(pair.b.store.fingerprint()) is None,
        timeout=5,
    )
    assert ok
    assert plat_a.delegation == "local"
    assert plat_a.cursor_hidden is False
    ok = wait_for(
        lambda: pair.b.kvm._state.get(pair.a.store.fingerprint()) is None,
        timeout=5,
    )
    assert ok
    wait_injected(plat_b, ("key", hid, False))  # released on the far side


def test_stale_ready_ignored(node_pair_ctx):
    """A READY for an unknown handoff id must not start suppressing."""
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    fp_b = pair.b.store.fingerprint()
    chord(plat_a)
    ok = wait_for(lambda: pair.a.kvm._state.get(fp_b) == "requesting")
    assert ok
    pair.a.kvm._on_control_ready(pair.a.kvm._channels[fp_b], __import__("struct").pack(">I", 9999))
    assert pair.a.kvm._state.get(fp_b) == "requesting"
    assert pair.a.kvm.platform.delegation == "local"
    # the genuine READY still arrives and the handoff completes
    ok = wait_for(lambda: pair.a.kvm.platform.delegation == "controlling")
    assert ok


def test_display_change_resyncs(node_pair_ctx):
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    plat_b.monitors = [{"x": 0, "y": 0, "w": 2560, "h": 1440, "scale": 1.0}]
    plat_b.engine.on_display_change()
    ok = wait_for(
        lambda: pair.a.kvm._peer_layouts[pair.b.store.fingerprint()].right() == 2560
    )
    assert ok

# -- channel admission: staged handshake, caps, stall protection ---------------

def raw_kvm_open(host, port, fp, nonce8=None):
    """Open a kvm connection claiming ``fp`` (does not complete the handshake)."""
    from core.kvm import KVM_PROTOCOL_VERSION

    sock = socket.create_connection((host, port), timeout=5)
    send_frame(
        sock,
        {
            "type": "kvm_open",
            "v": KVM_PROTOCOL_VERSION,
            "fp": fp,
            "nonce8": base64.b64encode(nonce8 or os.urandom(8)).decode("ascii"),
        },
    )
    return sock


def test_spoofed_kvm_open_keeps_active_channel(node_pair_ctx):
    """An attacker that claims a paired fp but cannot complete the key
    confirmation must not displace the live channel."""
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    fp_a = pair.a.store.fingerprint()
    old_channel = pair.b.kvm._channels[fp_a]
    peer_b = pair.test_peer(pair.a)

    sock = raw_kvm_open(peer_b.host, peer_b.port, fp_a)
    # Garbage instead of a frame sealed with the channel key.
    sock.sendall(b"\x00\x00\x00\x10" + os.urandom(16))
    ok = wait_for(lambda: pair.b.kvm._pending == [], timeout=8)
    assert ok, "rejected handshake must release the pending slot"
    assert pair.b.kvm._channels.get(fp_a) is old_channel, "spoofed open displaced the channel"
    # The surviving channel still exchanges events.
    ok = wait_for(lambda: pair.a.kvm._peer_layouts and pair.b.kvm._peer_layouts, timeout=5)
    assert ok, "live channel must still work after the spoof"
    sock.close()


def test_spoofed_kvm_open_with_wrong_key_rejected(node_pair_ctx):
    """Even a well-formed first frame fails authentication when sealed with
    a key the attacker cannot know."""
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    fp_a = pair.a.store.fingerprint()
    peer_b = pair.test_peer(pair.a)

    sock = raw_kvm_open(peer_b.host, peer_b.port, fp_a)
    ack = json.loads(recv_frame(sock).decode("utf-8"))
    assert ack["type"] == "kvm_ack"
    # Attacker derives a channel key from a WRONG trust key and seals frame 0.
    from core.kvm import kvm_channel_key

    wrong_key = b"x" * 32
    peer_nonce8 = base64.b64decode(ack["nonce8"])
    key = kvm_channel_key(wrong_key, 1, fp_a, pair.b.store.fingerprint(), os.urandom(8), peer_nonce8)
    frame0 = crypto.encrypt_with_nonce(key, crypto.chunk_nonce(os.urandom(8), 0), b"\x00")
    sock.sendall(b"\x00\x00\x00" + bytes([len(frame0)]) + frame0)
    reply = json.loads(recv_frame(sock).decode("utf-8"))
    assert reply["type"] == "error"
    assert reply["code"] == "kvm_auth_failed"
    sock.close()
    ok = wait_for(lambda: pair.b.kvm._pending == [], timeout=8)
    assert ok
    assert pair.b.kvm._channels.get(fp_a) is not None, "active channel must survive"


def test_stalled_kvm_handshake_expires(node_pair_ctx, monkeypatch):
    """An opener that never sends the key-confirmation frame must be swept
    by the handshake deadline without touching the live channel."""
    monkeypatch.setattr("core.kvm.HANDSHAKE_TIMEOUT", 1.0)
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    fp_a = pair.a.store.fingerprint()
    old_channel = pair.b.kvm._channels[fp_a]
    peer_b = pair.test_peer(pair.a)

    sock = raw_kvm_open(peer_b.host, peer_b.port, fp_a)
    ack = json.loads(recv_frame(sock).decode("utf-8"))
    assert ack["type"] == "kvm_ack"
    # Stall: send nothing; the responder must give up on its own.
    ok = wait_for(lambda: pair.b.kvm._pending == [], timeout=8)
    assert ok, "stalled handshake must expire"
    assert pair.b.kvm._channels.get(fp_a) is old_channel, "stall displaced the channel"
    assert pair.b.kvm.platform.delegation == "local", "no input suppression may remain"
    sock.close()


def test_kvm_pending_cap_refused(node_pair_ctx, monkeypatch):
    """Concurrent incomplete KVM opens are capped; overflow is refused."""
    monkeypatch.setattr("core.kvm.HANDSHAKE_TIMEOUT", 10.0)
    monkeypatch.setattr("core.kvm.MAX_PENDING_KVM", 1)
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    peer_b = pair.test_peer(pair.a)

    sock1 = raw_kvm_open(peer_b.host, peer_b.port, pair.a.store.fingerprint())
    ok = wait_for(lambda: len(pair.b.kvm._pending) == 1, timeout=8)
    assert ok, "first open must be admitted"
    sock2 = raw_kvm_open(peer_b.host, peer_b.port, pair.a.store.fingerprint())
    reply = json.loads(recv_frame(sock2).decode("utf-8"))
    assert reply["type"] == "error"
    assert reply["code"] == "kvm_busy"
    sock1.close()
    sock2.close()


def test_kvm_replacement_after_successful_handshake(node_pair_ctx):
    """After the link is replaced with a fully authenticated handshake the
    pair re-establishes and exchanges screen info again."""
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    fp_b = pair.b.store.fingerprint()
    pair.a.kvm._channels[fp_b].close()
    ok = wait_for(lambda: fp_b not in pair.a.kvm._channels, timeout=5)
    assert ok, "old channel must be torn down"

    def relink():
        pair.a.kvm.ensure_connections()
        pair.b.kvm.ensure_connections()
        return fp_b in pair.a.kvm._channels and pair.a.store.fingerprint() in pair.b.kvm._channels

    ok = wait_for(relink, timeout=20)
    assert ok, "channel must re-establish via a fresh authenticated handshake"
    ok = wait_for(lambda: pair.a.kvm._peer_layouts and pair.b.kvm._peer_layouts, timeout=5)
    assert ok, "screen info must be exchanged again after the replacement"


class DummyConn:
    """Socket stand-in for engine-level tests: never actually sends."""

    def __init__(self):
        self.timeout = None

    def settimeout(self, t):
        self.timeout = t

    def sendall(self, data):
        raise OSError("not connected")


class LiveDummyConn(DummyConn):
    """Stand-in that accepts sends, so the reader loop stays alive."""

    def __init__(self):
        super().__init__()
        self.sent = []

    def sendall(self, data):
        self.sent.append(data)

    def shutdown(self, how):
        pass

    def close(self):
        pass


def make_stuck_engine(tmp_path, fp, consent=True):
    """Engine with a peer whose control state is frozen at "controlling",
    the exact condition that used to leave the peer stuck forever."""
    store = TrustStore(str(tmp_path), keyring_enabled=False)
    store.peers[fp] = {"name": "BetaBox", "kvm_allowed": consent}
    toasts = []
    engine = KVMEngine(
        store,
        discovery=None,
        platform=None,
        on_status=lambda m, level="info": toasts.append((m, level)),
    )
    engine._state[fp] = "controlling"
    channel = KvmChannel(
        DummyConn(), fp, "BetaBox", os.urandom(32), os.urandom(8), os.urandom(8), engine, "target"
    )
    return engine, channel, toasts


def test_stuck_state_refuses_busy_with_error_toast(tmp_path):
    fp = "stuck-peer"
    engine, channel, toasts = make_stuck_engine(tmp_path, fp, consent=True)
    engine.handle_event(channel, KIND_CONTROL_REQUEST, encode_control_request(1, 200, 450, 0))
    assert toasts == [("KVM: BetaBox is busy", "error")]
    assert engine._state.get(fp) == "controlling"  # refusal alone must not clear state


def test_stuck_state_with_consent_off_refuses_denied_and_latches(tmp_path):
    fp = "stuck-peer"
    engine, channel, toasts = make_stuck_engine(tmp_path, fp, consent=False)
    engine.handle_event(channel, KIND_CONTROL_REQUEST, encode_control_request(1, 200, 450, 0))
    assert toasts == [("KVM: BetaBox is not allowed to take control", "error")]
    assert engine._denial_latch.get(fp) == "denied"
    # pointer still on the rejected edge: stay silent until it leaves
    engine.handle_event(channel, KIND_CONTROL_REQUEST, encode_control_request(2, 200, 450, 0))
    assert len(toasts) == 1


def test_inject_exception_does_not_kill_channel(node_pair_ctx, monkeypatch):
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    fp_a = pair.a.store.fingerprint()
    take_control(pair, plat_a, plat_b)
    channel = list(pair.b.kvm._channels.values())[0]

    def broken_inject(hid, down):
        raise RuntimeError("ctypes hiccup")

    monkeypatch.setattr(plat_b, "inject_key", broken_inject)
    hid = mac_vk_to_hid(0x00)
    pair.b.kvm.handle_event(channel, KIND_KEY_DOWN, encode_key(hid))  # must not raise
    assert channel in pair.b.kvm._channels.values()
    assert pair.b.kvm._state.get(fp_a) == "remote"
    monkeypatch.undo()
    pair.b.kvm.handle_event(channel, KIND_KEY_DOWN, encode_key(hid))
    wait_injected(plat_b, ("key", hid, True))


def test_run_loop_read_failure_still_releases_engine_state(tmp_path, monkeypatch):
    """A read/decrypt-level failure ends the loop; the finally-teardown net
    must still reset the engine (this is the channel-loss safety net)."""
    fp = "crash-peer"
    engine, channel, toasts = make_stuck_engine(tmp_path, fp, consent=True)
    engine._channels[fp] = channel

    def fake_recv_frame(conn):
        return b"garbage-not-encrypted"

    monkeypatch.setattr("core.kvm.recv_frame", fake_recv_frame)
    channel.run()  # must not raise: loop breaks, finally runs
    assert fp not in engine._channels
    assert fp not in engine._state
    assert any("control returned" in m for m, _ in toasts)


def test_run_loop_survives_handler_exception(tmp_path, monkeypatch):
    """A handler-level failure (e.g. a platform inject hiccup) must NOT kill
    the reader thread: the session and per-peer state stay alive, the error
    is reported, and the loop keeps reading."""
    fp = "survivor-peer"
    engine, channel, toasts = make_stuck_engine(tmp_path, fp, consent=True)
    engine._channels[fp] = channel
    channel.conn = LiveDummyConn()
    engine.stall_timeout = 60.0
    body = encode_control_request(1, 0, 0, 0)
    plain = pack_frame(0, 0, KIND_CONTROL_REQUEST, body)
    raw0 = crypto.encrypt_with_nonce(channel.key, crypto.chunk_nonce(channel.nonce8_in, 0), plain)
    raw1 = crypto.encrypt_with_nonce(channel.key, crypto.chunk_nonce(channel.nonce8_in, 1), plain)
    frames = iter([raw0, raw1])

    def fake_recv_frame(conn):
        try:
            return next(frames)
        except StopIteration:
            raise socket.timeout("idle")

    def boom_handle(channel, kind, body):
        raise RuntimeError("boom")

    monkeypatch.setattr("core.kvm.recv_frame", fake_recv_frame)
    monkeypatch.setattr(engine, "handle_event", boom_handle)
    thread = threading.Thread(target=channel.run, name="kvm-test-run", daemon=True)
    thread.start()
    ok = wait_for(lambda: any("error handling event" in m for m, _ in toasts))
    assert ok, "handler failure must be reported, not swallowed"
    assert fp in engine._state, "loop must survive: state stays live"
    assert channel in engine._channels.values(), "channel must stay admitted"
    channel.close()
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert fp not in engine._channels
    assert fp not in engine._state


# -- F1-F8: KVM hardening fixes ---------------------------------------------------

def test_f1_send_failure_tears_down_session(tmp_path):
    """A dead socket must not be swallowed: the session is torn down and
    the per-peer state cannot stay frozen at remote."""
    fp = "dead-peer"
    engine, channel, toasts = make_stuck_engine(tmp_path, fp, consent=True)
    engine.platform = FakePlatform("DeadScreen")
    engine._state[fp] = "remote"
    engine._handoffs[fp] = {
        "id": 7,
        "role": "target",
        "stage": "active",
        "deadline": None,
        "entry": (48, 540),
        "mask": 0,
        "fraction": None,
        "parked": False,
        "peer_last_seen": time.monotonic(),
        "lease_deadline": None,
    }
    engine._channels[fp] = channel
    engine.enabled = True  # on_escape_chord checks the enabled flag

    engine.on_escape_chord()  # release path on a dead socket

    ok = wait_for(lambda: channel.closed, timeout=5)
    assert ok, "send failure must close the channel"
    ok = wait_for(lambda: fp not in engine._state, timeout=5)
    assert ok, "send failure must clear the frozen engine state"
    assert any("send failed" in m for m, _ in toasts)
    assert engine.diagnostics()["send_failures"] >= 1


def test_f2_delegation_failure_surfaces_and_restarts_capture(tmp_path):
    """A failed re-association is the stuck-cursor symptom: it must be
    visible (error toast) and trigger a capture restart, not a swallow."""
    fp = "sticky-peer"
    store = TrustStore(str(tmp_path), keyring_enabled=False)
    store.peers[fp] = {"name": "StickyBox", "kvm_allowed": True}
    toasts = []
    platform = FakePlatform("StickyScreen")
    engine = KVMEngine(
        store,
        discovery=None,
        platform=platform,
        on_status=lambda m, level="info": toasts.append((m, level)),
    )
    channel = KvmChannel(
        DummyConn(), fp, "StickyBox", os.urandom(32), os.urandom(8), os.urandom(8), engine, "target"
    )
    engine._state[fp] = "remote"
    engine._handoffs[fp] = {
        "id": 1,
        "role": "target",
        "stage": "active",
        "deadline": None,
        "entry": (48, 540),
        "mask": 0,
        "fraction": None,
        "parked": False,
    }
    platform.delegation_fails = True
    platform.restarts = 0

    engine._revert_remote(channel, "test")

    assert any("failed to restore local input" in m for m, _ in toasts)
    assert platform.restarts == 1, "capture must be restarted after repeated failures"
    assert engine._state.get(fp) == "local"


def test_platform_input_lost_reverts_remote_session(tmp_path):
    """When the platform's input capture dies (macOS tap disabled), the
    peer must not believe it still owns this Mac: the session is reverted,
    delegation restored, and the peer told."""
    fp = "capture-dead-peer"
    engine, channel, toasts = make_stuck_engine(tmp_path, fp, consent=True)
    platform = FakePlatform("DeadScreen")
    engine.platform = platform
    engine._state[fp] = "remote"
    engine._handoffs[fp] = {
        "id": 9,
        "role": "target",
        "stage": "active",
        "deadline": None,
        "entry": (48, 540),
        "mask": 0,
        "fraction": None,
        "parked": False,
    }
    engine._channels[fp] = channel
    live = LiveDummyConn()
    channel.conn = live

    engine.on_platform_input_lost()

    assert engine._state.get(fp) == "local"
    assert platform.delegation == "local"
    ok = wait_for(lambda: len(live.sent) >= 2, timeout=5)
    assert ok, "revert + all-keys-up must reach the peer"
    kinds = []
    for i, frame in enumerate(live.sent):
        length = struct.unpack(">I", frame[:4])[0]
        nonce = crypto.chunk_nonce(channel.nonce8_out, i)
        plain = crypto.decrypt_with_nonce(channel.key, nonce, frame[4 : 4 + length])
        kinds.append(unpack_frame(plain)[2])
    assert KIND_CONTROL_REVERT in kinds
    assert KIND_ALL_KEYS_UP in kinds
    assert any("Control taken back" in m for m, _ in toasts)


def test_f3_waiting_active_label_and_transition_log(node_pair_ctx):
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    fp_b = pair.b.store.fingerprint()
    take_control(pair, plat_a, plat_b)
    # During the handshake the state is "controlling" but input is not yet
    # suppressed; the UI must render that intermediate stage distinctly.
    rec = pair.a.kvm._handoffs[fp_b]
    rec["stage"] = "waiting_active"
    assert pair.a.kvm.control_label(fp_b) == "waiting_active"
    assert pair.a.kvm.control_label(pair.a.store.fingerprint()) == "local"
    assert len(pair.a.kvm.recent_transitions()) >= 3
    assert any(
        stage == "waiting_active"
        for _, _, _s, stage, _h, _r, _b in pair.a.kvm.recent_transitions()
    )


def test_f4_concurrent_callback_and_reader_traffic(node_pair_ctx):
    """F4: the state machine must survive interleaved platform callbacks
    and channel events without losing the handoff."""
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    fp_b = pair.b.store.fingerprint()

    def traffic(plat):
        for i in range(200):
            plat.move(3, 0)
            plat.click(0, True)
            plat.click(0, False)
            plat.scroll(120)
            hid = mac_vk_to_hid(0x00)
            plat.press(hid)
            plat.release(hid)
            time.sleep(0.001)

    threads = [threading.Thread(target=traffic, args=(p,), daemon=True) for p in (plat_a, plat_b)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)
    assert pair.a.kvm.control_state(fp_b) == "local"
    assert pair.b.kvm.control_state(pair.a.store.fingerprint()) == "local"


def test_f5_revert_origin_reported_to_controller(node_pair_ctx):
    """F5: reverts must say which path triggered them, so a stuck
    "control on the target" episode is diagnosable.  The origin is
    generated on the target and must reach the controller's status line
    over the wire."""
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    take_control(pair, plat_a, plat_b)
    toasts = []
    pair.a.kvm.on_status = lambda m, level="info": toasts.append((m, level))
    chord(plat_b)  # explicit release on the target
    ok = wait_for(lambda: any("escape" in m for m, _ in toasts))
    assert ok, f"escape origin missing from controller toasts: {toasts}"
    assert pair.a.kvm.control_state(pair.b.store.fingerprint()) == "local"
    assert pair.b.kvm.control_state(pair.a.store.fingerprint()) == "local"
    ok = wait_for(lambda: pair.a.kvm.control_state(pair.b.store.fingerprint()) == "local", timeout=5)
    assert ok, f"A never reverted; got {pair.a.kvm.control_state(pair.b.store.fingerprint())}"

    # The revert latched A's edge: the cursor sits just inside the seam, so
    # a fresh takeover needs a deliberate exit of the latch zone first.
    plat_a.move(-700, 0)  # (1435, 450) -> (735, 450): clearly off the seam
    take_control(pair, plat_a, plat_b)


def test_f7_keyboard_stall_escalation_and_recovery(tmp_path):
    """F7: a stalled keyboard stream (mouse alive, keys dead) escalates
    from tap restart to a latched mouse-only notice, then recovers."""
    fp = "stall-peer"
    store = TrustStore(str(tmp_path), keyring_enabled=False)
    store.peers[fp] = {"name": "StallBox", "kvm_allowed": True}
    toasts = []

    class StallingPlatform(FakePlatform):
        def __init__(self):
            super().__init__("StallScreen")
            self.health = "stalled"
            self.stall_notices = 0

        def keyboard_health(self):
            return self.health

        def note_keyboard_stall(self):
            self.stall_notices += 1

    platform = StallingPlatform()
    engine = KVMEngine(
        store,
        discovery=None,
        platform=platform,
        on_status=lambda m, level="info": toasts.append((m, level)),
    )
    engine._state[fp] = "remote"

    engine._poll_keyboard_health()
    assert platform.stall_notices == 1
    assert engine._keyboard_stall_stage == 1

    engine._poll_keyboard_health()
    assert engine._keyboard_stall_stage == 2
    assert any("Secure Input" in m for m, _ in toasts)

    platform.health = "ok"
    engine._poll_keyboard_health()
    assert engine._keyboard_stall_stage == 0
    assert any("recovered" in m for m, _ in toasts)

    engine._state[fp] = "local"
    platform.health = "stalled"
    engine._poll_keyboard_health()
    assert engine._keyboard_stall_stage == 0, "no session: must not diagnose a stall"


def test_f8_rel_coalescing_and_control_priority(tmp_path):
    """F8: relative moves coalesce into single frames behind control
    events, which jump the queue and are never delayed by a mouse burst."""
    fp = "flow-peer"
    engine, channel, toasts = make_stuck_engine(tmp_path, fp, consent=True)
    engine.platform = FakePlatform("FlowScreen")
    conn = LiveDummyConn()
    channel.conn = conn
    engine._channels[fp] = channel

    channel.send_event(KIND_MOUSE_MOVE_REL, struct.pack(">hh", 3, 4))
    channel.send_event(KIND_MOUSE_MOVE_REL, struct.pack(">hh", 5, 6))
    channel.send_event(KIND_MOUSE_MOVE_REL, struct.pack(">hh", -2, 8))
    channel.send_event(KIND_KEY_DOWN, encode_key(0x04))

    ok = wait_for(lambda: len(conn.sent) >= 2, timeout=5)
    assert ok, f"expected coalesced+control frames, got {len(conn.sent)}"

    frames = []
    for raw in conn.sent:
        (size,) = struct.unpack(">I", raw[:4])
        frames.append(crypto.decrypt_with_nonce(channel.key, crypto.chunk_nonce(channel.nonce8_out, len(frames)), raw[4 : 4 + size]))

    kinds = [unpack_frame(f)[2] for f in frames]
    assert kinds[0] == KIND_KEY_DOWN, f"control frame must go first: {kinds}"
    assert kinds[1] == KIND_MOUSE_MOVE_REL, f"moves must coalesce after: {kinds}"
    assert len(frames) == 2, f"3 rel moves must collapse into 1 frame: {frames}"
    _, _, _, body = unpack_frame(frames[1])
    dx, dy = struct.unpack(">hh", body)
    assert (dx, dy) == (6, 18), f"coalesced deltas wrong: {(dx, dy)}"


def test_p1_deadlock_send_failure_teardown_releases_channel_lock(tmp_path):
    """P1a: engine_remove must never run while the channel lock is held
    (the engine lock is taken inside on_channel_closed, inverting the
    callback order engine-lock -> send_event -> channel-lock)."""
    fp = "deadlock-peer"
    engine, channel, toasts = make_stuck_engine(tmp_path, fp, consent=True)
    engine._state[fp] = "remote"
    engine._handoffs[fp] = {
        "id": 9,
        "role": "target",
        "stage": "active",
        "deadline": None,
        "entry": (48, 540),
        "mask": 0,
        "fraction": None,
        "parked": False,
    }
    engine._channels[fp] = channel

    lock_held_at_remove = []
    original = channel.engine_remove

    def guarded():
        lock_held_at_remove.append(channel._lock.locked())
        original()

    channel.engine_remove = guarded
    channel.send_event(KIND_KEY_DOWN, encode_key(0x04))

    ok = wait_for(lambda: lock_held_at_remove, timeout=5)
    assert ok, "engine_remove was never reached"
    assert lock_held_at_remove == [False], "engine_remove ran under the channel lock"
    ok = wait_for(lambda: fp not in engine._state, timeout=5)
    assert ok, "teardown must clear the frozen engine state"


def test_p1_deadlock_send_failure_completes_under_held_engine_lock(tmp_path):
    """P1a: the send-failure teardown must complete even while a platform
    callback holds the engine lock (the inversion scenario)."""
    fp = "invert-peer"
    engine, channel, toasts = make_stuck_engine(tmp_path, fp, consent=True)
    engine._state[fp] = "remote"
    engine._handoffs[fp] = {
        "id": 10,
        "role": "target",
        "stage": "active",
        "deadline": None,
        "entry": (48, 540),
        "mask": 0,
        "fraction": None,
        "parked": False,
    }
    engine._channels[fp] = channel

    with engine._lock:  # simulate on_local_key holding the engine lock
        channel.send_event(KIND_KEY_DOWN, encode_key(0x04))
        time.sleep(0.2)
    ok = wait_for(lambda: fp not in engine._state, timeout=5)
    assert ok, "teardown must not deadlock against a held engine lock"
    assert channel.closed


def test_p1_overflow_split_keeps_writer_alive(tmp_path):
    """P1b: a coalesced delta beyond ±32767 must be split into wire-format
    chunks, not raise in the writer thread and strand the session."""
    fp = "overflow-peer"
    engine, channel, toasts = make_stuck_engine(tmp_path, fp, consent=True)
    conn = LiveDummyConn()
    channel.conn = conn
    channel._dataq.append(("rel", 200000, -100000, 0))
    with channel._sendcv:
        channel._sendcv.notify_all()

    total_dx = 200000
    total_dy = -100000
    chunks = max((total_dx + 32766) // 32767, (-total_dy + 32766) // 32767)
    ok = wait_for(lambda: len(conn.sent) >= chunks, timeout=5)
    assert ok, f"expected {chunks} split frames, got {len(conn.sent)}"

    frames = []
    for raw in conn.sent:
        (size,) = struct.unpack(">I", raw[:4])
        frames.append(crypto.decrypt_with_nonce(channel.key, crypto.chunk_nonce(channel.nonce8_out, len(frames)), raw[4 : 4 + size]))

    dx = dy = 0
    for f in frames:
        _, _, kind, body = unpack_frame(f)
        assert kind == KIND_MOUSE_MOVE_REL
        cdx, cdy = struct.unpack(">hh", body)
        assert -32767 <= cdx <= 32767 and -32767 <= cdy <= 32767, (cdx, cdy)
        dx += cdx
        dy += cdy
    assert (dx, dy) == (total_dx, total_dy), f"split must preserve motion: {(dx, dy)}"
    assert not channel.closed, "the writer must survive a large delta"


def test_p1_no_keys_grace_and_single_tap_restart(tmp_path):
    """F7: 'no keys ever during the session' is ambiguous; it must wait
    out the grace period, restart the tap once, and never latch."""
    from core.kvm import KEYBOARD_NO_KEY_GRACE

    fp = "nokeys-peer"
    store = TrustStore(str(tmp_path), keyring_enabled=False)
    store.peers[fp] = {"name": "NoKeysBox", "kvm_allowed": True}
    toasts = []

    class NoKeysPlatform(FakePlatform):
        def __init__(self):
            super().__init__("NoKeysScreen")
            self.health = "no_keys"
            self.stall_notices = 0

        def keyboard_health(self):
            return self.health

        def note_keyboard_stall(self):
            self.stall_notices += 1

    platform = NoKeysPlatform()
    engine = KVMEngine(
        store,
        discovery=None,
        platform=platform,
        on_status=lambda m, level="info": toasts.append((m, level)),
    )
    engine._state[fp] = "remote"
    engine._active_since = time.monotonic()
    engine._poll_keyboard_health()
    assert engine._keyboard_stall_stage == 0, "young session must be exempt"
    assert platform.stall_notices == 0

    engine._active_since = time.monotonic() - KEYBOARD_NO_KEY_GRACE - 1.0
    engine._poll_keyboard_health()
    assert engine._keyboard_stall_stage == 1
    assert platform.stall_notices == 1
    assert any("no keyboard input" in m for m, _ in toasts)

    engine._poll_keyboard_health()
    assert engine._keyboard_stall_stage == 1, "must never latch mouse-only on no_keys"
    assert platform.stall_notices == 1, "tap restart must happen exactly once"
    assert not any("Secure Input" in m for m, _ in toasts)

    platform.health = "ok"
    engine._poll_keyboard_health()
    assert engine._keyboard_stall_stage == 0, "keys arriving must reset the stage"


pytestmark = pytest.mark.socket

# -- menu-driven control toggle (tray action) --------------------------------


def test_menu_request_control_drives_full_handoff(node_pair_ctx):
    """The tray action routes through the same acknowledged handoff as the
    chord; the entry point lands on the peer's screen center."""
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    fp_b = pair.b.store.fingerprint()
    layout = pair.b.kvm.platform.screen_layout()
    pair.a.kvm.request_control(fp_b)
    ok = wait_for(lambda: pair.a.kvm._state.get(fp_b) == "requesting")
    assert ok, "A never entered requesting"
    ok = wait_for(lambda: pair.a.kvm._state.get(fp_b) == "controlling")
    assert ok, "A never got controlling"
    ok = wait_for(lambda: pair.b.kvm._state.get(pair.a.store.fingerprint()) == "remote")
    assert ok, "B never entered remote"
    ok = wait_for(lambda: pair.a.kvm.platform.delegation == "controlling")
    assert ok, "A never suppressed input (ACTIVE never arrived)"
    rec = pair.a.kvm._handoffs.get(fp_b)
    assert rec is not None and rec.get("fraction") == 0.5
    assert rec.get("entry") == (
        layout.left() + layout.width() // 2,
        layout.top() + layout.height() // 2,
    )
    assert pair.b.kvm._last_request["decision"] == "accepted"


def test_menu_release_control_hands_back(node_pair_ctx):
    """Controller-side menu release: wire reason is 'user' (menu), not
    'escape' (chord), and the edge latch is set like any revert."""
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    fp_b = pair.b.store.fingerprint()
    take_control(pair, plat_a, plat_b)
    pair.a.kvm.release_control(fp_b)
    ok = wait_for(lambda: pair.a.kvm._state.get(fp_b) == "local", timeout=5)
    assert ok, "A never handed back control"
    ok = wait_for(lambda: pair.b.kvm._state.get(pair.a.store.fingerprint()) == "local")
    assert ok, "B never returned to local"
    assert pair.a.kvm.platform.delegation == "local"
    assert pair.a.kvm._blocked_edge.get(fp_b) == "right"
    reasons = [t[5] for t in pair.a.kvm.recent_transitions() if t[1] == fp_b and t[5]]
    assert any("user" in r for r in reasons), reasons
    assert not any("escape" in r for r in reasons), reasons


def test_target_menu_give_back_ends_session(node_pair_ctx):
    """Target-side menu action ('give control back') must tear the session
    down from the controlled device."""
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    fp_b = pair.b.store.fingerprint()
    take_control(pair, plat_a, plat_b)
    pair.b.kvm.release_control(pair.a.store.fingerprint())
    ok = wait_for(lambda: pair.a.kvm._state.get(fp_b) == "local", timeout=5)
    assert ok, "A never returned to local"
    ok = wait_for(lambda: pair.b.kvm._state.get(pair.a.store.fingerprint()) == "local")
    assert ok, "B never returned to local"
    assert pair.b.kvm.platform.delegation == "local"


def test_menu_request_control_refusals(node_pair_ctx):
    """Menu takeover refuses cleanly: unknown peer, and while a session is
    already active."""
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    toasts = []
    pair.a.kvm.on_status = lambda s, level="info": toasts.append(s)
    pair.a.kvm.request_control("deadbeefdeadbeef")
    assert "deadbeefdeadbeef" not in pair.a.kvm._handoffs
    assert any("no channel" in s for s in toasts), toasts
    fp_b = pair.b.store.fingerprint()
    take_control(pair, plat_a, plat_b)
    toasts.clear()
    pair.a.kvm.request_control(fp_b)
    assert pair.a.kvm._state.get(fp_b) == "controlling", "busy request must not disturb the session"
    assert any("finish the current session" in s for s in toasts), toasts


def test_chord_fires_with_right_option(node_pair_ctx):
    """Ctrl + right-Option + Space must arm the escape chord (right
    Option maps to ALTGR on both platforms)."""
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    fp_b = pair.b.store.fingerprint()
    for hid in (0x94, 0x9A):  # left ctrl + right alt/option
        plat_a.press(hid)
    plat_a.press(0x2C)
    ok = wait_for(lambda: pair.a.kvm._state.get(fp_b) == "requesting")
    assert ok, "Ctrl+right-Option+Space never requested control"
    plat_a.release(0x2C)
    for hid in (0x94, 0x9A):
        plat_a.release(hid)
    ok = wait_for(lambda: pair.a.kvm._state.get(fp_b) == "controlling")
    assert ok, "handoff did not complete"

def test_edge_seam_handoff_is_default(node_pair_ctx):
    """Crossing the shared edge must take control with no chord and no
    explicit flag: the seam handoff is the default takeover again."""
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    fp_b = pair.b.store.fingerprint()
    assert pair.a.kvm.edge_handoff_enabled is True
    plat_a.move(740, 0)  # to the right edge of A's 1440x900 screen
    ok = wait_for(lambda: pair.a.kvm._state.get(fp_b) == "requesting")
    assert ok, "edge crossing never requested control"
    ok = wait_for(lambda: pair.a.kvm._state.get(fp_b) == "controlling")
    assert ok, "edge crossing never completed the handoff"
    ok = wait_for(lambda: pair.b.kvm._state.get(pair.a.store.fingerprint()) == "remote")
    assert ok, "B never entered remote"
