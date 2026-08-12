"""Engine-level KVM tests: a fake InputPlatform drives two real Nodes over loopback.

The control flow is an acknowledged handoff, never a direct takeover:

    controller:  edge hit -> requesting -> (READY) -> controlling -> (ACTIVE)
    target:      (REQUEST) -> remote_preparing -> remote

Local input is suppressed only after CONTROL_ACTIVE: the controller's
platform delegation stays "local" until the remote confirmed.
"""

import os
import time

import pytest

from core.kvm_events import KIND_CONTROL_BEGIN
from core.kvm_geometry import Monitor, ScreenLayout
from core.kvm_keymap import mac_vk_to_hid


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

    def start(self, engine):
        self.engine = engine

    def stop(self):
        pass

    def permission_ok(self):
        return self.permissions_ok

    def screen_layout(self):
        return ScreenLayout([Monitor(**m) for m in self.monitors], primary=0)

    def invalidate_layout(self):
        pass

    def cursor_position(self):
        return self.cursor

    def warp_cursor(self, x, y):
        self.cursor = (x, y)

    def hide_cursor(self):
        self.cursor_hidden = True

    def show_cursor(self):
        self.cursor_hidden = False

    def set_delegation(self, state):
        self.delegation = state

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

    def move(self, dx, dy):
        x, y = self.cursor
        nx, ny = x + dx, y + dy
        self.cursor = (nx, ny)
        self.engine.on_local_mouse(dx, dy, nx, ny)

    def press(self, hid):
        self.engine.on_local_key(hid, True)

    def release(self, hid):
        self.engine.on_local_key(hid, False)

    def click(self, button, down):
        self.engine.on_local_button(button, down)

    def scroll(self, dy, dx=0):
        self.engine.on_local_wheel(dy, dx)

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


def take_control(pair, plat_a, plat_b):
    """Drive the full acknowledged handoff A -> B and return when active.

    A parks on its right seam (x=1440) which triggers the request; the
    handshake completes when B is remote and A's delegation is
    "controlling" (input suppressed on A only after ACTIVE).
    """
    fp_b = pair.b.store.fingerprint()
    plat_a.move(740, 0)  # cursor -> (1440, 450): A's right seam / jump zone
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

    # the seam-point ABS was injected on B (peer left edge, inset past jump zone)
    assert ("abs", 4, 540) in plat_b.injected

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
    plat_a.move(740, 0)  # request starts
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


def test_hand_back_on_peer_edge(node_pair_ctx):
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    fp_b = take_control(pair, plat_a, plat_b)
    # B's injected cursor reaches B's left edge (x=0) -> hand back
    plat_b.edge("left", 0, 540)
    ok = wait_for(lambda: pair.a.kvm._state.get(fp_b) == "local", timeout=5)
    assert ok, "A never handed back control"
    assert plat_b.delegation == "local"
    assert plat_a.cursor[0] == 1435  # restored on A's seam, inset past jump zone
    assert abs(plat_a.cursor[1] - 450) <= 1  # mirrored y (fraction 0.5)
    assert plat_a.cursor_hidden is False
    # the seam is inside the jump zone: a *deliberate* move back to the edge
    # re-takes control, but a move away from it must not
    plat_a.move(-10, 0)  # x -> 1425, off the seam
    assert pair.a.kvm._state.get(fp_b) == "local"
    plat_a.move(15, 0)  # x -> 1440, on the seam again: new handoff starts
    ok = wait_for(lambda: pair.a.kvm._state.get(fp_b) == "requesting")
    assert ok


def test_hand_back_releases_pressed_keys(node_pair_ctx):
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    take_control(pair, plat_a, plat_b)
    hid = mac_vk_to_hid(0x0F)  # T
    plat_a.press(hid)  # key still held when control is handed back
    wait_injected(plat_b, ("key", hid, True))  # B must apply it before reverting
    plat_b.edge("left", 0, 540)
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
    plat_a.move(740, 0)
    ok = wait_for(lambda: pair.a.kvm._blocked_edge.get(fp_b) is not None, timeout=5)
    assert ok, "A should have been refused"
    assert pair.a.kvm._state.get(fp_b) == "local"
    assert pair.a.kvm.platform.delegation == "local"
    assert plat_b.delegation == "local"
    # the controller edge is blocked while the pointer stays on it: wiggling
    # must not spam new attempts
    plat_a.move(1, 0)
    plat_a.move(-1, 0)
    assert pair.a.kvm._state.get(fp_b) == "local"
    # leaving the edge clears the block: a deliberate re-entry is a fresh
    # attempt that gets refused again
    plat_a.move(-20, 0)
    plat_a.move(20, 0)
    ok = wait_for(lambda: pair.a.kvm._state.get(fp_b) == "local", timeout=5)
    assert ok
    assert plat_b.delegation == "local"


def test_denial_deduplicated_until_edge_left(node_pair_ctx):
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    pair.b.store.set_peer_kvm_allowed(pair.a.store.fingerprint(), False)
    fp_a = pair.a.store.fingerprint()
    fp_b = pair.b.store.fingerprint()
    plat_a.move(740, 0)
    ok = wait_for(lambda: fp_a in pair.b.kvm._denial_latch, timeout=5)
    assert ok, "target never latched a denial"
    # pointer stays on the edge: further wiggling must not spam new requests
    for _ in range(5):
        plat_a.move(1, 0)
    assert pair.a.kvm._state.get(fp_b) == "local"
    # once the pointer leaves the edge, the latch is cleared
    plat_a.move(-20, 0)
    ok = wait_for(lambda: fp_a not in pair.b.kvm._denial_latch, timeout=5)
    assert ok, "denial latch was never cleared after leaving the edge"
    assert pair.a.kvm._blocked_edge.get(fp_b) is None


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
    plat_a.move(740, 0)
    assert pair.a.kvm._state.get(pair.b.store.fingerprint()) != "controlling"
    assert plat_b.delegation == "local"


def test_simultaneous_takeover(fp_pair):
    pair, plat_a, plat_b = fp_pair
    wait_linked(pair)
    plat_a.move(740, 0)  # A parks on its right seam edge -> A requests
    plat_b.move(-700, 0)  # B parks on its left seam edge -> B requests
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


def test_request_timeout_when_target_silent(node_pair_ctx, monkeypatch):
    """If the target never answers, the request expires and stays local."""
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    fp_b = pair.b.store.fingerprint()
    pair.a.kvm.handoff_timeout = 0.3
    monkeypatch.setattr(pair.b.kvm, "_on_control_request", lambda channel, body: None)
    plat_a.move(740, 0)  # request starts; B never answers
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
    plat_a.move(740, 0)
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
    plat_a.move(740, 0)
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


def test_expire_handoff_with_dead_channel_clears_state(node_pair_ctx):
    """Regression: _expire_handoff with a vanished channel left _state stuck
    in requesting and the watchdog re-fired the same expiry forever."""
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    fp_b = pair.b.store.fingerprint()
    rec = {
        "id": 123,
        "role": "controller",
        "stage": "waiting_ready",
        "deadline": time.monotonic() - 1,
        "entry": (4, 540),
        "mask": 0,
        "fraction": 0.5,
        "parked": False,
    }
    pair.a.kvm._handoffs[fp_b] = rec
    pair.a.kvm._state[fp_b] = "requesting"
    pair.a.kvm._channels.pop(fp_b, None)  # channel is already gone
    pair.a.kvm._expire_handoff(fp_b, rec)
    assert pair.a.kvm._state.get(fp_b) is None
    assert pair.a.kvm._handoffs.get(fp_b) is None
    assert plat_a.delegation == "local"
    # a second expiry (the watchdog firing again) must be a no-op
    pair.a.kvm._expire_handoff(fp_b, rec)
    assert pair.a.kvm._state.get(fp_b) is None


def test_expire_handoff_dead_channel_restores_parked_cursor(node_pair_ctx):
    """The controller cursor must be restored even when the channel died
    while the handoff was parked."""
    pair, plat_a, plat_b = node_pair_ctx
    wait_linked(pair)
    fp_b = pair.b.store.fingerprint()
    rec = {
        "id": 124,
        "role": "controller",
        "stage": "waiting_active",
        "deadline": time.monotonic() - 1,
        "entry": (4, 540),
        "mask": 0,
        "fraction": 0.5,
        "parked": True,
    }
    pair.a.kvm._handoffs[fp_b] = rec
    pair.a.kvm._state[fp_b] = "controlling"
    pair.a.kvm._channels.pop(fp_b, None)
    plat_a.cursor_hidden = True
    pair.a.kvm._expire_handoff(fp_b, rec)
    assert pair.a.kvm._state.get(fp_b) is None
    assert plat_a.cursor_hidden is False
    # restored just inside the seam (past the jump zone), mirrored y
    assert plat_a.cursor[0] == 1435
    assert abs(plat_a.cursor[1] - 450) <= 1