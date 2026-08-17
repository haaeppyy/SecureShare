"""Keyboard/mouse sharing between paired devices (KVM).

One persistent, encrypted binary channel per paired peer. The handshake
is a JSON frame exchange (``kvm_open`` / ``kvm_ack``) that binds protocol
version, both fingerprints, the role and both channel nonces into the
channel key; the first binary frame is the authenticated key
confirmation. After the handshake both sides switch to binary frames:

    [4-byte BE length][AES-GCM ciphertext]

with per-direction monotonic nonce counters (chunk_nonce). Every event
carries a kind byte + struct-packed body (see kvm_events.py).

Control is an acknowledged state machine, not a direct takeover. Both
peers track, per peer:

    link status:  offline -> connecting -> linked -> ready -> error
                  (ready means an authenticated channel that exchanged
                   screen info; mDNS discovery alone never means ready)
    control state: local | requesting | controlling | remote_preparing
                   | remote | reverting

Handoff flow (all messages carry a handoff_id):

    controller edge hit -> CONTROL_REQUEST(id, entry_x, entry_y, mask)
        controller stays *local*: cursor visible, input untouched
    target validates (paired, consent, topology, platform, no other
        active controller, channel live) -> remote_preparing ->
        CONTROL_READY(id)
    controller parks/hides its cursor at the screen center and sends
        CONTROL_BEGIN(id); input is still NOT suppressed
    target applies the absolute entry position + modifier mask, enters
        remote (suppresses local input) and sends CONTROL_ACTIVE(id)
    controller suppresses and forwards input only from CONTROL_ACTIVE on

Any timeout, stale handoff id, disconnect, platform failure, denied
consent or error produces CONTROL_CANCEL/CONTROL_REVERT and forces both
sides back to local. Control returns only via an explicit edge exit,
the escape chord (Ctrl+Alt+Space / Ctrl+Option+Space), channel loss or
a stall - never silently.

Safety: a peer that never explicitly confirms readiness cannot suppress
our input (the platform delegation is derived from confirmed states).
ALL_KEYS_UP reconciles both sides' key state on every handback.
"""

import base64
import collections
import json
import os
import random
import socket
import struct
import threading
import time

from cryptography.exceptions import InvalidTag

from . import crypto
from .kvm_events import (
    KIND_ALL_KEYS_UP,
    KIND_CONTROL_ACTIVE,
    KIND_CONTROL_BEGIN,
    KIND_CONTROL_CANCEL,
    KIND_CONTROL_READY,
    KIND_CONTROL_REQUEST,
    KIND_CONTROL_REVERT,
    KIND_EDGE_HIT,
    KIND_ERROR,
    KIND_KEY_DOWN,
    KIND_KEY_UP,
    KIND_MODIFIERS,
    KIND_MOUSE_BUTTON,
    KIND_MOUSE_MOVE_ABS,
    KIND_MOUSE_MOVE_REL,
    KIND_MOUSE_WHEEL,
    KIND_PING,
    KIND_PONG,
    KIND_SCREEN_INFO,
    decode_abs,
    decode_button,
    decode_control_request,
    decode_edge_hit,
    decode_error,
    decode_handoff_id,
    decode_handoff_message,
    decode_key,
    decode_modifiers,
    decode_rel,
    decode_screen_info,
    decode_wheel,
    encode_button,
    encode_control_request,
    encode_handoff_id,
    encode_handoff_message,
    encode_key,
    encode_modifiers,
    encode_rel,
    encode_screen_info,
    encode_wheel,
    unpack_event,
)
from .kvm_geometry import (
    GeometryError,
    JUMP_ZONE,
    LATCH_ZONE,
    ScreenLayout,
    entry_point,
    in_jump_zone,
    opposite_side,
    return_point,
    seam_fraction,
    verify_topology,
)
from .kvm_keymap import hid_is_modifier, modifier_hids_for_mask
from .transfer import ProtocolError, recv_frame, send_frame

KVM_PROTOCOL_VERSION = 1
RECONNECT_INTERVAL = 5.0
CHANNEL_READ_TIMEOUT = 2.0
STALL_TIMEOUT = 6.0
KEEPALIVE_INTERVAL = 2.0
HANDOFF_TIMEOUT = 1.5
HANDSHAKE_TIMEOUT = 5.0
MAX_FRAME = 1 << 20
COUNTER_LIMIT = 1 << 31
MAX_PENDING_KVM = 8        # concurrent unauthenticated opening connections
MAX_PENDING_KVM_PER_IP = 4
# F7: how long an active session may see zero key events (mouse alive)
# before the "no keyboard input" tap restart is attempted. Long enough
# that a user simply not typing is never treated as a fault.
KEYBOARD_NO_KEY_GRACE = 15.0


def _set_low_latency(conn) -> None:
    """Disable Nagle buffering for latency-sensitive KVM events."""
    try:
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass

# Control states (per peer).
STATE_LOCAL = "local"
STATE_REQUESTING = "requesting"
STATE_CONTROLLING = "controlling"
STATE_REMOTE_PREPARING = "remote_preparing"
STATE_REMOTE = "remote"
STATE_REVERTING = "reverting"

# Link states (per peer): mDNS discovery alone is never readiness.
LINK_OFFLINE = "offline"
LINK_CONNECTING = "connecting"
LINK_LINKED = "linked"
LINK_READY = "ready"
LINK_ERROR = "error"


class KvmError(Exception):
    pass


class InputPlatform:
    """Interface implemented by kvm_platform_mac / kvm_platform_win.

    The platform captures local input and forwards it to the engine via
    the ``on_local_*`` callbacks; the engine drives the platform through
    ``set_delegation`` and the ``inject_*`` methods. Capture runs whenever
    the engine is started; set_delegation decides what the capture does:

        local       pass input through untouched (never repost it); the
                    engine only watches for the seam edge
        controlling suppress input and forward it to the peer (entered
                    only after CONTROL_ACTIVE was confirmed)
        remote      suppress forwarded input; a physical pointer move or
                    button press releases control back to this device

    Injected events must never reach the capture callback again
    (self-injection filtering); the platform is responsible for that.
    """

    def start(self, engine) -> None:
        raise NotImplementedError

    def stop(self) -> None:
        raise NotImplementedError

    def permission_ok(self) -> bool:
        return True

    def permission_detail(self) -> str:
        """Human-readable description of the missing permission ("" ok)."""
        return ""

    def screen_layout(self) -> ScreenLayout:
        raise NotImplementedError

    def cursor_position(self) -> tuple[int, int]:
        raise NotImplementedError

    def warp_cursor(self, x: int, y: int) -> None:
        raise NotImplementedError

    def hide_cursor(self) -> None:
        raise NotImplementedError

    def show_cursor(self) -> None:
        raise NotImplementedError

    def set_delegation(self, state: str) -> bool:
        """Switch capture behavior; False means the OS-level delegation
        (e.g. cursor association) could not be applied."""
        return True

    def inject_move_rel(self, dx: int, dy: int) -> None:
        raise NotImplementedError

    def inject_move_abs(self, x: int, y: int) -> None:
        raise NotImplementedError

    def inject_button(self, button: int, down: bool) -> None:
        raise NotImplementedError

    def inject_wheel(self, dy: int, dx: int) -> None:
        raise NotImplementedError

    def inject_key(self, hid: int, down: bool) -> None:
        raise NotImplementedError


def kvm_channel_key(trust_key: bytes, version: int, fp_i: str, fp_r: str, nonce8_i: bytes, nonce8_r: bytes) -> bytes:
    """Channel key; every handshake parameter is bound into the KDF."""
    salt = b"".join(
        (
            struct.pack(">I", version),
            b"initiator",
            fp_i.encode("utf-8"),
            fp_r.encode("utf-8"),
            nonce8_i,
            nonce8_r,
        )
    )
    return crypto.derive_kvm_channel_key(trust_key, salt)


def validate_open(header: dict) -> bool:
    if header.get("type") != "kvm_open" or header.get("v") != KVM_PROTOCOL_VERSION:
        return False
    if not isinstance(header.get("fp"), str) or not header.get("fp"):
        return False
    try:
        nonce8 = base64.b64decode(header["nonce8"])
    except (KeyError, ValueError, TypeError):
        return False
    return len(nonce8) == crypto.CHUNK_NONCE_PREFIX_BYTES


def validate_ack(ack: dict, my_fp: str, expected_peer: str, my_nonce8: bytes) -> bool:
    if ack.get("type") != "kvm_ack" or ack.get("v") != KVM_PROTOCOL_VERSION:
        return False
    if ack.get("fp") != expected_peer or ack.get("peer_fp") != my_fp:
        return False
    try:
        nonce8 = base64.b64decode(ack["nonce8"])
    except (KeyError, ValueError, TypeError):
        return False
    return len(nonce8) == crypto.CHUNK_NONCE_PREFIX_BYTES


class KvmChannel:
    """One encrypted binary event stream to a paired peer."""

    def __init__(self, conn, peer_fp, peer_name, key, nonce8_out, nonce8_in, engine, role, inbound_start=0):
        self.conn = conn
        self.peer_fp = peer_fp
        self.peer_name = peer_name
        self.key = key
        self.nonce8_out = nonce8_out
        self.nonce8_in = nonce8_in
        self._engine = engine
        self.role = role
        self._lock = threading.Lock()
        self.closed = False
        self._engine_removed = False
        self._outbound = 0
        self._inbound = inbound_start  # responder pre-consumes frame 0 (key confirmation)
        self.last_inbound = time.monotonic()
        self._last_ping = 0.0
        # Outbound writer: the event tap / hook callbacks must never block
        # on sendall. Control and key frames are prioritized over mouse
        # motion, and relative motion is coalesced into one frame.
        self._ctrlq: collections.deque = collections.deque()
        self._dataq: collections.deque = collections.deque()
        self._sendcv = threading.Condition()
        self._writer = threading.Thread(
            target=self._writer_loop, name=f"kvm-send-{peer_fp[:6]}", daemon=True
        )
        self._writer.start()

    @staticmethod
    def _is_priority(kind: int) -> bool:
        """Control, keep-alive and discrete input frames outrank mouse
        movement so a mouse flood can never starve a revert/key frame."""
        return kind in (
            KIND_ALL_KEYS_UP,
            KIND_CONTROL_ACTIVE,
            KIND_CONTROL_BEGIN,
            KIND_CONTROL_CANCEL,
            KIND_CONTROL_READY,
            KIND_CONTROL_REQUEST,
            KIND_CONTROL_REVERT,
            KIND_ERROR,
            KIND_KEY_DOWN,
            KIND_KEY_UP,
            KIND_MODIFIERS,
            KIND_MOUSE_BUTTON,
            KIND_MOUSE_WHEEL,
            KIND_PING,
            KIND_PONG,
            KIND_SCREEN_INFO,
        )

    def send_event(self, kind: int, body: bytes = b"") -> bool:
        """Queue one event for the writer thread. True means the frame was
        accepted; False means the channel is already closed. Send failures
        surface in the writer (forced teardown), never silently here."""
        with self._lock:
            if self.closed or self._outbound >= COUNTER_LIMIT:
                return False
        with self._sendcv:
            if self._is_priority(kind):
                self._ctrlq.append((kind, body))
            elif kind == KIND_MOUSE_MOVE_REL and self._dataq and self._dataq[-1][0] == "rel":
                # Coalesce consecutive relative motion into one frame.
                _, dx, dy = self._dataq[-1]
                ndx, ndy = struct.unpack(">hh", body)
                self._dataq[-1] = ("rel", dx + ndx, dy + ndy)
            else:
                if kind == KIND_MOUSE_MOVE_REL:
                    ndx, ndy = struct.unpack(">hh", body)
                    self._dataq.append(("rel", ndx, ndy))
                else:
                    self._dataq.append((kind, body))
            self._sendcv.notify()
        self._engine._bump_stat("queued_frames")
        return True

    def _writer_loop(self) -> None:
        while not self.closed or self._ctrlq or self._dataq:
            with self._sendcv:
                while not self._ctrlq and not self._dataq and not self.closed:
                    self._sendcv.wait(0.25)
                if self._ctrlq:
                    item = self._ctrlq.popleft()
                elif self._dataq:
                    item = self._dataq.popleft()
                else:
                    continue
            try:
                if item[0] == "rel":
                    self._flush_rel(item[1], item[2])
                else:
                    self._flush_locked(item[0], item[1])
            except Exception:
                # No writer failure may strand the session: anything
                # unexpected still tears the channel down.
                try:
                    self._engine.on_status(
                        "KVM: channel send failed - tearing down session", level="error"
                    )
                except Exception:
                    pass
                self._engine._bump_stat("send_failures")
                self.closed = True
                self.close()
                self.engine_remove()
                return
            if self.closed:
                break

    def _flush_rel(self, dx: int, dy: int) -> None:
        """Send relative motion, splitting deltas that overflow the signed
        16-bit wire format. A blocked network writer can coalesce an
        arbitrary amount of motion into one queue entry; without the split
        struct.pack would raise and kill this thread, leaving the channel
        open and the peer state active."""
        while dx or dy:
            cdx = max(-32767, min(32767, dx))
            cdy = max(-32767, min(32767, dy))
            self._flush_locked(KIND_MOUSE_MOVE_REL, struct.pack(">hh", cdx, cdy))
            dx -= cdx
            dy -= cdy
            if self.closed:
                return

    def _flush_locked(self, kind: int, body: bytes) -> None:
        plain = bytes([kind]) + body
        failed = False
        with self._lock:
            if self.closed:
                return
            nonce = crypto.chunk_nonce(self.nonce8_out, self._outbound)
            ct = crypto.encrypt_with_nonce(self.key, nonce, plain)
            try:
                self.conn.sendall(struct.pack(">I", len(ct)) + ct)
                self._outbound += 1
            except OSError:
                # A dead socket must tear the channel down so the peer's
                # per-peer state cannot stay frozen at "controlling".
                self._engine._bump_stat("send_failures")
                self.closed = True
                failed = True
        if failed:
            # Teardown runs without the channel lock: engine_remove() takes
            # the engine lock, and holding the channel lock here would
            # invert the callback order (engine lock -> send_event ->
            # channel lock) and deadlock the send-failure recovery path.
            try:
                self._engine.on_status(
                    "KVM: channel send failed - tearing down session", level="error"
                )
            except Exception:
                pass
            self.close()
            self.engine_remove()
            return
        self._engine._bump_stat("outbound_frames")

    def run(self) -> None:
        """Blocking binary frame-read loop; runs in a dedicated thread or in
        the server connection thread depending on which side initiated.
        engine_remove() is guaranteed via finally so a handler exception can
        never leave the engine's per-peer state frozen."""
        try:
            self._run_loop()
        finally:
            self.engine_remove()

    def _run_loop(self) -> None:
        self.conn.settimeout(CHANNEL_READ_TIMEOUT)
        while not self.closed:
            try:
                raw = recv_frame(self.conn)
            except socket.timeout:
                if self._engine.control_active(self):
                    now = time.monotonic()
                    if now - self.last_inbound > self._engine.stall_timeout:
                        break
                    if now - self._last_ping >= self._engine.keepalive_interval:
                        self._last_ping = now
                        self.send_event(KIND_PING)
                continue
            except Exception:
                break
            if len(raw) > MAX_FRAME:
                break
            try:
                nonce = crypto.chunk_nonce(self.nonce8_in, self._inbound)
                plain = crypto.decrypt_with_nonce(self.key, nonce, raw)
            except (InvalidTag, ValueError):
                break  # key confirmation failure or tampering
            self._inbound += 1
            self.last_inbound = time.monotonic()
            try:
                kind, body = unpack_event(plain)
            except ProtocolError:
                break
            try:
                self._engine.handle_event(self, kind, body)
            except Exception as exc:
                # A platform-layer failure handling one event must never kill
                # this thread silently: that would freeze the per-peer engine
                # state (on_channel_closed, the only reset, runs after this
                # loop). Contain the event and keep the session alive; the
                # finally in run() remains the teardown net for read-level
                # failures.
                try:
                    self._engine.on_status(
                        f"KVM: error handling event: {exc}", level="error"
                    )
                except Exception:
                    pass

    def engine_remove(self) -> None:
        if self._engine_removed:
            return
        self._engine_removed = True
        self._engine.on_channel_closed(self)

    def close(self) -> None:
        self.closed = True
        with self._sendcv:
            self._sendcv.notify_all()
        try:
            self.conn.shutdown(socket.SHUT_RDWR)
        except (OSError, AttributeError):
            pass
        try:
            self.conn.close()
        except (OSError, AttributeError):
            pass


class KVMEngine:
    """Drives input sharing with paired, discovered peers."""

    def __init__(self, store, discovery, platform=None, on_status=None, relay=None):
        self.store = store
        self.discovery = discovery
        self.platform = platform
        self.relay = relay  # optional: (fp, kind, body) echo back for tests
        self.on_status = on_status or (lambda s, level="info": None)
        self.enabled = bool(store.kvm_enabled)
        self.stall_timeout = STALL_TIMEOUT
        self.keepalive_interval = KEEPALIVE_INTERVAL
        self.handoff_timeout = HANDOFF_TIMEOUT
        self._channels: dict[str, KvmChannel] = {}
        # Unauthenticated opening connections: admitted only after the
        # first binary frame decrypts (key confirmation). A pending entry
        # can never displace an active channel.
        self._pending: list[dict] = []  # {"conn", "fp", "addr", "deadline"}
        self._pending_by_ip: dict[str, int] = {}
        # Control state machine per peer (see STATE_*).
        self._state: dict[str, str] = {}
        # In-flight handoff records per peer:
        #   {"id", "role" ("controller"|"target"), "stage", "deadline",
        #    "entry" (x, y), "mask", "fraction", "parked"}
        self._handoffs: dict[str, dict] = {}
        # Authenticated channel readiness per peer (see LINK_*).
        self._link_status: dict[str, str] = {}
        self._peer_layouts: dict[str, ScreenLayout] = {}
        self._peer_sides: dict[str, str] = {}
        self._topology_ok: dict[str, bool] = {}
        # Edge that a refused handoff keeps blocked until the pointer
        # leaves it (at most one refusal message per edge dwell).
        self._blocked_edge: dict[str, str] = {}
        # Target side: while a peer's request was refused, ignore further
        # requests (and notifications) until that peer cancels / the
        # channel changes.
        self._denial_latch: dict[str, str] = {}
        self._last_sent_id: dict[str, int] = {}
        self._handoff_seq = random.randrange(1 << 29)  # random start: simultaneous takeovers must never share ids
        self._chord_armed = True
        self._perm_notified = False
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._connect_thread = None
        self._watchdog_thread = None
        self._platform_started = False
        # Diagnostics (F6): never toasted per event, exposed via diagnostics().
        self._stats: dict = {
            "outbound_frames": 0,
            "queued_frames": 0,
            "reverts_sent": 0,
            "send_failures": 0,
        }
        self._stats_lock = threading.Lock()
        # Ordered state-machine history for debugging (F3).
        self._transition_log: collections.deque = collections.deque(maxlen=64)
        # Platform family tag set by the input platform ("mac" / "win").
        self._capture_origin = ""
        self._keyboard_stall_stage = 0  # F7: 0 ok, 1 tap restarted, 2 latched mouse-only
        self._active_since = None  # F7: monotonic time the current session went active
        self.pressed: set[int] = set()  # HID keys I injected (remote side)
        self.modifier_mask = 0  # modifiers I injected (remote side)
        self._local_mask = 0  # modifiers physically held here (controller side)
        self._local_pressed: set[int] = set()  # non-modifier HID keys held here

    def _bump_stat(self, name: str, amount: int = 1) -> None:
        with self._stats_lock:
            self._stats[name] = self._stats.get(name, 0) + amount

    def _log_transition(
        self, fp: str, state: str, stage=None, hid=None, reason: str = None
    ) -> None:
        """Append (ts, fp, state, stage, hid, reason, blocked_edge_after).

        ``blocked_edge_after`` is the per-peer edge latch at log time; it is
        what tells a handback from an accidental immediate re-acquire apart.
        """
        self._transition_log.append(
            (
                time.monotonic(),
                fp,
                state,
                stage or "",
                hid or 0,
                reason or "",
                self._blocked_edge.get(fp),
            )
        )

    def recent_transitions(self) -> list:
        return list(self._transition_log)

    def control_label(self, fp: str) -> str:
        """UI label; 'controlling' before CONTROL_ACTIVE is really a
        waiting state (cursor parked, input still local)."""
        with self._lock:
            state = self._state.get(fp, STATE_LOCAL)
            if state == STATE_CONTROLLING:
                rec = self._handoffs.get(fp)
                if rec is not None and rec.get("stage") == "waiting_active":
                    return "waiting_active"
            return state

    def diagnostics(self) -> dict:
        """F6: counters + queue depth + state snapshot for the UI."""
        with self._stats_lock:
            out = dict(self._stats)
        with self._lock:
            out["channels"] = len(self._channels)
            out["queued"] = sum(
                len(ch._ctrlq) + len(ch._dataq) for ch in self._channels.values()
            )
            out["state"] = dict(self._state)
            out["blocked_edges"] = dict(self._blocked_edge)
            out["transitions"] = list(self._transition_log)
        if self.platform is not None:
            try:
                out["platform"] = self.platform.diagnostics()
            except Exception:
                pass
        return out

    # -- lifecycle -----------------------------------------------------------

    def start(self) -> None:
        self._stop.clear()
        if self.enabled:
            self._start_platform()
        if self._connect_thread is None or not self._connect_thread.is_alive():
            self._connect_thread = threading.Thread(target=self._connect_loop, name="kvm-connect", daemon=True)
            self._connect_thread.start()
        if self._watchdog_thread is None or not self._watchdog_thread.is_alive():
            self._watchdog_thread = threading.Thread(target=self._watchdog_loop, name="kvm-watchdog", daemon=True)
            self._watchdog_thread.start()

    def _start_platform(self) -> bool:
        """Start input capture only when the user explicitly enables sharing."""
        if self.platform is None or self._platform_started:
            return self.platform is not None
        try:
            self.platform.start(self)
            self._platform_started = True
            self._perm_notified = False
            return True
        except Exception as exc:
            detail = ""
            try:
                detail = self.platform.permission_detail()
            except Exception:
                pass
            if not self._perm_notified:
                self._perm_notified = True
                self.on_status(
                    f"Mouse & keyboard sharing needs permission: {detail or exc}",
                    level="error",
                )
            return False

    def _stop_input(self) -> None:
        """Force every local/remote control state back to local."""
        self._handoffs.clear()
        self._blocked_edge.clear()
        self._denial_latch.clear()
        self._last_sent_id.clear()
        self._local_pressed.clear()
        self._local_mask = 0
        self._restore_local_delegation(attempts=2)
        self._release_all_keys()
        self._chord_armed = True
        self._active_since = None

    def stop(self) -> None:
        self._stop.set()
        for ch in list(self._channels.values()):
            ch.close()
        self._channels.clear()
        self._state.clear()
        self._link_status.clear()
        self._peer_layouts.clear()
        self._peer_sides.clear()
        self._topology_ok.clear()
        self._stop_input()
        if self.platform is not None and self._platform_started:
            try:
                self.platform.stop()
            except Exception:
                pass
        self._platform_started = False

    def set_enabled(self, enabled: bool) -> None:
        self.enabled = bool(enabled)
        self.store.set_kvm_enabled(self.enabled)
        if not self.enabled:
            for ch in list(self._channels.values()):
                ch.close()
            self._channels.clear()
            self._state.clear()
            self._link_status.clear()
            self._peer_layouts.clear()
            self._peer_sides.clear()
            self._topology_ok.clear()
            self._stop_input()
            self.on_status("Keyboard & mouse sharing: off")
        else:
            if not self._start_platform():
                self.enabled = False
                self.store.set_kvm_enabled(False)
                return
            self.on_status("Keyboard & mouse sharing: on")

    # -- public accessors (UI) ------------------------------------------------

    def link_status(self, fp: str) -> str:
        with self._lock:
            return self._link_status.get(fp, LINK_OFFLINE)

    def control_state(self, fp: str) -> str:
        with self._lock:
            return self._state.get(fp, STATE_LOCAL)

    def control_active(self, channel: KvmChannel) -> bool:
        return self._state.get(channel.peer_fp, STATE_LOCAL) != STATE_LOCAL

    # -- inbound (from Node._on_other) ----------------------------------------

    def on_inbound(self, conn, header, header_bytes, addr) -> None:
        _set_low_latency(conn)
        fp = header.get("fp", "")
        peer = self.store.get_peer(fp) if validate_open(header) else None
        if peer is None or not self.enabled:
            try:
                send_frame(conn, {"type": "error", "code": "kvm_disabled"})
            except OSError:
                pass
            return
        if not self._admit_pending(conn, fp, addr):
            try:
                send_frame(conn, {"type": "error", "code": "kvm_busy"})
            except OSError:
                pass
            return
        try:
            # Challenge/response: derive the channel key from the open and
            # demand the first binary frame (key confirmation) NOW, while
            # the current channel stays untouched.
            my_nonce8 = os.urandom(crypto.CHUNK_NONCE_PREFIX_BYTES)
            peer_nonce8 = base64.b64decode(header["nonce8"])
            key = kvm_channel_key(
                peer["trust_key"], KVM_PROTOCOL_VERSION, fp, self.store.fingerprint(), peer_nonce8, my_nonce8
            )
            conn.settimeout(HANDSHAKE_TIMEOUT)
            send_frame(
                conn,
                {
                    "type": "kvm_ack",
                    "v": KVM_PROTOCOL_VERSION,
                    "fp": self.store.fingerprint(),
                    "peer_fp": fp,
                    "nonce8": base64.b64encode(my_nonce8).decode("ascii"),
                },
            )
            raw = recv_frame(conn)
            nonce = crypto.chunk_nonce(peer_nonce8, 0)
            plain = crypto.decrypt_with_nonce(key, nonce, raw)
            confirmed_kind, confirmed_body = unpack_event(plain)
        except (OSError, ProtocolError, ValueError, InvalidTag):
            try:
                send_frame(conn, {"type": "error", "code": "kvm_auth_failed"})
            except OSError:
                pass
            return
        finally:
            self._release_pending(conn)
        # Authenticated: only now may the current valid channel be replaced.
        with self._lock:
            old = self._channels.get(fp)
            if old is not None:
                old.close()
            if self._edge_claimed(fp):
                try:
                    send_frame(conn, {"type": "error", "code": "kvm_edge_busy"})
                except OSError:
                    pass
                return
            ch = KvmChannel(
                conn,
                fp,
                peer.get("name", fp[:8]),
                key,
                my_nonce8,
                peer_nonce8,
                self,
                "responder",
                inbound_start=1,
            )
            self._channels[fp] = ch
            self._link_status[fp] = LINK_LINKED
        # Dispatch the key-confirmation frame (the peer's screen info).
        self.handle_event(ch, confirmed_kind, confirmed_body)
        self._send_screen_info(ch)
        self.on_status(f"KVM linked with {ch.peer_name}")
        ch.run()

    def _admit_pending(self, conn, fp: str, addr: tuple) -> bool:
        """Admit an opening connection under the pending caps."""
        with self._lock:
            if len(self._pending) >= MAX_PENDING_KVM:
                return False
            if self._pending_by_ip.get(addr[0], 0) >= MAX_PENDING_KVM_PER_IP:
                return False
            self._pending.append(
                {
                    "conn": conn,
                    "fp": fp,
                    "addr": addr,
                    "deadline": time.monotonic() + HANDSHAKE_TIMEOUT,
                }
            )
            self._pending_by_ip[addr[0]] = self._pending_by_ip.get(addr[0], 0) + 1
            return True

    def _release_pending(self, conn) -> None:
        with self._lock:
            for i, entry in enumerate(self._pending):
                if entry["conn"] is conn:
                    del self._pending[i]
                    ip = entry["addr"][0]
                    n = self._pending_by_ip.get(ip, 0)
                    if n <= 1:
                        self._pending_by_ip.pop(ip, None)
                    else:
                        self._pending_by_ip[ip] = n - 1
                    return

    def _edge_claimed(self, fp: str) -> bool:
        side = self._my_side_for(fp)
        for other_fp, ch in self._channels.items():
            if other_fp != fp and self._my_side_for(other_fp) == side:
                return True
        return False

    # -- outbound -------------------------------------------------------------

    def _connect_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.ensure_connections()
            except Exception:
                pass
            self._stop.wait(RECONNECT_INTERVAL)

    def ensure_connections(self) -> None:
        if not self.enabled or self.platform is None:
            return
        my_fp = self.store.fingerprint()
        for fp, peer in self.discovery.peers().items():
            if fp == my_fp:
                continue
            with self._lock:
                if fp in self._channels or not self.store.is_paired(fp):
                    continue
            if fp > my_fp:
                continue  # the other side initiates
            with self._lock:
                self._link_status[fp] = LINK_CONNECTING
            conn = None
            try:
                conn = socket.create_connection((peer.host, peer.port), timeout=10)
                _set_low_latency(conn)
                conn.settimeout(HANDSHAKE_TIMEOUT)
                my_nonce8 = os.urandom(crypto.CHUNK_NONCE_PREFIX_BYTES)
                send_frame(
                    conn,
                    {
                        "type": "kvm_open",
                        "v": KVM_PROTOCOL_VERSION,
                        "fp": my_fp,
                        "nonce8": base64.b64encode(my_nonce8).decode("ascii"),
                    },
                )
                raw = recv_frame(conn)
                ack = json.loads(raw.decode("utf-8"))
            except Exception:
                if conn is not None:
                    try:
                        conn.close()
                    except OSError:
                        pass
                with self._lock:
                    if fp not in self._channels:
                        self._link_status[fp] = LINK_ERROR
                continue
            if not validate_ack(ack, my_fp, fp, my_nonce8):
                try:
                    conn.close()
                except OSError:
                    pass
                with self._lock:
                    if fp not in self._channels:
                        self._link_status[fp] = LINK_ERROR
                continue
            trust_key = self.store.get_peer(fp)["trust_key"]
            peer_nonce8 = base64.b64decode(ack["nonce8"])
            key = kvm_channel_key(trust_key, KVM_PROTOCOL_VERSION, my_fp, fp, my_nonce8, peer_nonce8)
            channel = KvmChannel(conn, fp, peer.name, key, my_nonce8, peer_nonce8, self, "initiator")
            with self._lock:
                if self._edge_claimed(fp):
                    channel.close()
                    self._link_status[fp] = LINK_ERROR
                    continue
                self._channels[fp] = channel
                self._link_status[fp] = LINK_LINKED
            self._send_screen_info(channel)
            self.on_status(f"KVM linked with {channel.peer_name}")
            threading.Thread(target=channel.run, name="kvm-out-conn", daemon=True).start()

    def _send_screen_info(self, channel: KvmChannel) -> None:
        if self.platform is None:
            return
        try:
            layout = self.platform.screen_layout()
        except Exception:
            return
        body = encode_screen_info(layout.to_monitors(), layout.primary, self._my_side_for(channel.peer_fp))
        channel.send_event(KIND_SCREEN_INFO, body)

    # -- watchdog: handoff deadlines ------------------------------------------

    def _watchdog_loop(self) -> None:
        while not self._stop.is_set():
            self._stop.wait(0.2)
            if not self.enabled:
                continue
            now = time.monotonic()
            with self._lock:
                for rec in list(self._handoffs.items()):
                    deadline = rec[1].get("deadline")
                    if deadline and now >= deadline:
                        self._expire_handoff(rec[0], rec[1])
                self._sweep_pending(now)
                self._poll_keyboard_health()

    def _sweep_pending(self, now: float) -> None:
        """Expire stalled opening connections; they never touch _channels."""
        stale = [e for e in self._pending if e["deadline"] <= now]
        for entry in stale:
            try:
                entry["conn"].close()
            except OSError:
                pass
            self._pending.remove(entry)
            ip = entry["addr"][0]
            n = self._pending_by_ip.get(ip, 0)
            if n <= 1:
                self._pending_by_ip.pop(ip, None)
            else:
                self._pending_by_ip[ip] = n - 1

    def _poll_keyboard_health(self) -> None:
        """F7: detect a mac keyboard stream that went quiet while mouse
        events still flow - the classic Secure Input symptom - and
        escalate: restart the HID tap, then latch mouse-only mode.

        Two distinct signatures:
          - "stalled": keys flowed and then stopped. The genuine Secure
            Input case; escalates to a latched mouse-only notice.
          - "no_keys": zero key events ever during the session. Ambiguous
            (the user may simply not be typing): waits out a grace period,
            then restarts the tap once - never latches mouse-only.
        """
        if self.platform is None or not hasattr(self.platform, "keyboard_health"):
            return
        if not any(s != STATE_LOCAL for s in self._state.values()):
            return
        try:
            health = self.platform.keyboard_health()
        except Exception:
            return
        if health == "stalled":
            if self._keyboard_stall_stage == 0:
                self._keyboard_stall_stage = 1
                try:
                    self.platform.note_keyboard_stall()
                except Exception:
                    pass
                self.on_status("KVM: keyboard stream stalled - restarting event tap")
            elif self._keyboard_stall_stage == 1:
                self._keyboard_stall_stage = 2
                self.on_status(
                    "KVM: macOS Secure Input is preventing keyboard sharing - mouse-only mode",
                    level="error",
                )
        elif health == "no_keys":
            now = time.monotonic()
            if self._active_since and now - self._active_since < KEYBOARD_NO_KEY_GRACE:
                return
            if self._keyboard_stall_stage == 0:
                self._keyboard_stall_stage = 1
                try:
                    self.platform.note_keyboard_stall()
                except Exception:
                    pass
                self.on_status(
                    "KVM: no keyboard input received during this session - "
                    "restarting event tap"
                )
        elif self._keyboard_stall_stage == 2:
            self._keyboard_stall_stage = 0
            self.on_status("KVM: keyboard sharing recovered")
        else:
            self._keyboard_stall_stage = 0

    def _expire_handoff(self, fp: str, rec: dict) -> None:
        ch = self._channels.get(fp)
        if ch is not None and not ch.closed:
            try:
                ch.send_event(KIND_CONTROL_CANCEL, encode_handoff_message(rec["id"], "timeout"))
            except Exception:
                pass
        if rec["role"] == "controller":
            self._blocked_edge[fp] = self._my_side_for(fp)
            self._revert_control(ch, "handoff timeout")
        else:
            self._revert_remote(ch, "handoff timeout")

    # -- platform callbacks (capture side) ------------------------------------

    def on_local_mouse(self, dx: int, dy: int, x: int, y: int) -> None:
        if not self.enabled or self.platform is None:
            return
        with self._lock:
            handoff_side = self._cursor_side(x, y)
            # Edge latches (a handback or refusal) clear only once the
            # pointer has clearly left the edge: the wider LATCH_ZONE, not
            # the 3 px handoff zone.  A revert restores the cursor just
            # inside the seam, so an 8 px latch zone keeps the former
            # controller from re-acquiring on residual motion.
            latch_side = self._cursor_side(x, y, LATCH_ZONE)
            for fp in list(self._blocked_edge):
                if latch_side is None or latch_side != self._blocked_edge[fp]:
                    self._blocked_edge.pop(fp, None)
                    self._send_edge_left_cancel(fp)
            channel = self._active_channel()
            if channel is not None:
                self._on_active_local_mouse(channel, dx, dy, x, y, handoff_side)
                return
            if handoff_side is None:
                return
            channel = self._channel_for(handoff_side)
            if channel is None:
                return
            fp = channel.peer_fp
            if handoff_side != self._my_side_for(fp):
                return
            if fp in self._blocked_edge:
                return
            if not self._link_ready(fp):
                return
            peer_layout = self._peer_layouts.get(fp)
            if peer_layout is None:
                return
            fraction = seam_fraction(self._my_layout(), handoff_side, x, y)
            tx, ty = entry_point(peer_layout, handoff_side, fraction)
            self._request_control(channel, tx, ty, fraction)

    def _on_active_local_mouse(self, channel, dx: int, dy: int, x: int, y: int, cursor_side) -> None:
        fp = channel.peer_fp
        state = self._state.get(fp, STATE_LOCAL)
        if state == STATE_CONTROLLING:
            rec = self._handoffs.get(fp)
            if rec is not None and rec.get("stage") == "active":
                channel.send_event(KIND_MOUSE_MOVE_REL, encode_rel(dx, dy))
            return
        if state == STATE_REQUESTING:
            # While a handoff is pending the pointer may wander away from
            # the edge; that withdraws the request.
            if cursor_side is None or cursor_side != self._my_side_for(fp):
                self._cancel_outbound(fp, "edge-left")
            return
        if state == STATE_REMOTE:
            origin = f"{self._capture_origin}-pointer" if self._capture_origin else "local-pointer"
            self.on_remote_local_input(origin=origin)

    def on_remote_local_input(self, origin: str = "local-input") -> None:
        """Release a peer's control after physical pointer input here.

        The controlled device is independent again after a local mouse move,
        click, or scroll.  In particular, injected pointer motion reaching a
        screen edge must *not* hand control back, or the two sides repeatedly
        bounce control as the cursor is clamped to that edge.
        """
        with self._lock:
            channel = self._active_channel()
            if channel is None:
                return
            fp = channel.peer_fp
            if self._state.get(fp) != STATE_REMOTE:
                return
            rec = self._handoffs.get(fp)
            if rec is None or channel.closed:
                return
            self._bump_stat("reverts_sent")
            ok = channel.send_event(KIND_CONTROL_REVERT, encode_handoff_message(rec["id"], origin))
            if not ok:
                # The frame could not even be queued: force the session
                # down so the peer's state cannot stay frozen.
                try:
                    self.on_status(
                        f"KVM DEBUG: revert id={rec['id']} send failed - forcing teardown",
                        level="error",
                    )
                except Exception:
                    pass
                channel.close()
                channel.engine_remove()
                return
            self._revert_remote(channel, "local input", origin=origin)

    def on_local_button(self, button: int, down: bool) -> None:
        with self._lock:
            channel = self._active_channel()
            if channel is None:
                return
            fp = channel.peer_fp
            if self._state.get(fp) == STATE_REMOTE:
                origin = f"{self._capture_origin}-pointer" if self._capture_origin else "local-pointer"
                self.on_remote_local_input(origin=origin)
                return
            rec = self._handoffs.get(fp)
            if self._state.get(fp) != STATE_CONTROLLING or rec is None or rec.get("stage") != "active":
                return
            channel.send_event(KIND_MOUSE_BUTTON, encode_button(button, down))

    def on_local_wheel(self, dy: int, dx: int) -> None:
        with self._lock:
            channel = self._active_channel()
            if channel is None:
                return
            fp = channel.peer_fp
            if self._state.get(fp) == STATE_REMOTE:
                origin = f"{self._capture_origin}-pointer" if self._capture_origin else "local-pointer"
                self.on_remote_local_input(origin=origin)
                return
            rec = self._handoffs.get(fp)
            if self._state.get(fp) != STATE_CONTROLLING or rec is None or rec.get("stage") != "active":
                return
            channel.send_event(KIND_MOUSE_WHEEL, encode_wheel(dy, dx))

    def on_local_key(self, hid: int, down: bool) -> None:
        if not self.enabled or self.platform is None:
            return
        with self._lock:
            # A real key press on the controlled device is an explicit
            # request to reclaim it, just like moving its physical mouse.
            # The event that triggers the release may be swallowed by the
            # platform; subsequent keys go to the now-local device normally.
            channel = self._active_channel()
            if channel is not None and self._state.get(channel.peer_fp) == STATE_REMOTE:
                if down:
                    origin = f"{self._capture_origin}-key" if self._capture_origin else "local-key"
                    self.on_remote_local_input(origin=origin)
                return
            if hid_is_modifier(hid):
                self._update_local_mask(hid, down)
            else:
                if down:
                    self._local_pressed.add(hid)
                else:
                    self._local_pressed.discard(hid)
            self._check_chord()
            channel = self._active_channel()
            if channel is None:
                return
            fp = channel.peer_fp
            rec = self._handoffs.get(fp)
            if self._state.get(fp) != STATE_CONTROLLING or rec is None or rec.get("stage") != "active":
                return
            if hid_is_modifier(hid):
                channel.send_event(KIND_MODIFIERS, encode_modifiers(self._local_mask))
            else:
                channel.send_event(KIND_KEY_DOWN if down else KIND_KEY_UP, encode_key(hid))

    def _update_local_mask(self, hid: int, down: bool) -> None:
        from .kvm_keymap import modifier_mask_for_hid

        bit = modifier_mask_for_hid(hid)
        if down:
            self._local_mask |= bit
        else:
            self._local_mask &= ~bit

    def _check_chord(self) -> None:
        from .kvm_keymap import MOD_ALT, MOD_CTRL

        combo = MOD_CTRL | MOD_ALT
        if self._local_mask & combo != combo:
            self._chord_armed = True
            return
        if 0x2C in self._local_pressed and self._chord_armed:
            self._chord_armed = False
            self.on_escape_chord()

    def on_remote_edge(self, side: str, x: int, y: int) -> None:
        """My cursor (driven by the peer) reached my seam edge: hand back."""
        if not self.enabled or self.platform is None:
            return
        with self._lock:
            channel = self._active_channel()
            if channel is None:
                return
            fp = channel.peer_fp
            if self._state.get(fp) != STATE_REMOTE:
                return
            if side != self._my_side_for(fp):
                return
            rec = self._handoffs.get(fp)
            if rec is None:
                return
            channel.send_event(KIND_CONTROL_REVERT, encode_handoff_message(rec["id"], "peer-edge"))
            self._revert_remote(channel, "peer edge", origin="peer-edge")

    def on_escape_chord(self) -> None:
        """Forced local release (Ctrl+Alt+Space / Ctrl+Option+Space)."""
        if not self.enabled:
            return
        with self._lock:
            channel = self._active_channel()
            if channel is None:
                return
            fp = channel.peer_fp
            state = self._state.get(fp, STATE_LOCAL)
            rec = self._handoffs.get(fp)
            if rec is None:
                return
            if state in (STATE_CONTROLLING, STATE_REQUESTING, STATE_REMOTE, STATE_REMOTE_PREPARING):
                try:
                    channel.send_event(KIND_CONTROL_REVERT, encode_handoff_message(rec["id"], "escape"))
                except Exception:
                    pass
                if state in (STATE_REMOTE, STATE_REMOTE_PREPARING):
                    self._revert_remote(channel, "escape chord", origin="escape")
                else:
                    # Same protection as a peer-driven revert: the cursor is
                    # restored just inside the seam, so latch the edge until
                    # the pointer clearly leaves it.
                    self._blocked_edge[fp] = self._my_side_for(fp)
                    self._revert_control(channel, "escape chord", origin="escape")

    def on_display_change(self) -> None:
        if not self.enabled or self.platform is None:
            return
        for ch in list(self._channels.values()):
            self._send_screen_info(ch)

    # -- handoff: controller side ---------------------------------------------

    def _next_handoff_id(self) -> int:
        self._handoff_seq += 1
        return self._handoff_seq

    def _request_control(self, channel: KvmChannel, tx: int, ty: int, fraction: float) -> None:
        fp = channel.peer_fp
        if not self._topology_ok.get(fp, True):
            self.on_status(f"KVM with {channel.peer_name}: screen layout mismatch", level="error")
            return
        if self._active_channel() is not None:
            return
        hid = self._next_handoff_id()
        self._handoffs[fp] = {
            "id": hid,
            "role": "controller",
            "stage": "waiting_ready",
            "deadline": time.monotonic() + self.handoff_timeout,
            "entry": (tx, ty),
            "mask": self._local_mask,
            "fraction": fraction,
            "parked": False,
        }
        self._last_sent_id[fp] = hid
        self._state[fp] = STATE_REQUESTING
        self._log_transition(fp, STATE_REQUESTING, "waiting_ready", hid)
        channel.send_event(KIND_CONTROL_REQUEST, encode_control_request(hid, tx, ty, self._local_mask))

    def _cancel_outbound(self, fp: str, reason: str) -> None:
        """Withdraw a pending controller-side request."""
        rec = self._handoffs.get(fp)
        if rec is None or rec["role"] != "controller":
            return
        ch = self._channels.get(fp)
        if self._state.get(fp) == STATE_REQUESTING:
            if ch is not None and not ch.closed:
                try:
                    ch.send_event(KIND_CONTROL_CANCEL, encode_handoff_message(rec["id"], reason))
                except Exception:
                    pass
        self._handoffs.pop(fp, None)
        if self._state.get(fp) in (STATE_REQUESTING, STATE_CONTROLLING):
            self._state[fp] = STATE_LOCAL
            self._log_transition(fp, STATE_LOCAL, None, rec["id"])

    def _send_edge_left_cancel(self, fp: str) -> None:
        """Tell the target the pointer left the edge (unblocks refusals)."""
        hid = self._last_sent_id.get(fp)
        if hid is None:
            return
        ch = self._channels.get(fp)
        if ch is None or ch.closed:
            return
        try:
            ch.send_event(KIND_CONTROL_CANCEL, encode_handoff_message(hid, "edge-left"))
        except Exception:
            pass
        self._last_sent_id.pop(fp, None)

    # -- handoff: transitions ---------------------------------------------------

    def _on_control_ready(self, channel: KvmChannel, body: bytes) -> None:
        try:
            hid = decode_handoff_id(body)
        except ProtocolError:
            return
        fp = channel.peer_fp
        rec = self._handoffs.get(fp)
        if rec is None or rec["role"] != "controller" or rec["id"] != hid:
            return  # stale or unknown handoff
        if rec.get("stage") != "waiting_ready":
            return
        self._state[fp] = STATE_CONTROLLING
        rec["stage"] = "waiting_active"
        rec["deadline"] = time.monotonic() + self.handoff_timeout
        self._log_transition(fp, STATE_CONTROLLING, "waiting_active", hid)
        # Park the controller cursor at a safe center point (Input Leap
        # behaves the same way) and hide it; local input is still NOT
        # suppressed until CONTROL_ACTIVE arrives.
        try:
            self.platform.hide_cursor()
            cx, cy = self._safe_center()
            self.platform.warp_cursor(cx, cy)
            rec["parked"] = True
        except Exception as exc:
            self._fail_controller(channel, rec, "platform", f"platform failure: {exc}")
            return
        channel.send_event(KIND_CONTROL_BEGIN, encode_handoff_id(hid))
        self.on_status(f"Controlling {channel.peer_name} (waiting for remote)")

    def _on_control_active(self, channel: KvmChannel, body: bytes) -> None:
        try:
            hid = decode_handoff_id(body)
        except ProtocolError:
            return
        fp = channel.peer_fp
        rec = self._handoffs.get(fp)
        if rec is None or rec["role"] != "controller" or rec["id"] != hid:
            return
        if rec.get("stage") != "waiting_active":
            return
        rec["stage"] = "active"
        rec["deadline"] = None
        self._log_transition(fp, STATE_CONTROLLING, "active", hid)
        self._active_since = time.monotonic()
        try:
            ok = self._sync_delegation(channel)
        except Exception as exc:
            self._fail_controller(channel, rec, "platform", f"platform failure: {exc}")
            return
        if not ok:
            self._fail_controller(channel, rec, "platform", "cursor association failed")
            return
        self.on_status(f"Control active with {channel.peer_name}")

    def _on_control_begin(self, channel: KvmChannel, body: bytes) -> None:
        try:
            hid = decode_handoff_id(body)
        except ProtocolError:
            return
        fp = channel.peer_fp
        rec = self._handoffs.get(fp)
        if rec is None or rec["role"] != "target" or rec["id"] != hid:
            return  # stale
        if rec.get("stage") != "waiting_begin":
            return
        rec["stage"] = "active"
        rec["deadline"] = None
        self._state[fp] = STATE_REMOTE
        self._log_transition(fp, STATE_REMOTE, "active", hid)
        self._active_since = time.monotonic()
        # Suppress local input only now: the controller confirmed.
        try:
            ok = self._sync_delegation(channel)
            if not ok:
                raise RuntimeError("delegation failed")
            self.platform.inject_move_abs(*rec["entry"])
            if rec.get("mask") != self.modifier_mask:
                self._apply_modifiers(rec["mask"])
        except Exception as exc:
            self._fail_target(channel, rec, "platform", f"platform failure: {exc}")
            return
        channel.send_event(KIND_CONTROL_ACTIVE, encode_handoff_id(hid))
        self.on_status(f"{channel.peer_name} controls this device")

    # -- handoff: target side --------------------------------------------------

    def _on_control_request(self, channel: KvmChannel, body: bytes) -> None:
        try:
            hid, tx, ty, mask = decode_control_request(body)
        except ProtocolError:
            return
        fp = channel.peer_fp
        rec = self._handoffs.get(fp)
        if rec is not None and rec["id"] == hid:
            return  # duplicate of the in-flight attempt
        if fp in self._denial_latch:
            # The pointer is still on the rejected edge; stay silent
            # until the controller cancels / leaves the edge.
            return
        peer = self.store.get_peer(fp)
        if peer is None or not peer.get("kvm_allowed", False):
            self._denial_latch[fp] = "denied"
            self._refuse(channel, hid, "denied", f"{channel.peer_name} is not allowed to take control")
            return
        if not self._topology_ok.get(fp, True):
            self._denial_latch[fp] = "topology"
            self._refuse(channel, hid, "topology")
            return
        state = self._state.get(fp, STATE_LOCAL)
        if state != STATE_LOCAL:
            # One active control at a time. Simultaneous takeover: the
            # higher fingerprint wins (deterministic tiebreak). The
            # loser withdraws its own request (a withdrawal must not be
            # mistaken for a refusal: the winner's request stays alive).
            if state == STATE_REQUESTING and self.store.fingerprint() < fp:
                self._cancel_outbound(fp, "withdrawn")
            else:
                self._refuse(channel, hid, "busy", f"{channel.peer_name} is busy")
                return
        if self.platform is None:
            self._refuse(channel, hid, "unavailable")
            return
        if channel.closed:
            return
        if any(s != STATE_LOCAL for s in self._state.values()):
            self._refuse(channel, hid, "busy", f"{channel.peer_name} is busy")
            return
        self._handoffs[fp] = {
            "id": hid,
            "role": "target",
            "stage": "waiting_begin",
            "deadline": time.monotonic() + self.handoff_timeout,
            "entry": (tx, ty),
            "mask": mask,
            "fraction": None,
            "parked": False,
        }
        self._state[fp] = STATE_REMOTE_PREPARING
        self._log_transition(fp, STATE_REMOTE_PREPARING, "waiting_begin", hid)
        channel.send_event(KIND_CONTROL_READY, encode_handoff_id(hid))

    def _refuse(self, channel: KvmChannel, hid: int, reason: str, message: str = "") -> None:
        try:
            channel.send_event(KIND_CONTROL_CANCEL, encode_handoff_message(hid, reason))
        except Exception:
            pass
        if message:
            self.on_status(f"KVM: {message}", level="error")

    # -- handoff: cancellation / revert (both roles) ---------------------------

    def _on_control_cancel(self, channel: KvmChannel, body: bytes) -> None:
        try:
            hid, reason = decode_handoff_message(body)
        except ProtocolError:
            return
        fp = channel.peer_fp
        # Any cancel unlatches the target so a later, deliberate request
        # (after the pointer left the rejected edge) gets a fresh answer.
        self._denial_latch.pop(fp, None)
        rec = self._handoffs.get(fp)
        if rec is None or rec["id"] != hid:
            return  # stale
        reason = reason or "cancelled"
        if rec["role"] == "controller":
            # A refused or failed handoff stays blocked until the pointer
            # leaves that edge: at most one message per edge dwell. An
            # explicit withdrawal is not a refusal and must not block.
            if reason != "withdrawn":
                self._blocked_edge[fp] = self._my_side_for(fp)
            self._revert_control(channel, f"peer: {reason}")
            return
        self._revert_remote(channel, f"peer: {reason}")

    def _on_control_revert(self, channel: KvmChannel, body: bytes) -> None:
        try:
            hid, reason = decode_handoff_message(body)
        except ProtocolError:
            return
        fp = channel.peer_fp
        rec = self._handoffs.get(fp)
        if rec is None or rec["id"] != hid:
            try:
                self.on_status(
                    f"KVM DEBUG: revert id={hid} rejected as stale, rec={rec}",
                    level="error",
                )
            except Exception:
                pass
            return  # stale
        try:
            self.on_status(
                f"KVM DEBUG: revert id={hid} accepted, state={self._state.get(fp)}",
                level="error",
            )
        except Exception:
            pass
        state = self._state.get(fp, STATE_LOCAL)
        reason = reason or "peer"
        if state in (STATE_REMOTE, STATE_REMOTE_PREPARING):
            self._revert_remote(channel, f"{reason}")
        else:
            # A target-driven revert restores our cursor just inside the
            # seam; latch that edge so residual motion cannot immediately
            # re-acquire control.  The latch clears once the pointer leaves
            # the LATCH_ZONE (on_local_mouse).
            if rec["role"] == "controller" and state in (STATE_CONTROLLING, STATE_REQUESTING):
                self._blocked_edge[fp] = self._my_side_for(fp)
            self._revert_control(channel, f"{reason}")

    # -- platform failure -> safe revert ---------------------------------------

    def _fail_controller(self, channel, rec, reason, message) -> None:
        try:
            channel.send_event(KIND_CONTROL_CANCEL, encode_handoff_message(rec["id"], reason))
        except Exception:
            pass
        self._revert_control(channel, message)

    def _fail_target(self, channel, rec, reason, message) -> None:
        try:
            channel.send_event(KIND_CONTROL_CANCEL, encode_handoff_message(rec["id"], reason))
        except Exception:
            pass
        self._revert_remote(channel, message)

    # -- control transitions ---------------------------------------------------

    def _revert_control(self, channel: KvmChannel, reason: str, origin: str = None) -> None:
        if channel is None:
            return
        fp = channel.peer_fp
        if self._state.get(fp, STATE_LOCAL) not in (STATE_CONTROLLING, STATE_REQUESTING):
            return
        rec = self._handoffs.get(fp)
        parked = bool(rec and rec.get("parked"))
        fraction = rec.get("fraction", 0.5) if rec else None
        hid = rec["id"] if rec else None
        combined = f"{origin}, {reason}" if origin else reason
        self._state[fp] = STATE_REVERTING
        self._handoffs.pop(fp, None)
        self._log_transition(fp, STATE_REVERTING, None, hid, combined)
        self._active_since = None
        if parked:
            self._restore_controller_cursor(fp, fraction)
        # Delegation failures are visible here: a stuck cursor is the exact
        # symptom the user reported, so it must not be swallowed (F2).
        self._restore_local_delegation()
        channel.send_event(KIND_ALL_KEYS_UP)
        self._state[fp] = STATE_LOCAL
        self._log_transition(fp, STATE_LOCAL, None, hid, combined)
        suffix = f" ({origin}, {reason})" if origin else f" ({reason})"
        self.on_status(f"Control returned from {channel.peer_name}{suffix}")

    def _revert_remote(self, channel: KvmChannel, reason: str, origin: str = None) -> None:
        if channel is None:
            return
        fp = channel.peer_fp
        if self._state.get(fp, STATE_LOCAL) not in (STATE_REMOTE, STATE_REMOTE_PREPARING):
            return
        rec = self._handoffs.get(fp)
        hid = rec["id"] if rec else None
        combined = f"{origin}, {reason}" if origin else reason
        self._state[fp] = STATE_REVERTING
        self._handoffs.pop(fp, None)
        self._log_transition(fp, STATE_REVERTING, None, hid, combined)
        self._active_since = None
        self._restore_local_delegation()
        self._release_all_keys()
        self._state[fp] = STATE_LOCAL
        self._log_transition(fp, STATE_LOCAL, None, hid, combined)
        suffix = f" ({origin}, {reason})" if origin else f" ({reason})"
        self.on_status(f"{channel.peer_name} released control{suffix}")

    def _restore_local_delegation(self, attempts: int = 3) -> bool:
        """Force the platform back to local delegation and show the cursor.

        A failed re-association must never be silent: it is exactly the
        "cursor never comes back" symptom. Retries briefly, then surfaces a
        visible error and restarts capture as the last resort (F2).
        """
        if self.platform is None:
            return True
        for i in range(attempts):
            try:
                if self.platform.set_delegation(STATE_LOCAL):
                    try:
                        self.platform.show_cursor()
                    except Exception:
                        pass
                    return True
            except Exception:
                pass
            time.sleep(0.05 * (i + 1))
        try:
            self.on_status(
                "KVM: failed to restore local input after control handback - "
                "restarting capture to recover",
                level="error",
            )
        except Exception:
            pass
        self._restart_capture()
        return False

    def _restart_capture(self) -> None:
        """Last-resort recovery: restart input capture so delegation is
        re-derived from a clean platform state."""
        if self.platform is None:
            return
        if self._platform_started:
            try:
                self.platform.stop()
            except Exception:
                pass
            self._platform_started = False
        try:
            self.platform.start(self)
            self._platform_started = True
        except Exception as exc:
            try:
                self.on_status(f"KVM: input capture restart failed: {exc}", level="error")
            except Exception:
                pass

    def _restore_controller_cursor(self, fp: str, fraction) -> None:
        """Warp back to my seam edge, inset past the jump zone so the
        next move must be a deliberate one to take control again."""
        if self.platform is None or fraction is None:
            return
        try:
            layout = self._my_layout()
            x, y = return_point(layout, self._my_side_for(fp), fraction)
            self.platform.warp_cursor(x, y)
        except Exception:
            pass

    def _sync_delegation(self, channel: KvmChannel = None) -> bool:
        """Derive the platform delegation from confirmed engine state.

        Returns False (never raises) when the platform could not apply the
        delegation; callers decide how to surface that.
        """
        fp = channel.peer_fp if channel is not None else None
        if fp is None:
            state = STATE_LOCAL
        else:
            st = self._state.get(fp, STATE_LOCAL)
            if st == STATE_CONTROLLING:
                rec = self._handoffs.get(fp)
                state = STATE_CONTROLLING if (rec and rec.get("stage") == "active") else STATE_LOCAL
            elif st == STATE_REMOTE:
                state = STATE_REMOTE
            else:
                state = STATE_LOCAL
        if self.platform is not None:
            try:
                return bool(self.platform.set_delegation(state))
            except Exception:
                return False
        return True

    def _safe_center(self) -> tuple[int, int]:
        layout = self._my_layout()
        return (layout.left() + layout.width() // 2, layout.top() + layout.height() // 2)

    # -- event handling (channel side) ----------------------------------------

    def handle_event(self, channel: KvmChannel, kind: int, body: bytes) -> None:
        # Every state/handoff mutation happens under the engine lock so the
        # watchdog, channel reader and platform tap threads can never
        # interleave a transition (F4).
        with self._lock:
            if self.relay:
                self.relay(channel.peer_fp, kind, body)
            if kind == KIND_PING:
                if self.control_active(channel):
                    channel.send_event(KIND_PONG)
                return
            if kind == KIND_PONG:
                return
            if kind == KIND_ERROR:
                code, message = decode_error(body)
                fp = channel.peer_fp
                self._blocked_edge[fp] = self._my_side_for(fp)
                self.on_status(f"KVM: {channel.peer_name} refused: {message or code}", level="error")
                self._revert_control(channel, "peer refused")
                return
            if kind == KIND_CONTROL_REQUEST:
                self._on_control_request(channel, body)
                return
            if kind == KIND_CONTROL_READY:
                self._on_control_ready(channel, body)
                return
            if kind == KIND_CONTROL_BEGIN:
                self._on_control_begin(channel, body)
                return
            if kind == KIND_CONTROL_ACTIVE:
                self._on_control_active(channel, body)
                return
            if kind == KIND_CONTROL_CANCEL:
                self._on_control_cancel(channel, body)
                return
            if kind == KIND_CONTROL_REVERT:
                self._on_control_revert(channel, body)
                return
            if kind == KIND_ALL_KEYS_UP:
                self._release_all_keys()
                return
            if kind == KIND_SCREEN_INFO:
                self._on_screen_info(channel, body)
                return
            if kind == KIND_EDGE_HIT:
                if self._state.get(channel.peer_fp) == STATE_CONTROLLING:
                    self._on_edge_hit(channel, body)
                return
            if self._state.get(channel.peer_fp) == STATE_REMOTE:
                self._inject_remote(kind, body)

    def _on_screen_info(self, channel: KvmChannel, body: bytes) -> None:
        try:
            monitors, primary, peer_side = decode_screen_info(body)
            layout = ScreenLayout.from_monitors(monitors, primary)
        except (ProtocolError, GeometryError):
            return
        fp = channel.peer_fp
        self._peer_layouts[fp] = layout
        self._peer_sides[fp] = peer_side
        my_side = self._my_side_for(fp)
        ok = bool(peer_side) and verify_topology(my_side, peer_side)
        changed = self._topology_ok.get(fp, True) != ok
        self._topology_ok[fp] = ok
        if fp in self._channels:
            self._link_status[fp] = LINK_READY
        if changed and not ok:
            self.on_status(
                f"KVM layout mismatch with {channel.peer_name}: "
                f"'{my_side}' vs their '{peer_side}' - fix in the menu",
                level="error",
            )
            rec = self._handoffs.get(fp)
            if rec is not None:
                try:
                    channel.send_event(KIND_CONTROL_CANCEL, encode_handoff_message(rec["id"], "topology"))
                except Exception:
                    pass
                if rec["role"] == "controller":
                    self._revert_control(channel, "layout mismatch")
                else:
                    self._revert_remote(channel, "layout mismatch")

    def _on_edge_hit(self, channel: KvmChannel, body: bytes) -> None:
        """Legacy informational hint: warp toward the shared seam."""
        try:
            direction, x, y = decode_edge_hit(body)
        except ProtocolError:
            return
        from .kvm_events import EDGE_BOTTOM, EDGE_LEFT, EDGE_RIGHT, EDGE_TOP

        side = {
            EDGE_LEFT: "left",
            EDGE_RIGHT: "right",
            EDGE_TOP: "top",
            EDGE_BOTTOM: "bottom",
        }.get(direction)
        if side is None:
            return
        my_side = self._my_side_for(channel.peer_fp)
        if side != opposite_side(my_side):
            return
        peer_layout = self._peer_layouts.get(channel.peer_fp)
        if peer_layout is None or self.platform is None:
            return
        fraction = seam_fraction(peer_layout, side, x, y)
        wx, wy = self._my_layout().edge_point(my_side, fraction)
        try:
            self.platform.warp_cursor(wx, wy)
        except Exception:
            pass

    def _inject_remote(self, kind: int, body: bytes) -> None:
        p = self.platform
        if p is None:
            return
        try:
            if kind == KIND_MOUSE_MOVE_REL:
                dx, dy = decode_rel(body)
                p.inject_move_rel(dx, dy)
            elif kind == KIND_MOUSE_MOVE_ABS:
                x, y = decode_abs(body)
                p.inject_move_abs(x, y)
            elif kind == KIND_MOUSE_BUTTON:
                button, down = decode_button(body)
                p.inject_button(button, down)
            elif kind == KIND_MOUSE_WHEEL:
                dy, dx = decode_wheel(body)
                p.inject_wheel(dy, dx)
            elif kind == KIND_KEY_DOWN:
                hid = decode_key(body)
                p.inject_key(hid, True)
                self.pressed.add(hid)
            elif kind == KIND_KEY_UP:
                hid = decode_key(body)
                p.inject_key(hid, False)
                self.pressed.discard(hid)
            elif kind == KIND_MODIFIERS:
                self._apply_modifiers(decode_modifiers(body))
        except Exception:
            pass  # a single bad inject (ctypes/Quartz hiccup) must not kill the channel

    def _apply_modifiers(self, mask: int) -> None:
        try:
            for hid in modifier_hids_for_mask(mask ^ self.modifier_mask):
                self.platform.inject_key(hid, bool(mask & self.modifier_mask_hid_bit(hid)))
            self.modifier_mask = mask
        except Exception:
            pass

    @staticmethod
    def modifier_mask_hid_bit(hid: int) -> int:
        from .kvm_keymap import modifier_mask_for_hid

        return modifier_mask_for_hid(hid)

    def _release_all_keys(self) -> None:
        if self.platform is None:
            return
        for hid in sorted(self.pressed):
            try:
                self.platform.inject_key(hid, False)
            except Exception:
                pass
        self.pressed.clear()
        if self.modifier_mask:
            for hid in modifier_hids_for_mask(self.modifier_mask):
                try:
                    self.platform.inject_key(hid, False)
                except Exception:
                    pass
            self.modifier_mask = 0

    def on_channel_closed(self, channel: KvmChannel) -> None:
        with self._lock:
            if self._channels.get(channel.peer_fp) is channel:
                del self._channels[channel.peer_fp]
            fp = channel.peer_fp
            state = self._state.pop(fp, None)
            self._handoffs.pop(fp, None)
            self._blocked_edge.pop(fp, None)
            self._denial_latch.pop(fp, None)
            self._last_sent_id.pop(fp, None)
            self._link_status.pop(fp, None)
            if state not in (None, STATE_LOCAL):
                self._restore_local_delegation(attempts=2)
                self._release_all_keys()
                self._log_transition(fp, STATE_LOCAL, None, None, "channel closed")
                self.on_status(f"KVM channel with {channel.peer_name} lost - control returned")
            self._peer_layouts.pop(fp, None)
            self._peer_sides.pop(fp, None)
            self._topology_ok.pop(fp, None)
            self._active_since = None

    # -- helpers --------------------------------------------------------------

    def _my_side_for(self, fp: str) -> str:
        peer = self.store.get_peer(fp)
        return peer.get("kvm_side", "right") if peer else "right"

    def _my_layout(self) -> ScreenLayout:
        if self.platform is None:
            raise KvmError("no platform")
        return self.platform.screen_layout()

    def _link_ready(self, fp: str) -> bool:
        return fp in self._channels and self._link_status.get(fp) == LINK_READY

    def _active_channel(self) -> KvmChannel | None:
        for fp, state in self._state.items():
            if state != STATE_LOCAL:
                return self._channels.get(fp)
        return None

    def _cursor_side(self, x: int, y: int, zone: int = JUMP_ZONE) -> str | None:
        try:
            return in_jump_zone(self._my_layout(), x, y, zone)
        except KvmError:
            return None

    def _channel_for(self, side: str | None) -> KvmChannel | None:
        if side is None:
            return self._active_channel()
        for fp, ch in self._channels.items():
            if self._my_side_for(fp) == side:
                return ch
        return None
