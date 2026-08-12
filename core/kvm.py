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
MAX_FRAME = 1 << 20
COUNTER_LIMIT = 1 << 31

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
        remote      suppress and drop input except for the escape chord

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

    def invalidate_layout(self) -> None:
        """Drop any cached screen layout (display-change signal). Default no-op."""

    def cursor_position(self) -> tuple[int, int]:
        raise NotImplementedError

    def warp_cursor(self, x: int, y: int) -> None:
        raise NotImplementedError

    def hide_cursor(self) -> None:
        raise NotImplementedError

    def show_cursor(self) -> None:
        raise NotImplementedError

    def set_delegation(self, state: str) -> None:
        raise NotImplementedError

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

    def __init__(self, conn, peer_fp, peer_name, key, nonce8_out, nonce8_in, engine, role):
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
        self._outbound = 0
        self._inbound = 0
        self.last_inbound = time.monotonic()
        self._last_ping = 0.0

    def send_event(self, kind: int, body: bytes = b"") -> None:
        plain = bytes([kind]) + body
        with self._lock:
            if self.closed:
                return
            if self._outbound >= COUNTER_LIMIT:
                self.closed = True
                return
            nonce = crypto.chunk_nonce(self.nonce8_out, self._outbound)
            ct = crypto.encrypt_with_nonce(self.key, nonce, plain)
            try:
                self.conn.sendall(struct.pack(">I", len(ct)) + ct)
                self._outbound += 1
            except OSError:
                self.closed = True

    def run(self) -> None:
        """Blocking binary frame-read loop; runs in a dedicated thread or in
        the server connection thread depending on which side initiated."""
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
            self._engine.handle_event(self, kind, body)
        self.engine_remove()

    def engine_remove(self) -> None:
        self._engine.on_channel_closed(self)

    def close(self) -> None:
        self.closed = True
        try:
            self.conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.conn.close()
        except OSError:
            pass


class KVMEngine:
    """Drives input sharing with paired, discovered peers."""

    def __init__(self, store, discovery, platform=None, on_status=None, relay=None):
        self.store = store
        self.discovery = discovery
        self.platform = platform
        self.relay = relay  # optional: (fp, kind, body) echo back for tests
        self.on_status = on_status or (lambda s: None)
        self.enabled = bool(store.kvm_enabled)
        self.stall_timeout = STALL_TIMEOUT
        self.keepalive_interval = KEEPALIVE_INTERVAL
        self.handoff_timeout = HANDOFF_TIMEOUT
        self._channels: dict[str, KvmChannel] = {}
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
        self.pressed: set[int] = set()  # HID keys I injected (remote side)
        self.modifier_mask = 0  # modifiers I injected (remote side)
        self._local_mask = 0  # modifiers physically held here (controller side)
        self._local_pressed: set[int] = set()  # non-modifier HID keys held here

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
                    f"Mouse & keyboard sharing needs permission: {detail or exc}"
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
        try:
            self._set_delegation_local()
        except Exception:
            pass
        if self.platform is not None:
            try:
                self.platform.show_cursor()
            except Exception:
                pass
        self._release_all_keys()
        self._chord_armed = True

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
        fp = header.get("fp", "")
        peer = self.store.get_peer(fp) if validate_open(header) else None
        if peer is None or not self.enabled:
            try:
                send_frame(conn, {"type": "error", "code": "kvm_disabled"})
            except OSError:
                pass
            return
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
            my_nonce8 = os.urandom(crypto.CHUNK_NONCE_PREFIX_BYTES)
            peer_nonce8 = base64.b64decode(header["nonce8"])
            key = kvm_channel_key(
                peer["trust_key"], KVM_PROTOCOL_VERSION, fp, self.store.fingerprint(), peer_nonce8, my_nonce8
            )
            ch = KvmChannel(conn, fp, peer.get("name", fp[:8]), key, my_nonce8, peer_nonce8, self, "responder")
            self._channels[fp] = ch
            self._link_status[fp] = LINK_LINKED
        try:
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
        except OSError:
            self.on_channel_closed(ch)
            return
        self._send_screen_info(ch)
        self.on_status(f"KVM linked with {ch.peer_name}")
        ch.run()

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
            try:
                conn = socket.create_connection((peer.host, peer.port), timeout=10)
                conn.settimeout(15)
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
                for fp, rec in list(self._handoffs.items()):
                    deadline = rec.get("deadline")
                    if deadline and now >= deadline:
                        self._expire_handoff(fp, rec)

    def _expire_handoff(self, fp: str, rec: dict) -> None:
        ch = self._channels.get(fp)
        if ch is not None and not ch.closed:
            try:
                ch.send_event(KIND_CONTROL_CANCEL, encode_handoff_message(rec["id"], "timeout"))
            except Exception:
                pass
        if ch is not None and not ch.closed:
            if rec["role"] == "controller":
                self._blocked_edge[fp] = self._my_side_for(fp)
                self._revert_control(ch, "handoff timeout")
            else:
                self._revert_remote(ch, "handoff timeout")
            return
        # The channel is already gone: nothing can be notified, but the
        # local control state must not linger. Otherwise the watchdog
        # re-expires this same handoff every 200 ms and the state stays
        # stuck in requesting/remote_preparing.
        self._state.pop(fp, None)
        self._handoffs.pop(fp, None)
        self._blocked_edge.pop(fp, None)
        self._last_sent_id.pop(fp, None)
        if rec.get("role") == "controller" and rec.get("parked"):
            self._restore_controller_cursor(fp, rec.get("fraction", 0.5))
        try:
            self._set_delegation_local()
        except Exception:
            pass
        if self.platform is not None:
            try:
                self.platform.show_cursor()
            except Exception:
                pass
        self._release_all_keys()
        self.on_status("KVM handoff timed out - control returned to local")

    # -- platform callbacks (capture side) ------------------------------------

    def on_local_mouse(self, dx: int, dy: int, x: int, y: int) -> None:
        if not self.enabled or self.platform is None:
            return
        cursor_side = self._cursor_side(x, y)
        # Clear edge blocks once the pointer leaves the blocked edge
        # (and unblock the target's denial latch for retries).
        for fp in list(self._blocked_edge):
            if cursor_side is None or cursor_side != self._blocked_edge[fp]:
                self._blocked_edge.pop(fp, None)
                self._send_edge_left_cancel(fp)
        channel = self._active_channel()
        if channel is not None:
            self._on_active_local_mouse(channel, dx, dy, x, y, cursor_side)
            return
        if cursor_side is None:
            return
        channel = self._channel_for(cursor_side)
        if channel is None:
            return
        fp = channel.peer_fp
        if cursor_side != self._my_side_for(fp):
            return
        if fp in self._blocked_edge:
            return
        if not self._link_ready(fp):
            return
        peer_layout = self._peer_layouts.get(fp)
        if peer_layout is None:
            return
        fraction = seam_fraction(self._my_layout(), cursor_side, x, y)
        tx, ty = entry_point(peer_layout, cursor_side, fraction)
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

    def on_local_button(self, button: int, down: bool) -> None:
        channel = self._active_channel()
        if channel is None:
            return
        fp = channel.peer_fp
        rec = self._handoffs.get(fp)
        if self._state.get(fp) != STATE_CONTROLLING or rec is None or rec.get("stage") != "active":
            return
        channel.send_event(KIND_MOUSE_BUTTON, encode_button(button, down))

    def on_local_wheel(self, dy: int, dx: int) -> None:
        channel = self._active_channel()
        if channel is None:
            return
        fp = channel.peer_fp
        rec = self._handoffs.get(fp)
        if self._state.get(fp) != STATE_CONTROLLING or rec is None or rec.get("stage") != "active":
            return
        channel.send_event(KIND_MOUSE_WHEEL, encode_wheel(dy, dx))

    def on_local_key(self, hid: int, down: bool) -> None:
        if not self.enabled or self.platform is None:
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
        self._revert_remote(channel, "peer edge")

    def on_escape_chord(self) -> None:
        """Forced local release (Ctrl+Alt+Space / Ctrl+Option+Space)."""
        if not self.enabled:
            return
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
                self._revert_remote(channel, "escape chord")
            else:
                self._revert_control(channel, "escape chord")

    def on_display_change(self) -> None:
        if not self.enabled or self.platform is None:
            return
        try:
            self.platform.invalidate_layout()
        except Exception:
            pass
        for ch in list(self._channels.values()):
            self._send_screen_info(ch)

    # -- handoff: controller side ---------------------------------------------

    def _next_handoff_id(self) -> int:
        self._handoff_seq += 1
        return self._handoff_seq

    def _request_control(self, channel: KvmChannel, tx: int, ty: int, fraction: float) -> None:
        fp = channel.peer_fp
        if not self._topology_ok.get(fp, True):
            self.on_status(f"KVM with {channel.peer_name}: screen layout mismatch")
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
        self.on_status(f"Controlling {channel.peer_name}")

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
        try:
            self._sync_delegation(channel)
        except Exception as exc:
            self._fail_controller(channel, rec, "platform", f"platform failure: {exc}")
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
        # Suppress local input only now: the controller confirmed.
        try:
            self._sync_delegation(channel)
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
        state = self._state.get(fp, STATE_LOCAL)
        if state != STATE_LOCAL:
            # One active control at a time. Simultaneous takeover: the
            # higher fingerprint wins (deterministic tiebreak). The
            # loser withdraws its own request (a withdrawal must not be
            # mistaken for a refusal: the winner's request stays alive).
            if state == STATE_REQUESTING and self.store.fingerprint() < fp:
                self._cancel_outbound(fp, "withdrawn")
            else:
                self._refuse(channel, hid, "busy")
                return
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
        if self.platform is None:
            self._refuse(channel, hid, "unavailable")
            return
        if channel.closed:
            return
        if any(s != STATE_LOCAL for s in self._state.values()):
            self._refuse(channel, hid, "busy")
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
        channel.send_event(KIND_CONTROL_READY, encode_handoff_id(hid))

    def _refuse(self, channel: KvmChannel, hid: int, reason: str, message: str = "") -> None:
        try:
            channel.send_event(KIND_CONTROL_CANCEL, encode_handoff_message(hid, reason))
        except Exception:
            pass
        if message:
            self.on_status(f"KVM: {message}")

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
            return  # stale
        state = self._state.get(fp, STATE_LOCAL)
        reason = reason or "peer"
        if state in (STATE_REMOTE, STATE_REMOTE_PREPARING):
            self._revert_remote(channel, f"{reason}")
        else:
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

    def _revert_control(self, channel: KvmChannel, reason: str) -> None:
        if channel is None:
            return
        fp = channel.peer_fp
        if self._state.get(fp, STATE_LOCAL) not in (STATE_CONTROLLING, STATE_REQUESTING):
            return
        rec = self._handoffs.get(fp)
        parked = bool(rec and rec.get("parked"))
        fraction = rec.get("fraction", 0.5) if rec else None
        self._state[fp] = STATE_REVERTING
        self._handoffs.pop(fp, None)
        if parked:
            self._restore_controller_cursor(fp, fraction)
        try:
            self._sync_delegation(channel)
        except Exception:
            pass
        if self.platform is not None:
            try:
                self.platform.show_cursor()
            except Exception:
                pass
        channel.send_event(KIND_ALL_KEYS_UP)
        self._state[fp] = STATE_LOCAL
        self.on_status(f"Control returned from {channel.peer_name} ({reason})")

    def _revert_remote(self, channel: KvmChannel, reason: str) -> None:
        if channel is None:
            return
        fp = channel.peer_fp
        if self._state.get(fp, STATE_LOCAL) not in (STATE_REMOTE, STATE_REMOTE_PREPARING):
            return
        self._state[fp] = STATE_REVERTING
        self._handoffs.pop(fp, None)
        try:
            self._sync_delegation(channel)
        except Exception:
            pass
        if self.platform is not None:
            try:
                self.platform.show_cursor()
            except Exception:
                pass
        self._release_all_keys()
        self._state[fp] = STATE_LOCAL
        self.on_status(f"{channel.peer_name} released control ({reason})")

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

    def _sync_delegation(self, channel: KvmChannel = None) -> None:
        """Derive the platform delegation from confirmed engine state.

        Raises on platform failure so callers can switch to a safe revert.
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
            self.platform.set_delegation(state)

    def _set_delegation_local(self) -> None:
        if self.platform is not None:
            self.platform.set_delegation(STATE_LOCAL)

    def _safe_center(self) -> tuple[int, int]:
        layout = self._my_layout()
        return (layout.left() + layout.width() // 2, layout.top() + layout.height() // 2)

    # -- event handling (channel side) ----------------------------------------

    def handle_event(self, channel: KvmChannel, kind: int, body: bytes) -> None:
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
            self.on_status(f"KVM: {channel.peer_name} refused: {message or code}")
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
                f"'{my_side}' vs their '{peer_side}' - fix in the menu"
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
        except ProtocolError:
            pass

    def _apply_modifiers(self, mask: int) -> None:
        for hid in modifier_hids_for_mask(mask ^ self.modifier_mask):
            self.platform.inject_key(hid, bool(mask & self.modifier_mask_hid_bit(hid)))
        self.modifier_mask = mask

    @staticmethod
    def modifier_mask_hid_bit(hid: int) -> int:
        from .kvm_keymap import modifier_mask_for_hid

        return modifier_mask_for_hid(hid)

    def _release_all_keys(self) -> None:
        if self.platform is None:
            return
        for hid in sorted(self.pressed):
            self.platform.inject_key(hid, False)
        self.pressed.clear()
        if self.modifier_mask:
            for hid in modifier_hids_for_mask(self.modifier_mask):
                self.platform.inject_key(hid, False)
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
            try:
                self._set_delegation_local()
            except Exception:
                pass
            if self.platform is not None:
                try:
                    self.platform.show_cursor()
                except Exception:
                    pass
            self._release_all_keys()
            self.on_status(f"KVM channel with {channel.peer_name} lost - control returned")
        self._peer_layouts.pop(fp, None)
        self._peer_sides.pop(fp, None)
        self._topology_ok.pop(fp, None)

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

    def _cursor_side(self, x: int, y: int) -> str | None:
        try:
            return in_jump_zone(self._my_layout(), x, y)
        except KvmError:
            return None

    def _channel_for(self, side: str | None) -> KvmChannel | None:
        if side is None:
            return self._active_channel()
        for fp, ch in self._channels.items():
            if self._my_side_for(fp) == side:
                return ch
        return None
