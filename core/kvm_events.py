"""Compact binary codec for keyboard/mouse control events.

Wire layout of one event frame (inside the KVM channel):

    [4-byte BE length][AES-GCM ciphertext]

where the plaintext is:

    [1-byte kind][body]

Bodies are struct-packed (big-endian) per the kind table. No JSON, no
base64: mouse events arrive at hundreds of hertz and the framing must be
cheap on both ends. The crypto (nonces, counters) lives in kvm.py.
"""

import json
import struct

from .transfer import ProtocolError

KIND_MOUSE_MOVE_REL = 0x01
KIND_MOUSE_MOVE_ABS = 0x02
KIND_MOUSE_BUTTON = 0x03
KIND_MOUSE_WHEEL = 0x04
KIND_KEY_DOWN = 0x05
KIND_KEY_UP = 0x06
KIND_MODIFIERS = 0x07
KIND_SCREEN_INFO = 0x08
KIND_EDGE_HIT = 0x09
KIND_TAKE_CONTROL = 0x0A  # legacy, deprecated by CONTROL_REQUEST
KIND_CONTROL_REVERT = 0x0B
KIND_ALL_KEYS_UP = 0x0C
KIND_ERROR = 0x0D
KIND_PING = 0x0E
KIND_PONG = 0x0F
KIND_CONTROL_REQUEST = 0x10
KIND_CONTROL_READY = 0x11
KIND_CONTROL_BEGIN = 0x12
KIND_CONTROL_ACTIVE = 0x13
KIND_CONTROL_CANCEL = 0x14

KINDS = {
    KIND_MOUSE_MOVE_REL: "mouse_move_rel",
    KIND_MOUSE_MOVE_ABS: "mouse_move_abs",
    KIND_MOUSE_BUTTON: "mouse_button",
    KIND_MOUSE_WHEEL: "mouse_wheel",
    KIND_KEY_DOWN: "key_down",
    KIND_KEY_UP: "key_up",
    KIND_MODIFIERS: "modifiers",
    KIND_SCREEN_INFO: "screen_info",
    KIND_EDGE_HIT: "edge_hit",
    KIND_TAKE_CONTROL: "take_control",
    KIND_CONTROL_REVERT: "control_revert",
    KIND_ALL_KEYS_UP: "all_keys_up",
    KIND_ERROR: "error",
    KIND_PING: "ping",
    KIND_PONG: "pong",
    KIND_CONTROL_REQUEST: "control_request",
    KIND_CONTROL_READY: "control_ready",
    KIND_CONTROL_BEGIN: "control_begin",
    KIND_CONTROL_ACTIVE: "control_active",
    KIND_CONTROL_CANCEL: "control_cancel",
}

# Mouse buttons, canonical ids shared by both platforms.
BUTTON_LEFT = 0
BUTTON_RIGHT = 1
BUTTON_MIDDLE = 2
BUTTON_X1 = 3
BUTTON_X2 = 4

# Edge directions (controller-relative seam sides).
EDGE_LEFT = 0
EDGE_RIGHT = 1
EDGE_TOP = 2
EDGE_BOTTOM = 3

# Error codes carried in KIND_ERROR bodies.
ERR_DENIED = 0
ERR_TOPOLOGY = 1
ERR_PROTOCOL = 2
ERR_BUSY = 3
ERR_UNSUPPORTED = 4


def pack_event(kind: int, body: bytes = b"") -> bytes:
    """Prepend the kind byte to a body."""
    if not 0 <= kind <= 0xFF:
        raise ValueError(f"kind {kind} out of range")
    return bytes([kind]) + body


def unpack_event(data: bytes) -> tuple[int, bytes]:
    """Split a plaintext into (kind, body)."""
    if not data:
        raise ProtocolError("empty event frame")
    return data[0], data[1:]


def encode_rel(dx: int, dy: int) -> bytes:
    return struct.pack(">hh", dx, dy)


def decode_rel(body: bytes) -> tuple[int, int]:
    if len(body) != 4:
        raise ProtocolError("bad rel body")
    return struct.unpack(">hh", body)


def encode_abs(x: int, y: int) -> bytes:
    return struct.pack(">ii", x, y)


def decode_abs(body: bytes) -> tuple[int, int]:
    if len(body) != 8:
        raise ProtocolError("bad abs body")
    return struct.unpack(">ii", body)


def encode_button(button: int, down: bool) -> bytes:
    return struct.pack(">BB", button, 1 if down else 0)


def decode_button(body: bytes) -> tuple[int, bool]:
    if len(body) != 2:
        raise ProtocolError("bad button body")
    button, down = struct.unpack(">BB", body)
    if down not in (0, 1):
        raise ProtocolError("bad button state")
    return button, bool(down)


def encode_wheel(dy: int, dx: int) -> bytes:
    return struct.pack(">ii", dy, dx)


def decode_wheel(body: bytes) -> tuple[int, int]:
    if len(body) != 8:
        raise ProtocolError("bad wheel body")
    return struct.unpack(">ii", body)


def encode_key(hid: int) -> bytes:
    return struct.pack(">H", hid)


def decode_key(body: bytes) -> int:
    if len(body) != 2:
        raise ProtocolError("bad key body")
    (hid,) = struct.unpack(">H", body)
    return hid


def encode_modifiers(mask: int) -> bytes:
    return struct.pack(">H", mask)


def decode_modifiers(body: bytes) -> int:
    if len(body) != 2:
        raise ProtocolError("bad modifiers body")
    (mask,) = struct.unpack(">H", body)
    return mask


def encode_screen_info(monitors: list, primary: int, side: str = "") -> bytes:
    payload = {"monitors": monitors, "primary": primary}
    if side:
        payload["side"] = side
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def decode_screen_info(body: bytes) -> tuple[list, int, str]:
    try:
        payload = json.loads(body.decode("utf-8"))
        monitors = payload["monitors"]
        primary = int(payload.get("primary", 0))
        side = str(payload.get("side", ""))
    except (ValueError, KeyError, TypeError):
        raise ProtocolError("bad screen_info body")
    if not isinstance(monitors, list) or not monitors:
        raise ProtocolError("empty screen_info body")
    return monitors, primary, side


def encode_edge_hit(direction: int, x: int, y: int) -> bytes:
    return struct.pack(">Bii", direction, x, y)


def decode_edge_hit(body: bytes) -> tuple[int, int, int]:
    if len(body) != 9:
        raise ProtocolError("bad edge_hit body")
    direction, x, y = struct.unpack(">Bii", body)
    return direction, x, y


def encode_error(code: int, message: str = "") -> bytes:
    return struct.pack(">B", code) + message.encode("utf-8")


def decode_error(body: bytes) -> tuple[int, str]:
    if not body:
        raise ProtocolError("bad error body")
    return body[0], body[1:].decode("utf-8", "replace")


# -- acknowledged handoff (CONTROL_*) codecs ---------------------------------
#
# Bodies carry a monotonically generated handoff_id so stale or duplicated
# control messages can be ignored by both peers. CONTROL_REVERT and
# CONTROL_CANCEL append a UTF-8 reason string (peer-edge, escape, denied,
# topology, busy, timeout, edge-left, platform, disabled, channel-lost...).


def encode_control_request(handoff_id: int, entry_x: int, entry_y: int, modifier_mask: int) -> bytes:
    return struct.pack(">IiiH", handoff_id, entry_x, entry_y, modifier_mask)


def decode_control_request(body: bytes) -> tuple[int, int, int, int]:
    if len(body) != 14:
        raise ProtocolError("bad control_request body")
    return struct.unpack(">IiiH", body)


def encode_handoff_id(handoff_id: int) -> bytes:
    return struct.pack(">I", handoff_id)


def decode_handoff_id(body: bytes) -> int:
    if len(body) != 4:
        raise ProtocolError("bad handoff_id body")
    (handoff_id,) = struct.unpack(">I", body)
    return handoff_id


def encode_handoff_message(handoff_id: int, reason: str = "") -> bytes:
    return struct.pack(">I", handoff_id) + reason.encode("utf-8")


def decode_handoff_message(body: bytes) -> tuple[int, str]:
    if len(body) < 4:
        raise ProtocolError("bad control message body")
    (handoff_id,) = struct.unpack(">I", body[:4])
    return handoff_id, body[4:].decode("utf-8", "replace")
