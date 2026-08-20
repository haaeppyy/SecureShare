import pytest
import socket

from core.kvm_events import (
    EDGE_BOTTOM,
    EDGE_LEFT,
    EDGE_RIGHT,
    KIND_CONTROL_ACTIVE,
    KIND_CONTROL_BEGIN,
    KIND_CONTROL_CANCEL,
    KIND_CONTROL_READY,
    KIND_CONTROL_REQUEST,
    KIND_CONTROL_REVERT,
    KIND_ERROR,
    KIND_KEY_DOWN,
    KIND_MODIFIERS,
    KIND_MOUSE_BUTTON,
    KIND_MOUSE_MOVE_ABS,
    KIND_MOUSE_MOVE_REL,
    KIND_MOUSE_WHEEL,
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
    encode_abs,
    encode_button,
    encode_control_request,
    encode_edge_hit,
    encode_error,
    encode_handoff_id,
    encode_handoff_message,
    encode_key,
    encode_modifiers,
    encode_rel,
    encode_screen_info,
    encode_wheel,
    pack_event,
    unpack_event,
)
from core.transfer import ProtocolError


def test_roundtrip_rel():
    body = encode_rel(-123, 45)
    assert decode_rel(body) == (-123, 45)
    assert len(body) == 4


def test_roundtrip_abs():
    body = encode_abs(12345, -678)
    assert decode_abs(body) == (12345, -678)
    assert len(body) == 8


def test_roundtrip_button():
    assert decode_button(encode_button(3, True)) == (3, True)
    assert decode_button(encode_button(1, False)) == (1, False)


def test_button_rejects_bad_state():
    with pytest.raises(ProtocolError):
        decode_button(b"\x00\x02")


def test_roundtrip_wheel():
    body = encode_wheel(240, -120)
    assert decode_wheel(body) == (240, -120)
    assert len(body) == 8


def test_roundtrip_key():
    body = encode_key(0x2C)
    assert decode_key(body) == 0x2C
    assert len(body) == 2


def test_roundtrip_modifiers():
    body = encode_modifiers(0b10101)
    assert decode_modifiers(body) == 0b10101
    assert len(body) == 2


def test_roundtrip_screen_info():
    monitors = [{"x": 0, "y": 0, "w": 1440, "h": 900, "scale": 2.0}]
    body = encode_screen_info(monitors, 0, "right")
    mons, primary, side = decode_screen_info(body)
    assert mons == monitors
    assert primary == 0
    assert side == "right"


def test_screen_info_rejects_empty():
    with pytest.raises(ProtocolError):
        decode_screen_info(b"{}")
    with pytest.raises(ProtocolError):
        decode_screen_info(b"not json")


def test_roundtrip_edge_hit():
    body = encode_edge_hit(EDGE_LEFT, 100, 200)
    assert decode_edge_hit(body) == (EDGE_LEFT, 100, 200)
    assert len(body) == 9


def test_roundtrip_error():
    body = encode_error(1, "layout mismatch")
    assert decode_error(body) == (1, "layout mismatch")


def test_roundtrip_control_request():
    body = encode_control_request(7, -1600, 540, 0b101)
    assert decode_control_request(body) == (7, -1600, 540, 0b101)
    assert len(body) == 14


def test_control_request_rejects_bad_length():
    with pytest.raises(ProtocolError):
        decode_control_request(b"\x00" * 13)


def test_roundtrip_handoff_id():
    body = encode_handoff_id(0xDEADBEEF)
    assert decode_handoff_id(body) == 0xDEADBEEF
    assert len(body) == 4


def test_handoff_id_rejects_bad_length():
    with pytest.raises(ProtocolError):
        decode_handoff_id(b"\x00" * 5)


def test_roundtrip_handoff_message():
    body = encode_handoff_message(42, "peer-edge")
    assert decode_handoff_message(body) == (42, "peer-edge")


def test_handoff_message_rejects_bad_length():
    with pytest.raises(ProtocolError):
        decode_handoff_message(b"\x00" * 3)


def test_handoff_kinds_in_order():
    assert KIND_CONTROL_REQUEST == 0x10
    assert KIND_CONTROL_READY == 0x11
    assert KIND_CONTROL_BEGIN == 0x12
    assert KIND_CONTROL_ACTIVE == 0x13
    assert KIND_CONTROL_CANCEL == 0x14
    assert KIND_CONTROL_REVERT == 0x0B


def test_pack_unpack_roundtrip():
    kind, body = unpack_event(pack_event(KIND_KEY_DOWN, encode_key(0x04)))
    assert kind == KIND_KEY_DOWN
    assert decode_key(body) == 0x04


def test_unpack_rejects_empty():
    with pytest.raises(ProtocolError):
        unpack_event(b"")


def test_pack_rejects_bad_kind():
    with pytest.raises(ValueError):
        pack_event(0x100)


def test_all_kinds_mapped():
    from core import kvm_events as ke

    for kind in ke.KINDS:
        assert pack_event(kind) == bytes([kind])


def test_kvm_channels_disable_nagle_buffering():
    from core.kvm import _set_low_latency

    class Socket:
        def __init__(self):
            self.options = []

        def setsockopt(self, level, option, value):
            self.options.append((level, option, value))

    conn = Socket()
    _set_low_latency(conn)
    assert conn.options == [(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)]


pytestmark = pytest.mark.unit
