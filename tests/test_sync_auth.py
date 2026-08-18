"""Sync channel authentication and replay protection tests.

Covers: spoofed opens must not displace a valid channel, replayed /
reordered / tampered frames are rejected, and the handshake + reconnect
paths work end to end on loopback.
"""

import base64
import os
import socket
import threading
import time

import pytest

from core import crypto, sync
from core.transfer import recv_frame, send_frame

from conftest import node_pair  # noqa: F401
from test_sync import FakeChannel, FakeClipboard, StubDiscovery, StubStore, make_engine, make_frame  # noqa: F401


# -- unit-level frame handling ------------------------------------------------

def test_duplicate_frame_is_dropped():
    fake = FakeClipboard()
    engine, channel = make_engine(fake)
    engine.enabled = True
    engine._note_seen()
    frame = make_frame(channel, "clipboard_text", b"hello")
    engine.handle_frame(channel, frame)
    assert fake.text == "hello"
    engine.handle_frame(channel, frame)  # exact replay
    assert fake.text == "hello"
    assert channel.closed is False, "duplicate must be dropped, not fatal"


def test_stale_frame_is_dropped():
    fake = FakeClipboard()
    engine, channel = make_engine(fake)
    engine.enabled = True
    engine.handle_frame(channel, make_frame(channel, "clipboard_text", b"one"))
    engine.handle_frame(channel, make_frame(channel, "clipboard_text", b"two"))
    engine.handle_frame(channel, make_frame(channel, "clipboard_text", b"two", seq=1))  # stale
    assert fake.text == "two"


def test_out_of_order_frame_closes_channel():
    fake = FakeClipboard()
    engine, channel = make_engine(fake)
    engine.enabled = True
    frame = make_frame(channel, "clipboard_text", b"jump", seq=5)  # skips 0
    engine.handle_frame(channel, frame)
    assert fake.text is None, "gap frame must not be applied"
    assert channel.closed, "a sequence gap must terminate the channel"


def test_wrong_fingerprint_frame_is_dropped():
    fake = FakeClipboard()
    engine, channel = make_engine(fake)
    engine.enabled = True
    frame = make_frame(channel, "clipboard_text", b"x")
    frame["fp"] = "attacker-fp"  # not the channel peer
    engine.handle_frame(channel, frame)
    assert fake.text is None


def test_tampered_payload_closes_channel():
    fake = FakeClipboard()
    engine, channel = make_engine(fake)
    engine.enabled = True
    frame = make_frame(channel, "clipboard_text", b"good")
    aad = sync._frame_aad("clipboard_text", sync.SYNC_PROTOCOL_VERSION, channel.peer_fp, "fp-a", 0)
    frame["payload"] = base64.b64encode(crypto.encrypt(b"x" * 32, b"evil", aad)).decode("ascii")
    engine.handle_frame(channel, frame)
    assert fake.text is None, "frame sealed with the wrong key must not apply"
    assert channel.closed, "authentication failure must close the channel"


def test_wrong_protocol_version_is_dropped():
    fake = FakeClipboard()
    engine, channel = make_engine(fake)
    engine.enabled = True
    frame = make_frame(channel, "clipboard_text", b"x")
    frame["v"] = 1
    engine.handle_frame(channel, frame)
    assert fake.text is None


def test_outgoing_frames_carry_monotonic_sequences():
    fake = FakeClipboard()
    engine, channel = make_engine(fake)
    engine.enabled = True
    seqs = []
    real_send = channel.send
    def capture(kind, data):
        seqs.append(channel._seq_out)
        real_send(kind, data)
    channel.send = capture
    for _ in range(3):
        engine._watch_once()
        fake.text = "x"
        engine._watch_once()
        fake.text = "y"
        engine._watch_once()
    assert len(seqs) >= 3
    assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs)


# -- handshake / integration (real sockets on loopback) -----------------------

def _wait(predicate, timeout=20.0, interval=0.1):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def _establish_sync(node_pair):
    """Pair the nodes, enable sync on both, and drive the handshake until
    channels exist on both sides."""
    node_pair.pair()
    a, b = node_pair.a, node_pair.b
    a.sync.set_enabled(True)
    b.sync.set_enabled(True)
    fp_a, fp_b = a.store.fingerprint(), b.store.fingerprint()

    def both_up():
        a.sync.ensure_connections()
        b.sync.ensure_connections()
        return fp_b in a.sync._channels and fp_a in b.sync._channels

    assert _wait(both_up), "sync handshake did not establish"
    return a, b, fp_a, fp_b


def test_handshake_establishes_channel_and_delivers(node_pair):
    a, b, fp_a, fp_b = _establish_sync(node_pair)
    collected = []
    b.sync.relay = lambda fp, kind, data: collected.append((fp, kind, data))
    a.sync._channels[fp_b].send("clipboard_text", b"round-trip")
    assert _wait(lambda: collected, timeout=5), "message must reach B over the new channel"
    assert collected[0][0] == fp_a
    assert collected[0][2] == b"round-trip"


def test_spoofed_open_keeps_current_channel(node_pair):
    a, b, fp_a, fp_b = _establish_sync(node_pair)
    old_channel = b.sync._channels[fp_a]
    collected = []
    b.sync.relay = lambda fp, kind, data: collected.append((fp, kind, data))

    # Attacker connects to B claiming A's fingerprint, then vanishes
    # without completing the authenticated hello.
    peer_b = node_pair.test_peer(node_pair.a)
    sock = socket.create_connection((peer_b.host, peer_b.port), timeout=5)
    send_frame(
        sock,
        {
            "type": "sync_open",
            "v": sync.SYNC_PROTOCOL_VERSION,
            "fp": fp_a,
            "nonce8": base64.b64encode(os.urandom(8)).decode("ascii"),
        },
    )
    sock.close()

    def spoof_handled():
        b.sync.ensure_connections()
        return b.sync._channels.get(fp_a) is old_channel

    assert _wait(spoof_handled, timeout=10), "spoofed open must not displace the channel"
    a.sync._channels[fp_b].send("clipboard_text", b"still-alive")
    assert _wait(lambda: collected, timeout=5), "surviving channel must still deliver"


def test_spoofed_open_with_plaintext_hello_rejected(node_pair):
    a, b, fp_a, fp_b = _establish_sync(node_pair)
    old_channel = b.sync._channels[fp_a]
    peer_b = node_pair.test_peer(node_pair.a)
    sock = socket.create_connection((peer_b.host, peer_b.port), timeout=5)
    send_frame(
        sock,
        {
            "type": "sync_open",
            "v": sync.SYNC_PROTOCOL_VERSION,
            "fp": fp_a,
            "nonce8": base64.b64encode(os.urandom(8)).decode("ascii"),
        },
    )
    raw = recv_frame(sock)  # sync_ack
    ack = __import__("json").loads(raw.decode("utf-8"))
    assert ack["type"] == "sync_ack"
    # Attacker answers with an unsealed hello: key confirmation fails.
    send_frame(
        sock,
        {
            "type": "sync_hello",
            "v": sync.SYNC_PROTOCOL_VERSION,
            "fp": fp_a,
            "peer_fp": ack["fp"],
            "seq": 0,
            "payload": "",
        },
    )
    reply = __import__("json").loads(recv_frame(sock).decode("utf-8"))
    assert reply["type"] == "error", "responder must reject the plaintext hello"
    sock.close()
    assert _wait(lambda: b.sync._channels.get(fp_a) is old_channel, timeout=10)


def test_reconnect_replaces_channel_after_auth(node_pair):
    a, b, fp_a, fp_b = _establish_sync(node_pair)
    # Kill A's channel; the connect loop must re-establish on the next pass.
    a.sync._channels[fp_b].close()
    assert _wait(lambda: fp_b not in a.sync._channels, timeout=5)
    collected = []
    b.sync.relay = lambda fp, kind, data: collected.append((fp, kind, data))
    assert _wait(lambda: fp_b in a.sync._channels, timeout=15), "channel must reconnect"
    a.sync._channels[fp_b].send("clipboard_text", b"after-reconnect")
    assert _wait(lambda: collected, timeout=5)
    assert collected[0][2] == b"after-reconnect"


def test_old_version_open_is_refused(node_pair):
    node_pair.pair()
    b = node_pair.b
    peer_b = node_pair.test_peer(node_pair.a)
    sock = socket.create_connection((peer_b.host, peer_b.port), timeout=5)
    send_frame(
        sock,
        {
            "type": "sync_open",
            "v": 1,  # legacy protocol
            "fp": node_pair.a.store.fingerprint(),
            "nonce8": base64.b64encode(os.urandom(8)).decode("ascii"),
        },
    )
    reply = __import__("json").loads(recv_frame(sock).decode("utf-8"))
    assert reply["type"] == "error"
    sock.close()


pytestmark = pytest.mark.socket
