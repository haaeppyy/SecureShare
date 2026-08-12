"""Transfer tests: integrity, tamper rejection, unpaired refusal, streaming."""

import base64
import json
import os
import socket
import struct
import threading
import time

from core import crypto
from core.transfer import (
    TransferRefusedError,
    recv_frame,
    recv_exact,
    send_frame,
)

from conftest import file_hash, make_file, node_pair  # noqa: F401

def test_transfer_integrity_multi_chunk(node_pair):
    node_pair.pair()
    src = make_file(node_pair.tmp, "data.bin", 3 * (1 << 20) + 12345)  # >3 chunks
    result = node_pair.a.send_file(node_pair.b.store.fingerprint(), src)
    assert result["bytes"] == os.path.getsize(src)
    assert result["mbps"] > 0
    got = os.path.join(node_pair.tmp, "dl_b", "data.bin")
    deadline = time.monotonic() + 10
    while not os.path.exists(got) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert file_hash(got) == file_hash(src)


def test_transfer_progress_reports_total(node_pair):
    node_pair.pair()
    src = make_file(node_pair.tmp, "progress.bin", 2 * (1 << 20) + 7)
    progress = []
    node_pair.a.send_file(
        node_pair.b.store.fingerprint(), src, on_progress=lambda sent, total: progress.append((sent, total))
    )
    assert progress
    assert progress[-1][0] == progress[-1][1] == os.path.getsize(src)


def test_receiver_reports_transfer_progress(node_pair):
    """The receiver side must surface start + progress callbacks with the
    sender's identity so the UI can attribute an incoming transfer."""
    node_pair.pair()
    src = make_file(node_pair.tmp, "recv_progress.bin", 2 * (1 << 20) + 13)
    size = os.path.getsize(src)
    lock = threading.Lock()
    starts, progress = [], []

    def on_start(info):
        with lock:
            starts.append(info)

    def on_progress(info, received, total):
        with lock:
            progress.append((info, received, total))

    node_pair.b.on_transfer_start = on_start
    node_pair.b.on_transfer_progress = on_progress
    result = node_pair.a.send_file(node_pair.b.store.fingerprint(), src)
    assert result["bytes"] == size
    assert starts, "receiver on_transfer_start must fire"
    assert progress, "receiver on_transfer_progress must fire"
    info = starts[0]
    assert info["name"] == "recv_progress.bin"
    assert info["size"] == size
    assert info["fingerprint"] == node_pair.a.store.fingerprint()
    assert info["from"]
    received = [r for info, r, t in progress]
    assert received == sorted(received), "progress must be monotonic"
    assert progress[-1][1] == progress[-1][2] == size
    for info, r, t in progress:
        assert info["fingerprint"] == node_pair.a.store.fingerprint()


def test_unpaired_sender_is_refused(tmp_path, node_pair):
    node_pair.pair()
    src = make_file(node_pair.tmp, "x.bin", 4096)
    # Craft a raw transfer from a device that never paired with B.
    trust_key = node_pair.a.store.get_peer(node_pair.b.store.fingerprint())["trust_key"]
    peer = node_pair.test_peer(node_pair.a)
    nonce8 = os.urandom(8)
    key = crypto.derive_transfer_key(trust_key, nonce8)
    header = {
        "type": "transfer",
        "name": "evil.bin",
        "size": 4096,
        "fp": "unknown-fingerprint-0000",
        "nonce8": base64.b64encode(nonce8).decode("ascii"),
        "chunk_size": 1 << 20,
    }
    sock = socket.create_connection((peer.host, peer.port), timeout=5)
    hdr = send_frame(sock, header)
    ct = crypto.encrypt_with_nonce(key, crypto.chunk_nonce(nonce8, 0), b"A" * 4096, aad=hdr)
    sock.sendall(struct.pack(">Q", len(ct)) + ct)
    reply = json.loads(recv_frame(sock).decode("utf-8"))
    sock.close()
    assert reply["type"] == "error"
    assert reply["code"] == "not_paired"
    assert not os.path.exists(os.path.join(node_pair.tmp, "dl_b", "evil.bin"))


def test_tampered_chunk_aborts_transfer(tmp_path, node_pair):
    node_pair.pair()
    errors = []
    node_pair.b.server.on_error = errors.append
    peer = node_pair.test_peer(node_pair.a)
    trust_key = node_pair.a.store.get_peer(node_pair.b.store.fingerprint())["trust_key"]
    nonce8 = os.urandom(8)
    key = crypto.derive_transfer_key(trust_key, nonce8)
    header = {
        "type": "transfer",
        "name": "tampered.bin",
        "size": 2048,
        "fp": node_pair.a.store.fingerprint(),
        "nonce8": base64.b64encode(nonce8).decode("ascii"),
        "chunk_size": 1024,
    }
    sock = socket.create_connection((peer.host, peer.port), timeout=5)
    hdr = send_frame(sock, header)
    payload = os.urandom(2048)
    for i in range(2):
        block = payload[i * 1024 : (i + 1) * 1024]
        nonce = crypto.chunk_nonce(nonce8, i)
        ct = bytearray(crypto.encrypt_with_nonce(key, nonce, bytes(block), aad=hdr))
        if i == 1:
            ct[100] ^= 0xFF  # tamper the ciphertext of chunk 2
        sock.sendall(struct.pack(">Q", len(ct)) + bytes(ct))
    sock.close()
    deadline = time.monotonic() + 5
    while not errors and time.monotonic() < deadline:
        time.sleep(0.05)
    assert errors, "receiver must report an error"
    assert not os.path.exists(os.path.join(node_pair.tmp, "dl_b", "tampered.bin"))


def test_large_file_streaming_memory(tmp_path, node_pair):
    """2 GB file would blow up non-streaming implementations; we verify the
    memory footprint of the sender stays flat by checking RSS growth."""
    node_pair.pair()
    size = 8 * (1 << 20)  # 8 MiB (enough for several chunks, cheap in CI)
    src = make_file(node_pair.tmp, "big.bin", size)
    import resource

    rss_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    result = node_pair.a.send_file(node_pair.b.store.fingerprint(), src)
    rss_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    got = os.path.join(node_pair.tmp, "dl_b", "big.bin")
    deadline = time.monotonic() + 10
    while not os.path.exists(got) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert file_hash(got) == file_hash(src)
    # RSS growth must stay well below the file size (flat chunked memory).
    assert (rss_after - rss_before) < 4 * (1 << 20), (rss_before, rss_after)