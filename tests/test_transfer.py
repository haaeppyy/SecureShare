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

import pytest

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


def _raw_send(node_pair, name, size, chunk_size, blocks):
    """Craft a raw transfer to B using A's stored trust key; returns the
    receiver's final reply frame (dict). ``blocks`` is a list of plaintext
    bytes (one per chunk) sent after the header."""
    peer = node_pair.test_peer(node_pair.a)
    trust_key = node_pair.a.store.get_peer(node_pair.b.store.fingerprint())["trust_key"]
    nonce8 = os.urandom(8)
    key = crypto.derive_transfer_key(trust_key, nonce8)
    header = {
        "type": "transfer",
        "name": name,
        "size": size,
        "fp": node_pair.a.store.fingerprint(),
        "nonce8": base64.b64encode(nonce8).decode("ascii"),
        "chunk_size": chunk_size,
    }
    sock = socket.create_connection((peer.host, peer.port), timeout=5)
    hdr = send_frame(sock, header)
    for index, block in enumerate(blocks):
        nonce = crypto.chunk_nonce(nonce8, index)
        ct = crypto.encrypt_with_nonce(key, nonce, block, aad=hdr)
        sock.sendall(struct.pack(">Q", len(ct)) + ct)
    return sock, json.loads(recv_frame(sock).decode("utf-8"))


def test_existing_file_is_preserved_and_suffixed(node_pair):
    """A colliding final path must never be overwritten: the receiver picks
    a -1/-2 suffix and the pre-existing file keeps its bytes."""
    node_pair.pair()
    existing = os.path.join(node_pair.tmp, "dl_b", "photo.jpg")
    os.makedirs(os.path.dirname(existing), exist_ok=True)
    with open(existing, "wb") as f:
        f.write(b"precious-original-bytes")
    src = make_file(node_pair.tmp, "photo.jpg", 4096)
    node_pair.a.send_file(node_pair.b.store.fingerprint(), src)
    suffix_path = os.path.join(node_pair.tmp, "dl_b", "photo-1.jpg")
    deadline = time.monotonic() + 10
    while not os.path.exists(suffix_path) and time.monotonic() < deadline:
        time.sleep(0.05)
    with open(existing, "rb") as f:
        assert f.read() == b"precious-original-bytes", "existing file was modified"
    assert file_hash(suffix_path) == file_hash(src)


def test_tampered_transfer_preserves_existing_file(node_pair):
    """Regression: the receiver used to os.remove(out_path) on failure,
    which would delete a pre-existing file it never owned. Tampering must
    leave both the existing file and no half-written artifacts."""
    node_pair.pair()
    errors = []
    node_pair.b.server.on_error = errors.append
    existing = os.path.join(node_pair.tmp, "dl_b", "tampered.bin")
    with open(existing, "wb") as f:
        f.write(b"keep-me")
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
    for i in range(2):
        nonce = crypto.chunk_nonce(nonce8, i)
        ct = bytearray(crypto.encrypt_with_nonce(key, nonce, os.urandom(1024), aad=hdr))
        if i == 1:
            ct[50] ^= 0xFF
        sock.sendall(struct.pack(">Q", len(ct)) + bytes(ct))
    sock.close()
    deadline = time.monotonic() + 5
    while not errors and time.monotonic() < deadline:
        time.sleep(0.05)
    assert errors, "receiver must report an error"
    with open(existing, "rb") as f:
        assert f.read() == b"keep-me", "existing file must survive a tampered transfer"
    assert not os.path.exists(os.path.join(node_pair.tmp, "dl_b", "tampered-1.bin"))
    assert not [f for f in os.listdir(node_pair.tmp + "/dl_b") if ".part-" in f], "temp files must be cleaned"


def test_interrupted_transfer_leaves_no_final_or_temp_file(node_pair):
    """Closing the socket mid-transfer must not leave a partial final file
    or a leftover .part temporary file."""
    node_pair.pair()
    peer = node_pair.test_peer(node_pair.a)
    trust_key = node_pair.a.store.get_peer(node_pair.b.store.fingerprint())["trust_key"]
    nonce8 = os.urandom(8)
    key = crypto.derive_transfer_key(trust_key, nonce8)
    header = {
        "type": "transfer",
        "name": "interrupted.bin",
        "size": 3 * (1 << 20),
        "fp": node_pair.a.store.fingerprint(),
        "nonce8": base64.b64encode(nonce8).decode("ascii"),
        "chunk_size": 1 << 20,
    }
    sock = socket.create_connection((peer.host, peer.port), timeout=5)
    hdr = send_frame(sock, header)
    for index in range(2):  # send 2 of 3 chunks, then die
        nonce = crypto.chunk_nonce(nonce8, index)
        ct = crypto.encrypt_with_nonce(key, nonce, os.urandom(1 << 20), aad=hdr)
        sock.sendall(struct.pack(">Q", len(ct)) + ct)
    sock.close()
    deadline = time.monotonic() + 5
    dl = os.path.join(node_pair.tmp, "dl_b")
    while time.monotonic() < deadline:
        files = [f for f in os.listdir(dl) if f != "interrupted.bin"]
        if not files:
            break
        time.sleep(0.05)
    assert not os.path.exists(os.path.join(dl, "interrupted.bin"))
    assert not [f for f in os.listdir(dl) if f != "interrupted.bin"], "no partial files may remain"


def test_insufficient_disk_space_refused(node_pair, monkeypatch):
    node_pair.pair()

    class _DiskUsage:
        free = 4096

    monkeypatch.setattr("core.transfer.shutil.disk_usage", lambda _dir: _DiskUsage())
    sock, reply = _raw_send(node_pair, "nospace.bin", 1 << 20, 1 << 20, [b""])
    sock.close()
    assert reply["type"] == "error"
    assert reply["code"] == "no_space"
    assert not os.path.exists(os.path.join(node_pair.tmp, "dl_b", "nospace.bin"))


def test_transfer_over_max_size_refused(node_pair):
    node_pair.pair()
    node_pair.b.server.max_transfer_size = 1024
    sock, reply = _raw_send(node_pair, "huge.bin", 2048, 1024, [b""])
    sock.close()
    assert reply["type"] == "error"
    assert reply["code"] == "too_large"
    assert not os.path.exists(os.path.join(node_pair.tmp, "dl_b", "huge.bin"))


def test_concurrent_same_name_transfers(node_pair):
    """Two transfers with the same name must land at data.bin and data-1.bin
    (claim set prevents the race to a shared final path)."""
    node_pair.pair()
    src = make_file(node_pair.tmp, "dup.bin", 2 * (1 << 20))
    results = []
    errors = []
    barrier = threading.Barrier(2)

    def send():
        barrier.wait()
        try:
            node_pair.a.send_file(node_pair.b.store.fingerprint(), src)
            results.append("ok")
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=send) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert not errors, errors
    dl = os.path.join(node_pair.tmp, "dl_b")
    deadline = time.monotonic() + 10
    paths = []
    while time.monotonic() < deadline:
        paths = [os.path.join(dl, n) for n in os.listdir(dl) if n.startswith("dup")]
        if len(paths) == 2:
            break
        time.sleep(0.05)
    assert sorted(os.path.basename(p) for p in paths) == ["dup-1.bin", "dup.bin"], paths
    assert file_hash(paths[0]) == file_hash(src)
    assert file_hash(paths[1]) == file_hash(src)

pytestmark = pytest.mark.socket
