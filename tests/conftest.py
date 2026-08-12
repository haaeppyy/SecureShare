"""Shared pytest fixtures: paired Node pairs on loopback, temp dirs."""

import os
import sys
import tempfile
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.node import Node  # noqa: E402

PORT_BASE = 49500


class NodePair:
    """Two nodes discovered/paired on loopback; returns sessions for driving."""

    def __init__(
        self,
        tmpdir,
        name_a="Alpha",
        name_b="Beta",
        on_transfer_start=None,
        on_transfer_progress=None,
        kvm_platforms=None,
    ):
        self.tmp = tmpdir
        self.sessions_b = []
        self.a = Node(
            name=name_a,
            data_dir=os.path.join(tmpdir, "a"),
            port=PORT_BASE,
            download_dir=os.path.join(tmpdir, "dl_a"),
            keyring_enabled=False,
            on_transfer_start=on_transfer_start,
            on_transfer_progress=on_transfer_progress,
            kvm_platform=(kvm_platforms or {}).get("a"),
        )
        self.b = Node(
            name=name_b,
            data_dir=os.path.join(tmpdir, "b"),
            port=PORT_BASE + 1,
            download_dir=os.path.join(tmpdir, "dl_b"),
            keyring_enabled=False,
            on_incoming_pair=self.sessions_b.append,
            on_transfer_start=on_transfer_start,
            on_transfer_progress=on_transfer_progress,
            kvm_platform=(kvm_platforms or {}).get("b"),
        )

    def start(self):
        self.a.start()
        self.b.start()
        return self

    def test_peer(self, node):
        """The peer from this pair, not some other device on the LAN.

        Test nodes listen on PORT_BASE/PORT_BASE+1; any other service on the
        network (e.g. a real SecureShare instance) uses a different port.
        """
        for p in node.discovery.peers().values():
            if p.port in (PORT_BASE, PORT_BASE + 1):
                return p
        return None

    def wait_discovery(self, timeout=20.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.test_peer(self.a) is not None and self.test_peer(self.b) is not None:
                return True
            time.sleep(0.2)
        return False

    def pair(self, timeout=15.0):
        """Full happy-path pairing: A initiates, B accepts, both confirm PINs."""
        if not self.wait_discovery():
            raise RuntimeError("discovery failed")
        peer_a = self.test_peer(self.a)
        assert peer_a is not None, "test peer not found"
        result = {}

        def run():
            result["session"] = self.a.pair_with(peer_a.host, peer_a.port)

        t = threading.Thread(target=run)
        t.start()
        deadline = time.monotonic() + timeout
        while not self.sessions_b and time.monotonic() < deadline:
            time.sleep(0.05)
        assert self.sessions_b, "B never received the pairing request"
        session_b = self.sessions_b[0]
        session_b.accept()
        t.join(timeout=timeout)
        session_a = result["session"]
        assert session_a.pin == session_b.pin, "PINs must match"
        session_a.confirm(True)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self.a.store.is_paired(self.b.store.fingerprint()):
                break
            time.sleep(0.05)
        assert self.a.store.is_paired(self.b.store.fingerprint())
        assert self.b.store.is_paired(self.a.store.fingerprint())
        return session_a, session_b

    def stop(self):
        self.a.stop()
        self.b.stop()


@pytest.fixture
def node_pair(tmp_path):
    pair = NodePair(str(tmp_path)).start()
    yield pair
    pair.stop()


def make_file(directory, name, size):
    path = os.path.join(directory, name)
    with open(path, "wb") as f:
        f.write(os.urandom(size))
    return path


def file_hash(path):
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()