"""Clipboard sync tests: echo prevention, framing, off-by-default toggle.

Uses a fake clipboard so the tests are hermetic; the real OS clipboard
round-trip is covered by the Step 8 manual suite and the integration
script (tests/integration_sync.py).
"""

import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import crypto, sync
from core.clipboard import ClipboardSnapshot
from core.node import Node

from conftest import node_pair  # noqa: F401


class FakeClipboard:
    def __init__(self):
        self.text = None
        self.image = None
        self.file_copy = False
        self.lock = threading.Lock()

    def read(self):
        with self.lock:
            return ClipboardSnapshot(
                text=self.text, image_png=self.image, file_copy=self.file_copy
            )

    def write(self, text=None, image_png=None):
        with self.lock:
            if image_png is not None:
                self.image = image_png
            if text is not None:
                self.text = text


class FakeChannel:
    def __init__(self, peer_fp="fp-b", name="Bob"):
        self.peer_fp = peer_fp
        self.peer_name = name
        self._trust_key = b"t" * 32
        self.sent = []
        self.closed = False

    def send(self, kind, data):
        self.sent.append((kind, data))

    def close(self):
        self.closed = True


class StubStore:
    def __init__(self):
        self.sync_enabled = False

    def set_sync_enabled(self, value):
        self.sync_enabled = value

    def fingerprint(self):
        return "fp-a"


class StubDiscovery:
    def peers(self):
        return {}


def make_engine(fake_clip):
    """A SyncEngine with the clipboard monkeypatched and one channel."""
    engine = sync.SyncEngine(store=StubStore(), discovery=StubDiscovery())
    sync.clipboard = fake_clip
    channel = FakeChannel()
    engine._channels[channel.peer_fp] = channel
    return engine, channel


def test_off_by_default_and_toggle(tmp_path, node_pair):
    node_pair.pair()
    assert node_pair.a.sync.enabled is False  # default OFF
    node_pair.a.sync.set_enabled(True)
    assert node_pair.a.store.sync_enabled is True  # persisted
    node_pair.a.sync.set_enabled(False)
    assert node_pair.a.sync.enabled is False


def test_engine_restart_clears_stop_event():
    """Regression: stop() set _stop, start() must clear it, or the watch and
    connect loops exit immediately after a restart."""
    fake = FakeClipboard()
    fake.text = "initial"
    engine, channel = make_engine(fake)
    engine.enabled = True
    engine.start()
    engine.stop()  # stop() clears _channels, as it does at app shutdown
    engine.start()  # restart must revive the loops
    time.sleep(0.5)
    engine._channels[channel.peer_fp] = channel  # ensure_connections re-adds it
    fake.text = "after restart"
    time.sleep(1.0)  # give the watcher a poll cycle
    assert channel.sent, "watcher should detect a change after restart"
    engine.stop()


def test_local_change_sends_once_no_loop():
    fake = FakeClipboard()
    fake.text = "initial"
    engine, channel = make_engine(fake)
    engine.enabled = True
    engine._note_seen()  # seeds last_seen, as _watch_loop does before polling
    engine._watch_once()
    assert channel.sent == []

    fake.text = "new value"
    engine._watch_once()
    assert len(channel.sent) == 1
    assert channel.sent[0][0] == "clipboard_text"

    # Second poll: unchanged -> no resend (no echo loop).
    engine._watch_once()
    assert len(channel.sent) == 1


def test_received_message_does_not_echo_back():
    """After writing a received message to the clipboard, the next poll must
    not treat it as a new local change."""
    fake = FakeClipboard()
    fake.text = "start"
    engine, channel = make_engine(fake)
    engine.enabled = True
    engine._note_seen()

    # Simulate an incoming text message being applied.
    fake.write(text="from remote")
    engine.handle_frame(channel, {"type": "clipboard_text", "payload": fake_payload("from remote")})
    assert fake.text == "from remote"
    before = len(channel.sent)
    engine._watch_once()
    assert len(channel.sent) == before  # no echo


def test_rapid_both_sides_copies_settle():
    fake_a = FakeClipboard()
    engine_a, channel_a = make_engine(fake_a)
    engine_a.enabled = True
    engine_a._note_seen()

    fake_b = FakeClipboard()
    engine_b, channel_b = make_engine(fake_b)
    engine_b.enabled = True
    engine_b._note_seen()

    for i in range(8):
        fake_a.text = f"value-{i}"
        engine_a._watch_once()  # A detects + sends
        if channel_a.sent:
            kind, data = channel_a.sent.pop(0)
            fake_b.write(text=data.decode())  # B applies it
            engine_b.handle_frame(channel_b, {"type": kind, "payload": fake_payload(data.decode())})
            engine_b._watch_once()  # B's poll after apply: must be no-op
        fake_b.text = f"value-{i}-b"
        engine_b._watch_once()
        if channel_b.sent:
            kind, data = channel_b.sent.pop(0)
            fake_a.write(text=data.decode())
            engine_a.handle_frame(channel_a, {"type": kind, "payload": fake_payload(data.decode())})
            engine_a._watch_once()
    # All messages must have propagated and everything settled with no echoes.
    assert channel_a.sent == []
    assert channel_b.sent == []


def test_image_sync_path():
    fake = FakeClipboard()
    engine, channel = make_engine(fake)
    engine.enabled = True
    engine._note_seen()
    fake.image = b"PNGDATA"
    engine._watch_once()
    assert len(channel.sent) == 1
    assert channel.sent[0][0] == "clipboard_image"
    engine._watch_once()
    assert len(channel.sent) == 1


def test_disabled_engine_drops_incoming():
    fake = FakeClipboard()
    engine, channel = make_engine(fake)
    engine.enabled = False
    engine.handle_frame(channel, {"type": "clipboard_text", "payload": fake_payload("nope")})
    assert fake.text is None


def test_file_copy_never_synced():
    fake = FakeClipboard()
    fake.file_copy = True
    engine, channel = make_engine(fake)
    engine.enabled = True
    engine._note_seen()
    fake.text = "file name on clipboard"
    fake.file_copy = True
    engine._watch_once()
    assert channel.sent == []


def fake_payload(text):
    key = b"t" * 32
    nonce = os.urandom(12)
    sealed = nonce + crypto.encrypt_with_nonce(
        crypto.derive_sync_key(key, nonce), nonce, text.encode()
    )
    import base64

    return base64.b64encode(sealed).decode("ascii")