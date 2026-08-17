"""Clipboard sync tests: echo prevention, framing, off-by-default toggle.

Uses a fake clipboard so the tests are hermetic; the real OS clipboard
round-trip is covered by the Step 8 manual suite and the integration
script (tests/integration_sync.py).
"""

import base64
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import crypto, sync
from core.clipboard import ClipboardSnapshot
from core.node import Node

from conftest import node_pair  # noqa: F401

import pytest


class FakeClipboard:
    def __init__(self):
        self._text = None
        self._image = None
        self.file_copy = False
        self.lock = threading.Lock()
        self.revisions = 0
        self.read_calls = 0

    @property
    def text(self):
        return self._text

    @text.setter
    def text(self, value):
        with self.lock:
            self.revisions += 1  # external copy: the OS bumps the counter too
            self._text = value

    @property
    def image(self):
        return self._image

    @image.setter
    def image(self, value):
        with self.lock:
            self.revisions += 1
            self._image = value

    def read(self):
        with self.lock:
            self.read_calls += 1
            return ClipboardSnapshot(
                text=self._text, image_png=self._image, file_copy=self.file_copy
            )

    def write(self, text=None, image_png=None):
        with self.lock:
            if image_png is not None:
                self.revisions += 1
                self._image = image_png
            if text is not None:
                self.revisions += 1
                self._text = text

    def change_count(self):
        with self.lock:
            return self.revisions


class FakeChannel:
    def __init__(self, peer_fp="fp-b", name="Bob", engine=None):
        self.peer_fp = peer_fp
        self.peer_name = name
        self._key = b"k" * 32
        self._engine = engine
        self._seq_out = 0
        self._seq_in = 0
        self.sent = []
        self.closed = False

    def send(self, kind, data):
        self._seq_out += 1
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
    channel = FakeChannel(engine=engine)
    engine._channels[channel.peer_fp] = channel
    return engine, channel


def make_frame(channel, kind, data, seq=None):
    """A valid v2 frame as the peer would send it (sealed with the channel
    key, sequence number in the AAD)."""
    engine = channel._engine
    if seq is None:
        seq = channel._seq_in + 1
    aad = sync._frame_aad(kind, sync.SYNC_PROTOCOL_VERSION, channel.peer_fp, engine.store.fingerprint(), seq)
    sealed = crypto.encrypt(channel._key, data, aad)
    return {
        "type": kind,
        "v": sync.SYNC_PROTOCOL_VERSION,
        "fp": channel.peer_fp,
        "peer_fp": engine.store.fingerprint(),
        "seq": seq,
        "payload": base64.b64encode(sealed).decode("ascii"),
    }


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
    engine.handle_frame(channel, make_frame(channel, "clipboard_text", b"from remote"))
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
            engine_b.handle_frame(channel_b, make_frame(channel_b, kind, data))
            engine_b._watch_once()  # B's poll after apply: must be no-op
        fake_b.text = f"value-{i}-b"
        engine_b._watch_once()
        if channel_b.sent:
            kind, data = channel_b.sent.pop(0)
            fake_a.write(text=data.decode())
            engine_a.handle_frame(channel_a, make_frame(channel_a, kind, data))
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
    engine.handle_frame(channel, make_frame(channel, "clipboard_text", b"nope"))
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

def test_watch_once_skips_read_when_count_unchanged():
    fake = FakeClipboard()
    fake.text = "initial"
    engine, channel = make_engine(fake)
    engine.enabled = True
    engine._note_seen()
    engine._watch_once()
    assert channel.sent == []
    reads_after_seed = fake.read_calls
    engine._watch_once()
    engine._watch_once()
    assert fake.read_calls == reads_after_seed, "count gate must avoid full reads"

    fake.text = "new value"  # OS bump: revision changes
    engine._watch_once()
    assert len(channel.sent) == 1
    engine._watch_once()
    assert len(channel.sent) == 1  # and stays quiet afterwards


def test_watch_once_falls_back_to_read_without_change_count(monkeypatch):
    fake = FakeClipboard()
    monkeypatch.setattr(fake, "change_count", None)
    fake.text = "initial"
    engine, channel = make_engine(fake)
    engine.enabled = True
    engine._note_seen()
    engine._watch_once()
    fake.text = "changed"
    engine._watch_once()
    assert len(channel.sent) == 1


def test_note_seen_after_sync_write_reseeds_counter():
    fake = FakeClipboard()
    fake.text = "start"
    engine, channel = make_engine(fake)
    engine.enabled = True
    engine._note_seen()
    fake.write(text="from remote")  # our own write: counter bumps
    engine._note_written()  # applied-path echo prevention
    engine._watch_once()
    assert channel.sent == []  # our own write must not be re-sent


def test_change_count_dispatcher_smoke():
    from core import clipboard

    cnt = clipboard.change_count()
    assert cnt is None or isinstance(cnt, int)


pytestmark = pytest.mark.socket
