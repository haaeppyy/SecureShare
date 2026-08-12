"""Clipboard sync between paired devices (text + images), off by default.

A persistent TCP connection is kept open to each paired, currently
discovered peer while sync is enabled. To avoid two simultaneous
connections between the same pair, the device with the lexicographically
larger fingerprint accepts, the smaller one initiates.

The watcher polls the local clipboard every 400ms and hash-compares it to
the last-seen value; on change it encrypts (AES-GCM, fresh nonce per
message) and forwards. Echo prevention: every time we set the clipboard
(own change or received message) we immediately re-read and record the
signature, so the next poll can never mistake our own write for a new
local change.
"""

import base64
import json
import os
import socket
import threading
import time

from . import clipboard, crypto
from .transfer import recv_frame, send_frame

POLL_INTERVAL = 0.4
RECONNECT_INTERVAL = 5.0
CHANNEL_TIMEOUT = 120.0


class SyncError(Exception):
    pass


class SyncChannel:
    """One persistent encrypted message stream to a paired peer."""

    def __init__(self, conn, peer_fp, peer_name, trust_key, engine):
        self.conn = conn
        self.peer_fp = peer_fp
        self.peer_name = peer_name
        self._trust_key = trust_key
        self._engine = engine
        self._lock = threading.Lock()
        self.closed = False

    def run(self) -> None:
        """Blocking frame-read loop; runs in a dedicated thread or in the
        server connection thread depending on which side initiated."""
        while not self.closed:
            try:
                raw = recv_frame(self.conn)
            except socket.timeout:
                continue  # idle, keep the persistent channel alive
            except Exception:
                break
            try:
                header = json.loads(raw.decode("utf-8"))
            except ValueError:
                continue
            self._engine.handle_frame(self, header)
        self.engine_remove()

    def engine_remove(self) -> None:
        self._engine.on_channel_closed(self)

    def send(self, kind: str, data: bytes) -> None:
        nonce = os.urandom(crypto.NONCE_LENGTH)
        key = crypto.derive_sync_key(self._trust_key, nonce)
        # The nonce is prepended so the receiver can derive the key.
        sealed = nonce + crypto.encrypt_with_nonce(key, nonce, data)
        payload = base64.b64encode(sealed).decode("ascii")
        with self._lock:
            if self.closed:
                return
            try:
                send_frame(self.conn, {"type": kind, "payload": payload})
            except Exception:
                self.closed = True

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


class SyncEngine:
    """Watches the local clipboard and mirrors it to paired peers."""

    def __init__(self, store, discovery, relay=None, on_status=None):
        self.store = store
        self.discovery = discovery
        self.relay = relay  # optional: (fp, kind, data) echo back for tests
        self.on_status = on_status or (lambda s: None)
        self.enabled = bool(store.sync_enabled)
        self._channels: dict[str, SyncChannel] = {}
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._watch_thread = None
        self._connect_thread = None
        self.last_seen = ()

    # -- lifecycle -----------------------------------------------------------

    def start(self) -> None:
        self._stop.clear()
        self._watch_thread = threading.Thread(target=self._watch_loop, name="sync-watch", daemon=True)
        self._watch_thread.start()
        self._connect_thread = threading.Thread(target=self._connect_loop, name="sync-connect", daemon=True)
        self._connect_thread.start()

    def stop(self) -> None:
        self._stop.set()
        for ch in list(self._channels.values()):
            ch.close()
        self._channels.clear()

    def set_enabled(self, enabled: bool) -> None:
        self.enabled = bool(enabled)
        self.store.set_sync_enabled(self.enabled)
        if not self.enabled:
            for ch in list(self._channels.values()):
                ch.close()
            self._channels.clear()
            self.on_status("Clipboard sync: off")
        else:
            self.on_status("Clipboard sync: on")

    # -- inbound connection handling (from TransferServer.on_other) ----------

    def on_inbound(self, conn, header, header_bytes, addr) -> None:
        """Handle a sync_open frame on a fresh connection (server thread)."""
        fp = header.get("fp", "")
        peer = self.store.get_peer(fp)
        if not peer or not self.enabled:
            try:
                send_frame(conn, {"type": "error", "code": "sync_disabled"})
            except OSError:
                pass
            return
        with self._lock:
            old = self._channels.get(fp)
            if old is not None:
                old.close()
            ch = SyncChannel(conn, fp, peer.get("name", fp[:8]), peer["trust_key"], self)
            self._channels[fp] = ch
        self.on_status(f"Synced with {ch.peer_name}")
        ch.run()  # reads frames until the connection dies

    def handle_frame(self, channel: SyncChannel, header: dict) -> None:
        kind = header.get("type")
        payload_b64 = header.get("payload")
        if kind not in ("clipboard_text", "clipboard_image") or not payload_b64:
            return
        if not self.enabled:
            return
        try:
            sealed = base64.b64decode(payload_b64)
            nonce = sealed[:crypto.NONCE_LENGTH]
            ct = sealed[crypto.NONCE_LENGTH:]
            key = crypto.derive_sync_key(channel._trust_key, nonce)
            data = crypto.decrypt_with_nonce(key, nonce, ct)
        except Exception:
            return  # bad message (incl. InvalidTag): drop it
        if self.relay:
            self.relay(channel.peer_fp, kind, data)
        if kind == "clipboard_text":
            clipboard.write(text=data.decode("utf-8", "replace"))
        elif kind == "clipboard_image":
            clipboard.write(image_png=data)
        self._note_written()

    def _note_written(self) -> None:
        """Record the clipboard signature immediately after we wrote to it,
        so the next poll cannot mistake our own write for a new local
        change (echo prevention)."""
        self._note_seen()

    def on_channel_closed(self, channel: SyncChannel) -> None:
        with self._lock:
            if self._channels.get(channel.peer_fp) is channel:
                del self._channels[channel.peer_fp]

    # -- outbound ------------------------------------------------------------

    def _connect_loop(self) -> None:
        while not self._stop.is_set():
            self.ensure_connections()
            self._stop.wait(RECONNECT_INTERVAL)

    def ensure_connections(self) -> None:
        if not self.enabled:
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
            try:
                conn = socket.create_connection((peer.host, peer.port), timeout=10)
                conn.settimeout(CHANNEL_TIMEOUT)
                trust_key = self.store.get_peer(fp)["trust_key"]
                send_frame(conn, {"type": "sync_open", "fp": self.store.fingerprint()})
            except Exception:
                continue
            channel = SyncChannel(conn, fp, peer.name, trust_key, self)
            with self._lock:
                self._channels[fp] = channel
            self.on_status(f"Synced: {channel.peer_name}")
            threading.Thread(target=channel.run, name="sync-out-conn", daemon=True).start()

    # -- watcher -------------------------------------------------------------

    def _watch_loop(self) -> None:
        self._note_seen()  # seed last_seen at start
        while not self._stop.is_set():
            start = time.monotonic()
            try:
                self._watch_once()
            except Exception:
                pass
            elapsed = time.monotonic() - start
            self._stop.wait(max(0.0, POLL_INTERVAL - elapsed))

    def _note_seen(self) -> None:
        try:
            self.last_seen = clipboard.read().signature()
        except Exception:
            self.last_seen = ()

    def _watch_once(self) -> None:
        snap = clipboard.read()
        sig = snap.signature()
        if sig == self.last_seen:
            return
        self.last_seen = sig
        if not self.enabled or snap.file_copy:
            return
        with self._lock:
            channels = list(self._channels.values())
        if snap.image_png is not None:
            for ch in channels:
                ch.send("clipboard_image", snap.image_png)
        if snap.text is not None:
            for ch in channels:
                ch.send("clipboard_text", snap.text.encode("utf-8"))