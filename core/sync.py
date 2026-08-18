"""Clipboard sync between paired devices (text + images), off by default.

A persistent TCP connection is kept open to each paired, currently
discovered peer while sync is enabled. To avoid two simultaneous
connections between the same pair, the device with the lexicographically
smaller fingerprint accepts, the larger one initiates.

Channel security (protocol version 2):

- Opening is a challenge/response handshake authenticated with the pair's
  trust key. The responder never touches its current channel until the
  initiator proves knowledge of the trust key by sealing a ``sync_hello``
  frame with the channel key; only then is the old channel replaced.
- The channel key binds protocol version, both fingerprints, the role and
  both 8-byte nonces (HKDF over the trust key).
- Every clipboard frame carries immutable metadata (type, protocol
  version, sender/receiver fingerprints) and a per-direction monotonic
  sequence number; the exact JSON of those fields is the AES-GCM AAD.
  Duplicates, stale and out-of-order frames are rejected.

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
import struct
import threading
import time

from cryptography.exceptions import InvalidTag

from . import clipboard, crypto
from .transfer import ProtocolError, recv_frame, send_frame

SYNC_PROTOCOL_VERSION = 2
POLL_INTERVAL = 0.4
RECONNECT_INTERVAL = 5.0
CHANNEL_TIMEOUT = 120.0
HANDSHAKE_TIMEOUT = 10.0
MAX_SEQ_GAP = 0  # any gap (seq > last+1) is fatal: the stream is dropped


class SyncError(Exception):
    pass


def sync_channel_key(
    trust_key: bytes,
    version: int,
    fp_i: str,
    fp_r: str,
    nonce8_i: bytes,
    nonce8_r: bytes,
) -> bytes:
    """Channel key; every handshake parameter is bound into the KDF."""
    salt = b"".join(
        (
            struct.pack(">I", version),
            b"sync",
            b"initiator",
            fp_i.encode("utf-8"),
            fp_r.encode("utf-8"),
            nonce8_i,
            nonce8_r,
        )
    )
    return crypto.derive_sync_channel_key(trust_key, salt)


def _frame_aad(kind: str, version: int, fp: str, peer_fp: str, seq: int) -> bytes:
    """Canonical AAD bytes for one frame: the exact JSON of its immutable
    metadata. Built in a fixed key order on both sides so the bytes always
    match the sender's."""
    meta = {
        "type": kind,
        "v": version,
        "fp": fp,
        "peer_fp": peer_fp,
        "seq": seq,
    }
    return json.dumps(meta, separators=(",", ":")).encode("utf-8")


class SyncChannel:
    """One persistent encrypted message stream to a paired peer."""

    def __init__(self, conn, peer_fp, peer_name, key, engine):
        self.conn = conn
        self.peer_fp = peer_fp
        self.peer_name = peer_name
        self._key = key
        self._engine = engine
        self._lock = threading.Lock()
        self._seq_out = 0
        self._seq_in = -1  # next expected inbound sequence
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
        if kind not in ("clipboard_text", "clipboard_image"):
            return
        with self._lock:
            if self.closed:
                return
            seq = self._seq_out
            self._seq_out += 1
        aad = _frame_aad(kind, SYNC_PROTOCOL_VERSION, self._engine.store.fingerprint(), self.peer_fp, seq)
        sealed = crypto.encrypt(self._key, data, aad)
        with self._lock:
            if self.closed:
                return
            try:
                send_frame(
                    self.conn,
                    {
                        "type": kind,
                        "v": SYNC_PROTOCOL_VERSION,
                        "fp": self._engine.store.fingerprint(),
                        "peer_fp": self.peer_fp,
                        "seq": seq,
                        "payload": base64.b64encode(sealed).decode("ascii"),
                    },
                )
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
        self.on_status = on_status or (lambda s, level="info": None)
        self.enabled = bool(store.sync_enabled)
        self._channels: dict[str, SyncChannel] = {}
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._watch_thread = None
        self._connect_thread = None
        self.last_seen = ()
        self._last_count = None

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
        """Handle a sync_open frame on a fresh connection (server thread).

        Runs the challenge/response handshake *without* touching the current
        channel: the old channel is closed only after the initiator proves
        knowledge of the trust key via the sealed sync_hello frame.
        """
        v = header.get("v")
        fp = header.get("fp", "")
        peer = self.store.get_peer(fp)
        if v != SYNC_PROTOCOL_VERSION or not peer or not self.enabled:
            try:
                send_frame(conn, {"type": "error", "code": "sync_disabled"})
            except OSError:
                pass
            return
        try:
            nonce8_i = base64.b64decode(header["nonce8"])
        except (KeyError, ValueError, TypeError):
            try:
                send_frame(conn, {"type": "error", "code": "bad_open"})
            except OSError:
                pass
            return
        if len(nonce8_i) != crypto.CHUNK_NONCE_PREFIX_BYTES:
            try:
                send_frame(conn, {"type": "error", "code": "bad_open"})
            except OSError:
                pass
            return
        my_nonce8 = os.urandom(crypto.CHUNK_NONCE_PREFIX_BYTES)
        key = sync_channel_key(
            peer["trust_key"], v, fp, self.store.fingerprint(), nonce8_i, my_nonce8
        )
        conn.settimeout(HANDSHAKE_TIMEOUT)
        try:
            send_frame(
                conn,
                {
                    "type": "sync_ack",
                    "v": v,
                    "fp": self.store.fingerprint(),
                    "peer_fp": fp,
                    "nonce8": base64.b64encode(my_nonce8).decode("ascii"),
                },
            )
            raw = recv_frame(conn)
            hello = json.loads(raw.decode("utf-8"))
            self._verify_hello(key, hello, fp)
        except (OSError, ProtocolError, ValueError, InvalidTag):
            try:
                send_frame(conn, {"type": "error", "code": "auth_failed"})
            except OSError:
                pass
            return
        try:
            send_frame(conn, {"type": "sync_ok"})
        except OSError:
            return
        conn.settimeout(CHANNEL_TIMEOUT)
        # Only now may the current valid channel be replaced.
        with self._lock:
            old = self._channels.get(fp)
            if old is not None:
                old.close()
            ch = SyncChannel(conn, fp, peer.get("name", fp[:8]), key, self)
            self._channels[fp] = ch
        self.on_status(f"Synced with {ch.peer_name}")
        ch.run()  # reads frames until the connection dies

    def _verify_hello(self, key: bytes, hello: dict, expected_fp: str) -> None:
        if hello.get("type") != "sync_hello":
            raise InvalidTag("not a hello frame")
        if hello.get("v") != SYNC_PROTOCOL_VERSION:
            raise InvalidTag("wrong version")
        if hello.get("fp") != expected_fp:
            raise InvalidTag("wrong sender")
        aad = _frame_aad("sync_hello", SYNC_PROTOCOL_VERSION, expected_fp, self.store.fingerprint(), 0)
        try:
            payload = base64.b64decode(hello["payload"])
        except (KeyError, ValueError, TypeError):
            raise InvalidTag("no payload")
        crypto.decrypt(key, payload, aad)  # raises InvalidTag unless key matches

    def handle_frame(self, channel: SyncChannel, header: dict) -> None:
        kind = header.get("type")
        if kind not in ("clipboard_text", "clipboard_image"):
            return
        if not self.enabled:
            return
        if header.get("v") != SYNC_PROTOCOL_VERSION:
            return
        if header.get("fp") != channel.peer_fp or header.get("peer_fp") != self.store.fingerprint():
            return
        try:
            seq = int(header.get("seq", -1))
        except (TypeError, ValueError):
            return
        if seq != channel._seq_in + 1:
            if seq <= channel._seq_in:
                return  # duplicate or stale: drop silently
            channel.close()  # gap: out-of-order frame, stream is compromised
            return
        channel._seq_in = seq
        payload_b64 = header.get("payload")
        if not payload_b64:
            return
        aad = _frame_aad(kind, SYNC_PROTOCOL_VERSION, channel.peer_fp, self.store.fingerprint(), seq)
        try:
            sealed = base64.b64decode(payload_b64)
            data = crypto.decrypt(channel._key, sealed, aad)
        except (ValueError, InvalidTag):
            channel.close()  # tampered payload: drop the channel
            return
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
            conn = None
            key = None
            try:
                conn = socket.create_connection((peer.host, peer.port), timeout=10)
                conn.settimeout(HANDSHAKE_TIMEOUT)
                trust_key = self.store.get_peer(fp)["trust_key"]
                my_nonce8 = os.urandom(crypto.CHUNK_NONCE_PREFIX_BYTES)
                send_frame(
                    conn,
                    {
                        "type": "sync_open",
                        "v": SYNC_PROTOCOL_VERSION,
                        "fp": my_fp,
                        "nonce8": base64.b64encode(my_nonce8).decode("ascii"),
                    },
                )
                raw = recv_frame(conn)
                ack = json.loads(raw.decode("utf-8"))
                if (
                    ack.get("type") != "sync_ack"
                    or ack.get("v") != SYNC_PROTOCOL_VERSION
                    or ack.get("fp") != fp
                    or ack.get("peer_fp") != my_fp
                ):
                    raise ProtocolError("bad sync_ack")
                peer_nonce8 = base64.b64decode(ack["nonce8"])
                if len(peer_nonce8) != crypto.CHUNK_NONCE_PREFIX_BYTES:
                    raise ProtocolError("bad sync_ack nonce")
                key = sync_channel_key(trust_key, SYNC_PROTOCOL_VERSION, my_fp, fp, my_nonce8, peer_nonce8)
                hello_aad = _frame_aad("sync_hello", SYNC_PROTOCOL_VERSION, my_fp, fp, 0)
                hello = {
                    "type": "sync_hello",
                    "v": SYNC_PROTOCOL_VERSION,
                    "fp": my_fp,
                    "peer_fp": fp,
                    "seq": 0,
                    "payload": base64.b64encode(
                        crypto.encrypt(key, b"hello", hello_aad)
                    ).decode("ascii"),
                }
                send_frame(conn, hello)
                raw = recv_frame(conn)
                ok = json.loads(raw.decode("utf-8"))
                if ok.get("type") != "sync_ok":
                    raise ProtocolError("handshake rejected")
            except (OSError, ProtocolError, ValueError):
                if conn is not None:
                    try:
                        conn.close()
                    except OSError:
                        pass
                continue
            conn.settimeout(CHANNEL_TIMEOUT)
            channel = SyncChannel(conn, fp, peer.name, key, self)
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
        self._last_count = None
        try:
            self._last_count = clipboard.change_count()
        except Exception:
            self._last_count = None
        if self._last_count is None:
            try:
                self.last_seen = clipboard.read().signature()
            except Exception:
                self.last_seen = ()

    def _watch_once(self) -> None:
        cnt = None
        try:
            cnt = clipboard.change_count()
        except Exception:
            cnt = None
        if cnt is not None:
            if cnt == self._last_count:
                return  # cheap gate: nothing changed since last poll
            self._last_count = cnt
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
