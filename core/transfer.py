"""Chunked, authenticated file transfer over direct TCP.

Wire format
-----------
Every message is a frame: [4-byte big-endian length][UTF-8 JSON].
A transfer is a header frame followed by N chunk frames:

    header: {"type": "transfer", "name", "size", "fp", "nonce8", "chunk_size"}
    chunk:  [8-byte big-endian length][ciphertext]

The exact bytes of the header frame are used as AAD for every chunk, so
tampering with the header or any chunk fails AES-GCM authentication.
Each chunk uses a nonce of 8 random bytes + a 32-bit chunk counter
(see core.crypto.chunk_nonce), guaranteeing no nonce reuse. Chunks are
streamed end to end, keeping memory use flat regardless of file size.
"""

import base64
import json
import os
import socket
import struct
import threading
import time

from cryptography.exceptions import InvalidTag

from . import crypto
from .trust_store import TrustStore

MAX_HEADER = 1 << 20  # 1 MiB
MAX_CHUNK = 1 << 22   # 4 MiB guard
CHUNK_SIZE = 1 << 20  # 1 MiB default
GCM_OVERHEAD = 16     # AES-GCM auth tag bytes
DEFAULT_PORT = 48620
SOCK_TIMEOUT = 30.0


class ProtocolError(Exception):
    pass


class TransferRefusedError(ProtocolError):
    pass


class AuthFailedError(ProtocolError):
    pass


def send_frame(sock: socket.socket, obj: dict) -> bytes:
    data = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    sock.sendall(struct.pack(">I", len(data)) + data)
    return data


def recv_exact(sock: socket.socket, n: int) -> bytes:
    parts = []
    remaining = n
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ProtocolError("connection closed by peer")
        parts.append(chunk)
        remaining -= len(chunk)
    return b"".join(parts)


def recv_frame(sock: socket.socket) -> bytes:
    (length,) = struct.unpack(">I", recv_exact(sock, 4))
    if length > MAX_HEADER:
        raise ProtocolError("header too large")
    return recv_exact(sock, length)


def _pending_error(sock: socket.socket) -> str | None:
    """If the receiver rejected the transfer mid-flight, its error frame is
    still in our receive buffer; surface its message instead of a bare
    BrokenPipe."""
    sock.settimeout(0.5)
    try:
        raw = recv_frame(sock)
    except Exception:
        return None
    try:
        msg = json.loads(raw.decode("utf-8"))
    except ValueError:
        return None
    if msg.get("type") == "error":
        return str(msg.get("message", "transfer rejected"))
    return None


def default_download_dir() -> str:
    base = os.environ.get("USERPROFILE") or os.path.expanduser("~")
    return os.path.join(base, "Downloads", "SecureShare")


def send_file(
    host: str,
    port: int,
    sender_fingerprint: str,
    trust_key: bytes,
    path: str,
    on_progress=None,
    chunk_size: int = CHUNK_SIZE,
) -> dict:
    """Stream ``path`` to the peer with per-chunk AES-GCM authentication.

    ``sender_fingerprint`` is THIS device's fingerprint: the receiver uses
    it to look up the sender in its trust store. ``trust_key`` is the
    receiver's trust key stored on this side. Returns a result dict with
    ``bytes`` sent, ``elapsed`` seconds and the achieved ``mbps``.
    """
    size = os.path.getsize(path)
    name = os.path.basename(path)
    on_progress = on_progress or (lambda sent, total: None)
    nonce8 = os.urandom(crypto.CHUNK_NONCE_PREFIX_BYTES)
    key = crypto.derive_transfer_key(trust_key, nonce8)
    header = {
        "type": "transfer",
        "name": name,
        "size": size,
        "fp": sender_fingerprint,
        "nonce8": base64.b64encode(nonce8).decode("ascii"),
        "chunk_size": chunk_size,
    }

    started = time.monotonic()
    sent = 0
    with socket.create_connection((host, port), timeout=SOCK_TIMEOUT) as sock:
        sock.settimeout(SOCK_TIMEOUT)
        header_bytes = send_frame(sock, header)
        try:
            with open(path, "rb") as f:
                index = 0
                while True:
                    block = f.read(chunk_size)
                    if not block:
                        break
                    nonce = crypto.chunk_nonce(nonce8, index)
                    ct = crypto.encrypt_with_nonce(key, nonce, block, aad=header_bytes)
                    sock.sendall(struct.pack(">Q", len(ct)) + ct)
                    index += 1
                    sent += len(block)
                    on_progress(sent, size)
        except OSError as exc:
            reason = _pending_error(sock)
            if reason is not None:
                raise TransferRefusedError(reason) from exc
            raise
        ack_raw = recv_frame(sock)
    try:
        ack = json.loads(ack_raw.decode("utf-8"))
    except ValueError:
        raise ProtocolError("malformed acknowledgment")
    if ack.get("type") != "ok":
        raise TransferRefusedError(ack.get("message", "transfer refused"))
    elapsed = time.monotonic() - started
    mbps = (size / (1024 * 1024)) / elapsed if elapsed > 0 else 0.0
    return {"bytes": sent, "elapsed": elapsed, "mbps": mbps}


class TransferServer:
    """Listens for incoming transfers and other framed messages.

    Unknown message types are delegated to ``on_other`` (used by the
    pairing manager): ``on_other(conn, header, header_bytes, addr)``.
    """

    def __init__(
        self,
        store: TrustStore,
        port: int = DEFAULT_PORT,
        download_dir: str | None = None,
        on_transfer_start=None,
        on_progress=None,
        on_transfer_complete=None,
        on_error=None,
        on_other=None,
    ):
        self.store = store
        self.port = port
        self.download_dir = download_dir or default_download_dir()
        self.on_transfer_start = on_transfer_start or (lambda info: None)
        self.on_progress = on_progress or (lambda info, received, total: None)
        self.on_transfer_complete = on_transfer_complete or (lambda info: None)
        self.on_error = on_error or (lambda exc: None)
        self.on_other = on_other
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> int:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        last_err = None
        for port in range(self.port, self.port + 20):
            try:
                sock.bind(("0.0.0.0", port))
                self.port = port
                last_err = None
                break
            except OSError as exc:
                last_err = exc
        if last_err is not None:
            sock.close()
            raise last_err
        sock.listen(8)
        sock.settimeout(1.0)
        self._sock = sock
        os.makedirs(self.download_dir, exist_ok=True)
        self._thread = threading.Thread(
            target=self._accept_loop, name="transfer-server", daemon=True
        )
        self._thread.start()
        return self.port

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._handle_connection,
                args=(conn, addr),
                name="transfer-conn",
                daemon=True,
            ).start()

    def _handle_connection(self, conn: socket.socket, addr: tuple) -> None:
        conn.settimeout(SOCK_TIMEOUT)
        owned = False
        try:
            header_bytes = recv_frame(conn)
            header = json.loads(header_bytes.decode("utf-8"))
            mtype = header.get("type")
            if mtype == "transfer":
                self._handle_transfer(conn, header, header_bytes)
            elif self.on_other is not None:
                # on_other returns True when it takes ownership of the
                # connection (pairing sessions keep it open across messages).
                owned = bool(self.on_other(conn, header, header_bytes, addr))
            else:
                send_frame(
                    conn,
                    {"type": "error", "code": "unknown", "message": "unknown message type"},
                )
        except ProtocolError as exc:
            self.on_error(exc)
        except (OSError, ValueError, InvalidTag) as exc:
            self.on_error(exc)
        finally:
            if not owned:
                try:
                    conn.close()
                except OSError:
                    pass

    def _handle_transfer(
        self,
        conn: socket.socket,
        header: dict,
        header_bytes: bytes,
    ) -> None:
        fingerprint = header.get("fp", "")
        peer = self.store.get_peer(fingerprint)
        if peer is None:
            send_frame(
                conn,
                {"type": "error", "code": "not_paired", "message": "device is not paired"},
            )
            return
        try:
            nonce8 = base64.b64decode(header["nonce8"])
            chunk_size = int(header.get("chunk_size", CHUNK_SIZE))
            size = int(header.get("size", -1))
            name = os.path.basename(str(header.get("name", "unknown")))
        except (KeyError, ValueError, TypeError):
            send_frame(conn, {"type": "error", "code": "bad_header", "message": "malformed header"})
            return
        if size < 0 or size > (1 << 42) or chunk_size > MAX_CHUNK:
            send_frame(conn, {"type": "error", "code": "bad_header", "message": "unreasonable sizes"})
            return
        if len(nonce8) != crypto.CHUNK_NONCE_PREFIX_BYTES:
            send_frame(conn, {"type": "error", "code": "bad_header", "message": "bad nonce"})
            return

        key = crypto.derive_transfer_key(peer["trust_key"], nonce8)
        out_path = os.path.join(self.download_dir, name)
        os.makedirs(self.download_dir, exist_ok=True)
        self.on_transfer_start(
            {
                "name": name,
                "size": size,
                "from": peer.get("name", fingerprint[:8]),
                "fingerprint": fingerprint,
            }
        )
        received = 0
        index = 0
        try:
            with open(out_path, "wb") as out:
                while received < size:
                    (chunk_len,) = struct.unpack(">Q", recv_exact(conn, 8))
                    if chunk_len == 0 or chunk_len > chunk_size + GCM_OVERHEAD or chunk_len > MAX_CHUNK:
                        raise ProtocolError("invalid chunk length")
                    ct = recv_exact(conn, chunk_len)
                    nonce = crypto.chunk_nonce(nonce8, index)
                    try:
                        block = crypto.decrypt_with_nonce(key, nonce, ct, aad=header_bytes)
                    except InvalidTag:
                        raise AuthFailedError("chunk authentication failed")
                    if len(block) > chunk_size:
                        raise ProtocolError("chunk larger than declared")
                    out.write(block)
                    received += len(block)
                    if received > size:
                        raise ProtocolError("received more data than declared")
                    index += 1
                    self.on_progress(
                        {
                            "name": name,
                            "size": size,
                            "from": peer.get("name", fingerprint[:8]),
                            "fingerprint": fingerprint,
                        },
                        received,
                        size,
                    )
        except (ProtocolError, InvalidTag):
            try:
                os.remove(out_path)
            except OSError:
                pass
            send_frame(conn, {"type": "error", "code": "auth_failed", "message": "transfer failed"})
            raise
        if received != size:
            try:
                os.remove(out_path)
            except OSError:
                pass
            send_frame(conn, {"type": "error", "code": "short", "message": "transfer ended early"})
            raise ProtocolError("transfer ended early")
        send_frame(conn, {"type": "ok", "bytes": received})
        self.on_transfer_complete(
            {"name": name, "size": received, "path": out_path, "fingerprint": fingerprint}
        )