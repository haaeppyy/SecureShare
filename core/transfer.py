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
import shutil
import socket
import struct
import tempfile
import threading
import time

from cryptography.exceptions import InvalidTag

from . import crypto
from .limits import ConnectionLimiter, address_allowed, parse_subnets
from .trust_store import TrustStore

MAX_HEADER = 1 << 20  # 1 MiB
MAX_CHUNK = 1 << 22   # 4 MiB guard
CHUNK_SIZE = 1 << 20  # 1 MiB default
GCM_OVERHEAD = 16     # AES-GCM auth tag bytes
DEFAULT_PORT = 48620
SOCK_TIMEOUT = 30.0
MAX_TRANSFER_SIZE = 10 * (1 << 30)  # 10 GiB default cap
MIN_FREE_SPACE = 1 << 20             # 1 MiB free-space margin
_PATH_LOCK = threading.Lock()


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
        max_transfer_size: int | None = None,
        trusted_subnets=None,
    ):
        self.store = store
        self.port = port
        self.download_dir = download_dir or default_download_dir()
        self.max_transfer_size = max_transfer_size if max_transfer_size is not None else MAX_TRANSFER_SIZE
        self.trusted_subnets = parse_subnets(trusted_subnets)
        self.limiter = ConnectionLimiter()
        self.on_transfer_start = on_transfer_start or (lambda info: None)
        self.on_progress = on_progress or (lambda info, received, total: None)
        self.on_transfer_complete = on_transfer_complete or (lambda info: None)
        self.on_error = on_error or (lambda exc: None)
        self.on_other = on_other
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._claimed: set[str] = set()  # final paths reserved by in-flight transfers
        self._claim_lock = threading.Lock()

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
            # This listener also carries KVM and clipboard channels.  Keep
            # interactive control frames out of Nagle's small-write buffer.
            try:
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
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
            if not address_allowed(addr, self.trusted_subnets):
                try:
                    send_frame(
                        conn,
                        {"type": "error", "code": "refused", "message": "connection not allowed"},
                    )
                except OSError:
                    pass
                return
            if not self.limiter.enter(addr):
                try:
                    send_frame(
                        conn,
                        {"type": "error", "code": "busy", "message": "too many connections"},
                    )
                except OSError:
                    pass
                return
            try:
                if not self.limiter.allow_request(addr):
                    try:
                        send_frame(
                            conn,
                            {"type": "error", "code": "rate_limited", "message": "too many requests"},
                        )
                    except OSError:
                        pass
                    return
                header_bytes = recv_frame(conn)
            finally:
                self.limiter.leave(addr)
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
        if size > self.max_transfer_size:
            send_frame(
                conn,
                {"type": "error", "code": "too_large", "message": "transfer exceeds the maximum allowed size"},
            )
            return
        try:
            free = shutil.disk_usage(self.download_dir).free
        except OSError:
            free = 0
        if free < size + MIN_FREE_SPACE:
            send_frame(
                conn,
                {"type": "error", "code": "no_space", "message": "not enough free disk space"},
            )
            return

        key = crypto.derive_transfer_key(peer["trust_key"], nonce8)
        # Reserve a final path that does not exist yet (suffix -1, -2, ...
        # on collision). The claim keeps two concurrent same-name transfers
        # from racing to the same final path. It is released on every exit
        # path via the outer finally.
        os.makedirs(self.download_dir, exist_ok=True)
        out_path = self._reserve_path(name)
        try:
            info = {
                "name": os.path.basename(out_path),
                "size": size,
                "from": peer.get("name", fingerprint[:8]),
                "fingerprint": fingerprint,
            }
            self.on_transfer_start(info)
            # Write to a unique temporary file in the same directory, then
            # atomically rename it to out_path only after every chunk has
            # been authenticated and the received size matches. A failure
            # deletes only the temporary file - a pre-existing file at
            # out_path is never opened or removed (out_path is guaranteed
            # not to exist).
            fd, tmp_path = tempfile.mkstemp(
                prefix=f".{os.path.basename(out_path)}.part-", dir=self.download_dir
            )
            received = 0
            index = 0
            try:
                with os.fdopen(fd, "wb") as out:
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
                        self.on_progress(info, received, size)
                    out.flush()
                    os.fsync(out.fileno())
            except (ProtocolError, InvalidTag):
                self._cleanup_tmp(tmp_path)
                send_frame(conn, {"type": "error", "code": "auth_failed", "message": "transfer failed"})
                raise
            if received != size:
                self._cleanup_tmp(tmp_path)
                send_frame(conn, {"type": "error", "code": "short", "message": "transfer ended early"})
                raise ProtocolError("transfer ended early")
            try:
                os.replace(tmp_path, out_path)
            except OSError as exc:
                self._cleanup_tmp(tmp_path)
                send_frame(conn, {"type": "error", "code": "write_failed", "message": "could not write file"})
                raise ProtocolError(f"could not write {out_path}: {exc}") from exc
            send_frame(conn, {"type": "ok", "bytes": received})
            self.on_transfer_complete(
                {
                    "name": os.path.basename(out_path),
                    "size": received,
                    "path": out_path,
                    "fingerprint": fingerprint,
                }
            )
        finally:
            self._release_path(out_path)

    def _reserve_path(self, name: str) -> str:
        """Final path that does not exist and is not claimed by another
        transfer in flight; appends -1, -2, ... until free."""
        name = os.path.basename(name)
        base, ext = os.path.splitext(name)
        with self._claim_lock:
            candidate = os.path.join(self.download_dir, name)
            index = 1
            while os.path.exists(candidate) or candidate in self._claimed:
                candidate = os.path.join(self.download_dir, f"{base}-{index}{ext}")
                index += 1
            self._claimed.add(candidate)
            return candidate

    def _release_path(self, path: str) -> None:
        with self._claim_lock:
            self._claimed.discard(path)

    @staticmethod
    def _cleanup_tmp(tmp_path: str) -> None:
        """Delete only the temporary file; never touch the final path."""
        try:
            os.remove(tmp_path)
        except OSError:
            pass
