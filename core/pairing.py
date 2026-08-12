"""ECDH pairing handshake with out-of-band PIN verification.

First-time connection between two devices:

1. Both sides generate an ephemeral ECDH (SECP256R1) key pair.
2. Public keys are exchanged over the LAN TCP connection.
3. Both derive the shared secret (ECDH) and a long-term trust key (HKDF).
4. Each side shows the same 6-digit PIN (hash of the shared secret) in its
   tray UI. The human confirms the codes match (Bluetooth/Signal-style
   out-of-band verification) before trust is stored - this is what defeats
   a man-in-the-middle on the LAN, because an attacker who swapped public
   keys would produce different PINs on the two screens.
5. Only after confirmation is the trust key stored, keyed by the other
   device's persistent fingerprint UUID.
"""

import json
import socket
import threading

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import crypto
from .transfer import ProtocolError, recv_frame, send_frame

PAIR_TIMEOUT = 60.0


class PairingError(Exception):
    pass


class PairingDenied(Exception):
    pass


def _new_keypair():
    return ec.generate_private_key(ec.SECP256R1())


def _pubkey_pem(key) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def _load_pubkey(pem: str):
    try:
        return serialization.load_pem_public_key(pem.encode("ascii"))
    except Exception as exc:
        raise PairingError("invalid public key received") from exc


def _shared_secret(my_priv, peer_pub) -> bytes:
    return my_priv.exchange(ec.ECDH(), peer_pub)


class PairingSession:
    """A pairing handshake in progress; driven by tray menu actions."""

    def __init__(self, store, conn, role, peer_name, peer_fp, peer_pub_pem, my_priv=None):
        self.store = store
        self.conn = conn
        self.role = role  # "initiator" | "responder"
        self.peer_name = peer_name
        self.peer_fp = peer_fp
        self.peer_fp_short = peer_fp[:8]
        self.state = "pending"  # pending -> awaiting_confirm / awaiting_accept -> done/denied
        self._my_priv = my_priv or _new_keypair()
        self._peer_pub = None
        self.shared_secret = None
        self.trust_key = None
        self.pin = None
        self.error = None
        try:
            peer_pub = _load_pubkey(peer_pub_pem)
            self.shared_secret = _shared_secret(self._my_priv, peer_pub)
            self.trust_key = crypto.derive_trust_key(self.shared_secret)
            self.pin = crypto.derive_pin(self.shared_secret)
        except PairingError as exc:
            self.error = str(exc)

    @property
    def my_pubkey_pem(self) -> str:
        return _pubkey_pem(self._my_priv)

    @property
    def insession(self) -> bool:
        return self.error is None and self.shared_secret is not None

    def _send(self, obj: dict) -> None:
        try:
            send_frame(self.conn, obj)
        except OSError as exc:
            raise PairingError(f"connection lost: {exc}") from exc

    # -- responder side ------------------------------------------------------

    def accept(self) -> None:
        """Responder accepts after the human verified the PIN on both screens."""
        if self.role != "responder":
            raise PairingError("accept() is only valid on the responder side")
        self._send({"type": "pair_response", "name": self.store.identity["name"], "fp": self.store.fingerprint(), "pubkey": self.my_pubkey_pem})
        self.state = "awaiting_confirm"
        threading.Thread(target=self._wait_for_confirm, daemon=True, name="pair-wait").start()

    def deny(self) -> None:
        self._send({"type": "pair_denied", "message": "user denied pairing"})
        self.state = "denied"

    def _wait_for_confirm(self) -> None:
        try:
            raw = recv_frame(self.conn)
            reply = json.loads(raw.decode("utf-8"))
            if reply.get("type") == "pair_confirm":
                self.store.add_peer(self.peer_fp, self.peer_name, self.trust_key)
                self.state = "done"
            else:
                self.state = "denied"
        except (OSError, ProtocolError, ValueError) as exc:
            self.error = str(exc)
            self.state = "denied"

    # -- initiator side -----------------------------------------------------

    def confirm(self, matches: bool) -> None:
        """Initiator confirms (or refutes) that the PINs shown match."""
        if self.role != "initiator":
            raise PairingError("confirm() only valid on the initiator side")
        if matches:
            self._send({"type": "pair_confirm"})
            self.store.add_peer(self.peer_fp, self.peer_name, self.trust_key)
            self.state = "confirmed"
        else:
            self._send({"type": "pair_denied", "message": "PIN mismatch"})
            self.state = "denied"

    def abort(self) -> None:
        try:
            self.conn.close()
        except OSError:
            pass
        self.state = "denied"

    def close(self) -> None:
        try:
            self.conn.close()
        except OSError:
            pass


class PairingManager:
    """Creates PairingSessions: initiates toward a peer or responds to requests.

    ``on_session(session)`` is invoked whenever a new session enters a state
    the UI must react to (new PIN to approve, confirmation awaited).
    """

    def __init__(self, store, on_session=None):
        self.store = store
        self.on_session = on_session or (lambda s: None)

    # -- responder entry point (called by TransferServer.on_other) ----------

    def on_pair_request(self, conn, header, header_bytes, addr) -> None:
        if header.get("type") != "pair_request":
            send_error(conn, "expected pair_request")
            return
        peer_name = str(header.get("name", "unknown"))
        peer_fp = str(header.get("fp", ""))
        pub_pem = str(header.get("pubkey", ""))
        if not peer_fp or not pub_pem:
            send_error(conn, "malformed pairing request")
            return
        session = PairingSession(self.store, conn, "responder", peer_name, peer_fp, pub_pem)
        if session.error:
            session.close()
            send_error(conn, session.error)
            return
        self.on_session(session)

    # -- initiator entry point (called from the tray) -----------------------

    def initiate(self, host: str, port: int) -> PairingSession:
        """Connect to the peer and start a pairing handshake (blocking)."""
        try:
            conn = socket.create_connection((host, port), timeout=PAIR_TIMEOUT)
        except OSError as exc:
            raise PairingError(f"cannot reach peer {host}:{port}: {exc}") from exc
        conn.settimeout(PAIR_TIMEOUT)
        my_priv = _new_keypair()
        try:
            send_frame(
                conn,
                {
                    "type": "pair_request",
                    "name": self.store.identity["name"],
                    "fp": self.store.fingerprint(),
                    "pubkey": _pubkey_pem(my_priv),
                },
            )
            raw = recv_frame(conn)
            reply = json.loads(raw.decode("utf-8"))
        except (OSError, ProtocolError, ValueError) as exc:
            conn.close()
            raise PairingError(f"pairing handshake failed: {exc}") from exc
        if reply.get("type") == "pair_denied":
            conn.close()
            raise PairingDenied(reply.get("message", "peer denied pairing"))
        if reply.get("type") != "pair_response":
            conn.close()
            raise PairingError("unexpected pairing response")
        session = PairingSession(
            self.store,
            conn,
            "initiator",
            str(reply.get("name", "unknown")),
            str(reply.get("fp", "")),
            str(reply.get("pubkey", "")),
            my_priv=my_priv,
        )
        if session.error:
            session.close()
            raise PairingError(session.error)
        session.state = "awaiting_confirm"
        self.on_session(session)
        return session


def send_error(conn, message: str) -> None:
    try:
        send_frame(conn, {"type": "error", "code": "pairing", "message": message})
    except OSError:
        pass