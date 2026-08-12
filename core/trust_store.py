"""Persistent paired-device store.

Trust keys are stored at rest in an OS-appropriate app-data directory,
encrypted with a Fernet key derived from a keyring-managed master secret
(Windows Credential Manager / macOS Keychain). If keyring is unavailable
we fall back to a plaintext file with restrictive permissions.

Tradeoff (documented in README): keyring keeps trust keys cryptographically
protected at rest, but adds a Keychain/Credential-Manager dependency and can
fail in headless or restricted environments; the fallback trades at-rest
encryption for availability, relying on restrictive file permissions.
"""

import base64
import datetime
import json
import os
import socket
import sys
import threading
import uuid

from cryptography.fernet import Fernet, InvalidToken

APP_DIR_NAME = "SecureShare"
SERVICE_NAME = "SecureShare"
KEYRING_USERNAME = "trust-master"


class KeyringUnavailable(Exception):
    pass


def default_data_dir() -> str:
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
    elif sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Application Support")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, APP_DIR_NAME)


def _keyring_fetch() -> bytes:
    """Return a 32-byte master secret from the OS keyring, creating it on first use."""
    import keyring

    raw = keyring.get_password(SERVICE_NAME, KEYRING_USERNAME)
    if raw is None:
        raw = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")
        keyring.set_password(SERVICE_NAME, KEYRING_USERNAME, raw)
    master = base64.urlsafe_b64decode(raw.encode("ascii"))
    if len(master) != 32:
        raise KeyringUnavailable("existing keyring entry has unexpected length")
    return master


class TrustStore:
    """Local store of paired-device trust keys, keyed by device fingerprint."""

    def __init__(self, data_dir: str | None = None, keyring_enabled: bool = True):
        self.data_dir = os.path.abspath(data_dir or default_data_dir())
        os.makedirs(self.data_dir, exist_ok=True)
        self._path = os.path.join(self.data_dir, "trust.json")
        self._keyring_enabled = keyring_enabled
        self._lock = threading.RLock()
        self.encrypted = False
        self.keyring_used = False
        self.identity = {"fingerprint": str(uuid.uuid4()), "name": socket.gethostname()}
        self.sync_enabled = False
        self.kvm_enabled = False
        self.peers: dict[str, dict] = {}
        self._load()

    # -- keyring helpers -----------------------------------------------------

    def _fernet_key(self) -> bytes:
        if not self._keyring_enabled:
            raise KeyringUnavailable("keyring disabled")
        return base64.urlsafe_b64encode(_keyring_fetch())

    # -- serialization -------------------------------------------------------

    def _to_payload(self) -> dict:
        peers = {
            fp: {
                "name": p["name"],
                "trust_key": base64.b64encode(p["trust_key"]).decode("ascii"),
                "paired_date": p["paired_date"],
                "kvm_allowed": bool(p.get("kvm_allowed", False)),
                "kvm_side": p.get("kvm_side", "right"),
            }
            for fp, p in self.peers.items()
        }
        return {
            "identity": self.identity,
            "peers": peers,
            "sync_enabled": bool(self.sync_enabled),
            "kvm_enabled": bool(self.kvm_enabled),
            "encrypted": False,
            "version": 1,
        }

    def _from_payload(self, payload: dict) -> None:
        self.identity.update(payload.get("identity") or {})
        peers = payload.get("peers") or {}
        self.peers = {
            fp: {
                "name": p.get("name", fp),
                "trust_key": base64.b64decode(p["trust_key"].encode("ascii")),
                "paired_date": p.get("paired_date", ""),
                "kvm_allowed": bool(p.get("kvm_allowed", False)),
                "kvm_side": p.get("kvm_side", "right"),
            }
            for fp, p in peers.items()
        }
        self.sync_enabled = bool(payload.get("sync_enabled", False))
        self.kvm_enabled = bool(payload.get("kvm_enabled", False))

    def _load(self) -> None:
        if not os.path.exists(self._path):
            return
        try:
            with open(self._path, "rb") as f:
                raw = f.read()
        except OSError:
            return
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            # Not ours (or corrupt). Leave a fresh store; do not destroy the file.
            return
        if payload.get("encrypted"):
            try:
                key = self._fernet_key()
                blob = payload.get("blob")
                if not blob:
                    return
                plain = Fernet(key).decrypt(blob.encode("ascii"))
                payload = json.loads(plain.decode("utf-8"))
                self.keyring_used = True
                self.encrypted = True
            except (InvalidToken, KeyringUnavailable, ValueError, TypeError):
                # Keyring gone or wrong secret: start empty rather than crash.
                return
        self._from_payload(payload)

    def save(self) -> None:
        with self._lock:
            payload = self._to_payload()
            try:
                key = self._fernet_key()
                blob = Fernet(key).encrypt(json.dumps(payload).encode("utf-8"))
                payload_bytes = json.dumps(
                    {"encrypted": True, "blob": blob.decode("ascii")}
                ).encode("utf-8")
                self.keyring_used = True
                self.encrypted = True
            except KeyringUnavailable:
                payload_bytes = json.dumps(payload).encode("utf-8")
                self.keyring_used = False
                self.encrypted = False
            tmp = self._path + ".tmp"
            with open(tmp, "wb") as f:
                f.write(payload_bytes)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self._path)

    # -- identity ------------------------------------------------------------

    def fingerprint(self) -> str:
        return self.identity["fingerprint"]

    def set_name(self, name: str) -> None:
        self.identity["name"] = name
        self.save()

    # -- peers --------------------------------------------------------------

    def is_paired(self, fingerprint: str) -> bool:
        return fingerprint in self.peers

    def get_peer(self, fingerprint: str) -> dict | None:
        return self.peers.get(fingerprint)

    def add_peer(self, fingerprint: str, name: str, trust_key: bytes) -> None:
        with self._lock:
            self.peers[fingerprint] = {
                "name": name,
                "trust_key": trust_key,
                "paired_date": datetime.datetime.now().isoformat(timespec="seconds"),
                "kvm_allowed": False,
                "kvm_side": "right",
            }
            self.save()

    def remove_peer(self, fingerprint: str) -> None:
        with self._lock:
            self.peers.pop(fingerprint, None)
            self.save()

    def list_peers(self) -> list[dict]:
        with self._lock:
            return [
                {
                    "fingerprint": fp,
                    "name": p["name"],
                    "paired_date": p.get("paired_date", ""),
                    "kvm_allowed": bool(p.get("kvm_allowed", False)),
                    "kvm_side": p.get("kvm_side", "right"),
                }
                for fp, p in self.peers.items()
            ]

    def set_sync_enabled(self, enabled: bool) -> None:
        self.sync_enabled = bool(enabled)
        self.save()

    def set_kvm_enabled(self, enabled: bool) -> None:
        self.kvm_enabled = bool(enabled)
        self.save()

    def set_peer_kvm_allowed(self, fingerprint: str, allowed: bool) -> None:
        """Record that this device permits ``fingerprint`` to take control
        of its keyboard and mouse."""
        with self._lock:
            peer = self.peers.get(fingerprint)
            if peer is None:
                return
            peer["kvm_allowed"] = bool(allowed)
            self.save()

    def set_peer_kvm_side(self, fingerprint: str, side: str) -> None:
        """Record which edge of this screen ``fingerprint`` sits at."""
        if side not in ("left", "right", "top", "bottom"):
            raise ValueError(f"bad kvm side {side!r}")
        with self._lock:
            peer = self.peers.get(fingerprint)
            if peer is None:
                return
            peer["kvm_side"] = side
            self.save()