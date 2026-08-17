"""Programmatic entry point used by tests and the tray app.

Composes discovery, trust store, pairing and sync into a runnable node.
The tray application adds pystray UI on top; tests use this without UI.
"""

import sys

from .discovery import Discovery
from .kvm import KVMEngine
from .pairing import PairingManager
from .sync import SyncEngine
from .transfer import DEFAULT_PORT, TransferServer, send_file as _send_file
from .trust_store import TrustStore


def default_kvm_platform():
    """Best available input platform for this OS, or None if unsupported."""
    if sys.platform == "darwin":
        from . import kvm_platform_mac

        return kvm_platform_mac.MacInputPlatform()
    if sys.platform == "win32":
        from . import kvm_platform_win

        return kvm_platform_win.WindowsInputPlatform()
    return None


class Node:
    """One SecureShare device: discovery + listener + pairing + sync."""

    def __init__(
        self,
        name=None,
        data_dir=None,
        port=DEFAULT_PORT,
        download_dir=None,
        keyring_enabled=True,
        on_status=None,
        on_incoming_pair=None,
        on_transfer_start=None,
        on_transfer_progress=None,
        on_transfer_complete=None,
        log=None,
        kvm_platform=None,
        max_transfer_size=None,
        trusted_subnets=None,
    ):
        self.log = log or (lambda msg: None)
        self.on_status = on_status or (lambda s: None)
        self.on_incoming_pair = on_incoming_pair or (lambda session: None)
        self.on_transfer_start = on_transfer_start or (lambda info: None)
        self.on_transfer_progress = on_transfer_progress or (lambda info, received, total: None)
        self.on_transfer_complete = on_transfer_complete or (lambda info: None)

        self.store = TrustStore(data_dir=data_dir, keyring_enabled=keyring_enabled)
        if name:
            self.store.set_name(name)
        self.discovery = Discovery(
            name=self.store.identity["name"],
            fingerprint=self.store.fingerprint(),
            port=port,
        )
        self.pairing = PairingManager(self.store, on_session=self._pairing_hook)

        self.server = TransferServer(
            store=self.store,
            port=port,
            download_dir=download_dir,
            on_transfer_start=self._t_start,
            on_progress=self._t_progress,
            on_transfer_complete=self._t_done,
            on_error=lambda exc: self.log(f"transfer error: {exc}"),
            on_other=self._on_other,
            max_transfer_size=max_transfer_size,
            trusted_subnets=trusted_subnets,
        )
        self.sync = SyncEngine(self.store, self.discovery, on_status=on_status)
        if kvm_platform is None:
            kvm_platform = default_kvm_platform()
        self.kvm = KVMEngine(self.store, self.discovery, platform=kvm_platform, on_status=on_status)

    # -- lifecycle -----------------------------------------------------------

    def start(self) -> int:
        self.server.start()
        self.discovery.port = self.server.port
        self.discovery.start()
        self.sync.start()
        self.kvm.start()
        self.log(f"started on port {self.server.port} as {self.store.identity['name']}")
        return self.server.port

    def stop(self) -> None:
        try:
            self.kvm.stop()
        except Exception:
            pass
        try:
            self.sync.stop()
        except Exception:
            pass
        try:
            self.discovery.stop()
        except Exception:
            pass
        try:
            self.server.stop()
        except Exception:
            pass

    # -- transfer ------------------------------------------------------------

    def send_file(self, peer_fingerprint: str, path: str, on_progress=None):
        """Send a file to a paired, discovered peer (must be paired already)."""
        peer = self.discovery.find(peer_fingerprint)
        if peer is None:
            raise RuntimeError(f"device {peer_fingerprint[:8]} not on network")
        if not self.store.is_paired(peer_fingerprint):
            raise RuntimeError("device is not paired; pair first")
        trust_key = self.store.get_peer(peer_fingerprint)["trust_key"]
        return _send_file(
            peer.host,
            peer.port,
            self.store.fingerprint(),
            trust_key,
            path,
            on_progress=on_progress,
        )

    # -- pairing -------------------------------------------------------------

    def pair_with(self, host: str, port: int):
        """Initiates pairing toward a discovered device (blocking until the
        peer replies; returns the session; the human confirms the PIN)."""
        session = self.pairing.initiate(host, port)
        self.on_status(f"Pairing with {session.peer_name}")
        return session

    def check_pin(self, session, matches: bool) -> None:
        session.confirm(matches)

    def _pairing_hook(self, session):
        self.on_incoming_pair(session)

    # -- listener dispatch ---------------------------------------------------

    def _t_start(self, info):
        self.log(f"receiving {info['name']} from {info['from']}")
        self.on_transfer_start(info)

    def _t_progress(self, info, received, total):
        self.on_transfer_progress(info, received, total)

    def _t_done(self, info):
        self.log(f"received {info['name']} -> {info['path']}")
        self.on_transfer_complete(info)

    def _on_other(self, conn, header, header_bytes, addr):
        mtype = header.get("type")
        if mtype == "pair_request":
            self.pairing.on_pair_request(conn, header, header_bytes, addr)
            return True  # pairing session owns the connection now
        elif mtype == "sync_open":
            self.sync.on_inbound(conn, header, header_bytes, addr)
            return False
        elif mtype == "kvm_open":
            self.kvm.on_inbound(conn, header, header_bytes, addr)
            return False
        else:
            from .transfer import send_frame

            try:
                send_frame(conn, {"type": "error", "code": "unsupported", "message": "unsupported"})
            except OSError:
                pass
            self.log(f"unsupported message {mtype} from {addr}")
            return False