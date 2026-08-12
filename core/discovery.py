"""LAN discovery via mDNS/DNS-SD (zeroconf).

Advertises the SecureShare service on all local interfaces and browses
for peers, replacing the old raw UDP broadcast approach.

Resolution is deliberately done in a dedicated polling thread rather than
inside the browser callbacks: zeroconf's blocking ``get_service_info``
cannot be called from the browser thread without deadlocking it.
"""

import ipaddress
import re
import socket
import threading

from zeroconf import ServiceBrowser, ServiceInfo, ServiceStateChange, Zeroconf

SERVICE_TYPE = "_secureshare._tcp.local."
RESOLVE_INTERVAL = 1.0


def _pick_address(info: ServiceInfo) -> str | None:
    """First usable address from a resolved service.

    Prefers IPv4 and skips addresses that can never be connected to from
    another host (link-local IPv6 like fe80:: needs a zone index and
    routinely fails with "No route to host").
    """
    v4: list[str] = []
    v6: list[str] = []
    for a in info.parsed_addresses():
        try:
            ip = ipaddress.ip_address(a)
        except ValueError:
            continue
        if ip.is_unspecified or ip.is_multicast or ip.is_link_local or ip.is_loopback:
            continue
        (v4 if ip.version == 4 else v6).append(str(ip))
    for candidate in v4 + v6:
        return candidate
    return None


def sanitize(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "-", name).strip("-") or "device"
    return cleaned[:50]


def _local_ip_bytes() -> bytes:
    """Best-effort primary LAN IPv4 address for the mDNS A record."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return socket.inet_aton(s.getsockname()[0])
        finally:
            s.close()
    except OSError:
        return socket.inet_aton("127.0.0.1")


class Peer:
    __slots__ = ("name", "fingerprint", "host", "port", "service")

    def __init__(self, name, fingerprint, host, port, service):
        self.name = name
        self.fingerprint = fingerprint
        self.host = host
        self.port = port
        self.service = service

    def __repr__(self):
        return f"<Peer {self.name} {self.fingerprint[:8]} @ {self.host}:{self.port}>"


class Discovery:
    """Advertise a SecureShare service and keep a registry of discovered peers."""

    def __init__(self, name: str, fingerprint: str, port: int, on_change=None):
        self.name = name
        self.fingerprint = fingerprint
        self.port = port
        self.on_change = on_change or (lambda: None)
        self._zc: Zeroconf | None = None
        self._info: ServiceInfo | None = None
        self._browser: ServiceBrowser | None = None
        self._lock = threading.Lock()
        self._peers: dict[str, Peer] = {}
        self._pending: dict[str, int] = {}  # service name -> failed attempts
        self._stop = threading.Event()
        self._resolve_thread: threading.Thread | None = None

    def start(self) -> None:
        if self._resolve_thread is not None and self._resolve_thread.is_alive():
            raise RuntimeError(
                "Discovery.start() called while the resolve thread is still "
                "running; call stop() first"
            )
        self._stop.clear()
        service_name = f"{sanitize(self.name)}-{self.fingerprint[:8]}.{SERVICE_TYPE}"
        self._info = ServiceInfo(
            SERVICE_TYPE,
            service_name,
            port=self.port,
            addresses=[_local_ip_bytes()],
            properties={
                "name": self.name.encode("utf-8"),
                "fp": self.fingerprint.encode("ascii"),
            },
        )
        self._zc = Zeroconf()
        self._zc.register_service(self._info)
        self._browser = ServiceBrowser(
            self._zc,
            SERVICE_TYPE,
            handlers=[self._on_service_state_change],
        )
        self._resolve_thread = threading.Thread(
            target=self._resolve_loop, name="mcast-resolve", daemon=True
        )
        self._resolve_thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            if self._browser is not None:
                self._browser.cancel()
            if self._zc is not None and self._info is not None:
                self._zc.unregister_service(self._info)
            if self._zc is not None:
                self._zc.close()
        except Exception:
            pass
        self._zc = None
        self._browser = None
        if self._resolve_thread is not None:
            self._resolve_thread.join(timeout=2.0)
            if self._resolve_thread.is_alive():
                print(
                    "[discovery] resolve thread did not exit within timeout",
                    flush=True,
                )
            self._resolve_thread = None

    # -- zeroconf events (must stay light: never call get_service_info here) --

    def _on_service_state_change(
        self, zeroconf: Zeroconf, service_type: str, name: str, state_change: ServiceStateChange
    ) -> None:
        if self._info is not None and name == self._info.name:
            return
        if state_change == ServiceStateChange.Removed:
            self._drop_service(name)
        elif state_change in (ServiceStateChange.Added, ServiceStateChange.Updated):
            with self._lock:
                # re-resolve if we don't have a peer for this service yet
                if not any(p.service == name for p in self._peers.values()):
                    self._pending.setdefault(name, 0)
            import os as _os
            if _os.environ.get("SECURESHARE_DEBUG"):
                print(f"[discovery] {state_change.name} {name}", flush=True)

    def _drop_service(self, name: str) -> None:
        self._lock.acquire()
        removed = [fp for fp, p in self._peers.items() if p.service == name]
        for fp in removed:
            del self._peers[fp]
        removed_pending = name in self._pending
        if removed_pending:
            del self._pending[name]
        self._lock.release()
        if removed or removed_pending:
            self.on_change()  # notify only when something actually changed

    # -- periodic resolution thread (blocking get_service_info is safe here) --

    def _resolve_loop(self) -> None:
        while not self._stop.is_set():
            self._stop.wait(RESOLVE_INTERVAL)
            to_resolve: list[str] = []
            with self._lock:
                to_resolve = list(self._pending.keys())
            for service_name in to_resolve:
                # drop the pending entry that is handled elsewhere
                if service_name not in self._pending:
                    continue
                info = self._resolve(service_name)
                if info is not None:
                    name, fp = self._props(info)
                    host = _pick_address(info)
                    if host is None:
                        # Service announcements can briefly arrive before an
                        # address record (or just after a Wi-Fi/VPN change).
                        # Keep trying; dropping it here leaves one-way
                        # discovery until the peer happens to advertise again.
                        with self._lock:
                            self._pending[service_name] = self._pending.get(service_name, 0) + 1
                        import os as _os
                        if _os.environ.get("SECURESHARE_DEBUG"):
                            print(f"[discovery] resolve {service_name}: no usable address", flush=True)
                        continue
                    with self._lock:
                        self._peers[fp] = Peer(name, fp, host, info.port, info.name)
                        self._pending.pop(info.name, None)
                    import os as _os
                    if _os.environ.get("SECURESHARE_DEBUG"):
                        print(f"[discovery] RESOLVED {service_name} -> {name} {host}:{info.port}", flush=True)
                    self.on_change()
                else:
                    import os as _os
                    with self._lock:
                        attempts = self._pending.get(service_name, 0) + 1
                    if _os.environ.get("SECURESHARE_DEBUG"):
                        print(f"[discovery] resolve {service_name} failed (attempt {attempts})", flush=True)
                    with self._lock:
                        # Do not give up after an arbitrary number of mDNS
                        # attempts. A peer may come online after its service
                        # name was first observed, without emitting another
                        # browser event on every network stack.
                        self._pending[service_name] = attempts

    def _resolve(self, service_name: str) -> ServiceInfo | None:
        """Resolve a service with a live DNS query, cache only as fallback.

        A live query returns the peer's *current* advertised address, so a
        stale cache entry (peer roamed networks, DHCP renewal, VPN on/off)
        cannot make us connect to an unreachable address.
        """
        try:
            return self._zc.get_service_info(SERVICE_TYPE, service_name)
        except Exception:
            pass
        try:
            cached = ServiceInfo(SERVICE_TYPE, service_name)
            if cached.load_from_cache(self._zc):
                return cached
        except Exception:
            pass
        return None

    @staticmethod
    def _props(info: ServiceInfo) -> tuple[str, str]:
        props = info.properties or {}
        pname = props.get(b"name", props.get("name", b""))
        pfp = props.get(b"fp", props.get("fp", b""))
        if isinstance(pname, bytes):
            pname = pname.decode("utf-8", "replace")
        if isinstance(pfp, bytes):
            pfp = pfp.decode("ascii", "replace")
        return str(pname), str(pfp)

    # -- registry -------------------------------------------------------------

    def peers(self) -> dict[str, Peer]:
        with self._lock:
            return dict(self._peers)

    def find(self, fingerprint: str) -> Peer | None:
        with self._lock:
            return self._peers.get(fingerprint)
