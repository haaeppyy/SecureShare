"""Listener admission helpers: trusted-subnet parsing and per-IP limits."""

import ipaddress
import threading
import time

DEFAULT_PER_IP_CONNECTIONS = 8
RATE_WINDOW = 1.0
RATE_MAX_PER_IP = 40  # unauthenticated requests per second per IP


def parse_subnets(spec: str | None) -> list:
    """Parse a comma/space-separated CIDR list; empty/None -> allow all."""
    if not spec:
        return []
    out = []
    for part in str(spec).replace(";", ",").replace(" ", ",").split(","):
        part = part.strip()
        if not part:
            continue
        out.append(ipaddress.ip_network(part, strict=False))
    return out


def address_allowed(addr: tuple, subnets: list) -> bool:
    """True when no subnets were configured or the peer is inside one."""
    if not subnets:
        return True
    try:
        ip = ipaddress.ip_address(addr[0])
    except ValueError:
        return False
    return any(ip in net for net in subnets)


class ConnectionLimiter:
    """Per-IP concurrent-connection cap and a token-bucket request limiter.

    Guards the listener against LAN denial-of-service from unauthenticated
    connections: no single source may hold more than ``max_per_ip``
    connections or send more than ``rate_max`` frames per second.
    """

    def __init__(self, max_per_ip: int = DEFAULT_PER_IP_CONNECTIONS, rate_max: int = RATE_MAX_PER_IP):
        self.max_per_ip = max_per_ip
        self.rate_max = rate_max
        self._lock = threading.Lock()
        self._counts: dict[str, int] = {}
        self._buckets: dict[str, tuple[float, int]] = {}

    def enter(self, addr: tuple) -> bool:
        """Register a new connection; False when the per-IP cap is exceeded."""
        key = addr[0]
        with self._lock:
            n = self._counts.get(key, 0)
            if n >= self.max_per_ip:
                return False
            self._counts[key] = n + 1
            return True

    def leave(self, addr: tuple) -> None:
        key = addr[0]
        with self._lock:
            n = self._counts.get(key, 0)
            if n <= 1:
                self._counts.pop(key, None)
            else:
                self._counts[key] = n - 1

    def allow_request(self, addr: tuple) -> bool:
        """Token-bucket admission for one frame from this IP."""
        key = addr[0]
        now = time.monotonic()
        with self._lock:
            refill, tokens = self._buckets.get(key, (now, self.rate_max))
            tokens = min(self.rate_max, tokens + (now - refill) * self.rate_max)
            if tokens < 1:
                self._buckets[key] = (now, tokens)
                return False
            self._buckets[key] = (now, tokens - 1)
            return True