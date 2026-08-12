"""Discovery test. mDNS on loopback is environment-dependent, so this test
skips (with a warning) rather than failing when the platform does not
propagate multicast between two instances on one host."""

import time

from core.discovery import Discovery


def test_discovery_finds_peer(tmp_path):
    d1 = Discovery("Alpha", "AAAA1111-0000-0000-0000-000000000001", 49700)
    d2 = Discovery("Beta", "BBBB2222-0000-0000-0000-000000000002", 49701)
    d1.start()
    d2.start()
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if d1.find("BBBB2222-0000-0000-0000-000000000002") and d2.find(
                "AAAA1111-0000-0000-0000-000000000001"
            ):
                break
            time.sleep(0.3)
        peer = d1.find("BBBB2222-0000-0000-0000-000000000002")
        if peer is None:
            import pytest

            pytest.skip("mDNS loopback did not resolve a peer on this host")
        assert peer.port == 49701
        assert peer.name == "Beta"
        assert peer.fingerprint == "BBBB2222-0000-0000-0000-000000000002"
    finally:
        d1.stop()
        d2.stop()


def test_discovery_restart_still_finds_peer(tmp_path):
    """Regression: stop() set the _stop event which start() never cleared,
    so a restarted Discovery stopped resolving services (resolve loop
    exited immediately)."""
    d1 = Discovery("Alpha", "AAAA1111-0000-0000-0000-000000000001", 49702)
    d2 = Discovery("Beta", "BBBB2222-0000-0000-0000-000000000002", 49703)
    d1.start()
    d2.start()
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if d1.find("BBBB2222-0000-0000-0000-000000000002"):
                break
            time.sleep(0.3)
        if d1.find("BBBB2222-0000-0000-0000-000000000002") is None:
            import pytest

            pytest.skip("mDNS loopback did not resolve a peer on this host")
        d1.stop()
        d2.stop()
        time.sleep(0.5)
        d1.start()
        d2.start()
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if d1.find("BBBB2222-0000-0000-0000-000000000002") and d2.find(
                "AAAA1111-0000-0000-0000-000000000001"
            ):
                break
            time.sleep(0.3)
        assert d1.find("BBBB2222-0000-0000-0000-000000000002") is not None
        assert d2.find("AAAA1111-0000-0000-0000-000000000001") is not None
    finally:
        d1.stop()
        d2.stop()


def test_sanitize():
    from core.discovery import sanitize

    assert sanitize("My Mac Book") == "My-Mac-Book"
    assert sanitize("a/b\\c:d") == "a-b-c-d"
    assert sanitize("!!!") == "device"


class _FakeInfo:
    def __init__(self, addresses):
        self._addresses = addresses

    def parsed_addresses(self):
        return list(self._addresses)


def test_pick_address_prefers_ipv4_and_skips_link_local():
    """Regression: a peer resolving first to an IPv6 link-local address
    (fe80::) failed with 'No route to host' on connect."""
    from core.discovery import _pick_address

    assert _pick_address(_FakeInfo(["192.168.0.6"])) == "192.168.0.6"
    assert _pick_address(_FakeInfo(["fe80::1abc", "192.168.0.6"])) == "192.168.0.6"
    assert _pick_address(_FakeInfo(["fe80::1abc"])) is None
    assert _pick_address(_FakeInfo(["127.0.0.1"])) is None
    assert _pick_address(_FakeInfo(["::", "fd00::1", "10.0.0.5"])) == "10.0.0.5"
    assert _pick_address(_FakeInfo([])) is None
