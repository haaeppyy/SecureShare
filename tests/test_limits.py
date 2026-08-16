"""Listener admission: trusted-subnet filtering and per-IP limits."""

import base64
import json
import os
import socket
import time

from core.limits import parse_subnets
from core.transfer import recv_frame, send_frame

from conftest import node_pair  # noqa: F401

import pytest


def test_parse_subnets_handles_formats():
    from core.limits import parse_subnets

    nets = parse_subnets("192.168.1.0/24, 10.0.0.0/8 ; 172.16.0.0/12")
    assert len(nets) == 3
    assert parse_subnets(None) == []
    assert parse_subnets("") == []


def test_address_allowed():
    from core.limits import address_allowed, parse_subnets

    subnets = parse_subnets("192.168.1.0/24")
    assert address_allowed(("192.168.1.7", 1), subnets)
    assert not address_allowed(("10.0.0.3", 1), subnets)
    assert not address_allowed(("not-an-ip", 1), subnets)
    assert address_allowed(("10.0.0.3", 1), [])  # no subnets -> allow all


def test_limiter_per_ip_cap():
    from core.limits import ConnectionLimiter

    limiter = ConnectionLimiter(max_per_ip=3)
    addr = ("10.0.0.1", 1000)
    assert limiter.enter(addr)
    assert limiter.enter(addr)
    assert limiter.enter(addr)
    assert not limiter.enter(addr), "fourth connection from one IP must be refused"
    limiter.leave(addr)
    assert limiter.enter(addr), "slot must free up after leave"


def test_limiter_rate_bucket():
    from core.limits import ConnectionLimiter

    limiter = ConnectionLimiter(rate_max=5)
    addr = ("10.0.0.2", 2000)
    allowed = [limiter.allow_request(addr) for _ in range(7)]
    assert allowed == [True] * 5 + [False] * 2, allowed


def test_trusted_subnets_refuse_connection(node_pair):
    """A connection from outside the configured subnets is refused before
    any frame is read."""
    assert node_pair.wait_discovery(timeout=20), "nodes must discover each other"
    peer_b = node_pair.test_peer(node_pair.a)
    node_pair.b.server.trusted_subnets = parse_subnets("10.99.0.0/16")
    sock = socket.create_connection((peer_b.host, peer_b.port), timeout=5)
    send_frame(sock, {"type": "transfer", "name": "x", "size": 1})
    reply = json.loads(recv_frame(sock).decode("utf-8"))
    assert reply["type"] == "error"
    assert reply["code"] == "refused"
    sock.close()


def test_trusted_subnets_allow_peer_host(node_pair):
    assert node_pair.wait_discovery(timeout=20), "nodes must discover each other"
    peer_b = node_pair.test_peer(node_pair.a)
    node_pair.b.server.trusted_subnets = parse_subnets(f"{peer_b.host}/32")
    sock = socket.create_connection((peer_b.host, peer_b.port), timeout=5)
    send_frame(sock, {"type": "bogus"})
    reply = json.loads(recv_frame(sock).decode("utf-8"))
    assert reply["type"] == "error"
    assert reply["code"] != "refused"  # passed the subnet check
    sock.close()


def test_per_ip_connection_cap_on_listener(node_pair):
    """The listener refuses connections from one IP beyond the cap."""
    assert node_pair.wait_discovery(timeout=20), "nodes must discover each other"
    peer_b = node_pair.test_peer(node_pair.a)
    limiter = node_pair.b.server.limiter
    limiter.max_per_ip = 2
    key = peer_b.host
    # Hold both slots deterministically, then the real connection is refused.
    assert limiter.enter((key, 1))
    assert limiter.enter((key, 1))
    sock = socket.create_connection((peer_b.host, peer_b.port), timeout=5)
    send_frame(sock, {"type": "bogus"})
    reply = json.loads(recv_frame(sock).decode("utf-8"))
    assert reply["code"] == "busy"
    sock.close()
    limiter.leave((key, 1))
    limiter.leave((key, 1))


def test_rate_limit_on_listener(node_pair):
    """Excess unauthenticated requests from one IP are throttled."""
    assert node_pair.wait_discovery(timeout=20), "nodes must discover each other"
    peer_b = node_pair.test_peer(node_pair.a)
    limiter = node_pair.b.server.limiter
    limiter.rate_max = 2
    key = peer_b.host
    # Empty this IP's bucket, then the next connection is rate_limited.
    for _ in range(2):
        assert limiter.allow_request((key, 1))
    sock = socket.create_connection((peer_b.host, peer_b.port), timeout=5)
    send_frame(sock, {"type": "bogus"})
    reply = json.loads(recv_frame(sock).decode("utf-8"))
    assert reply["code"] == "rate_limited"
    sock.close()

pytestmark = pytest.mark.socket
