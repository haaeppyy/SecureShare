"""Pairing flow tests, including the MITM public-key-swap simulation."""

import json
import os
import socket
import threading
import time

from core.pairing import PairingDenied, PairingError
from core.transfer import recv_frame, send_frame
from core.node import Node

from conftest import node_pair  # noqa: F401


def test_happy_path_pairing(node_pair):
    session_a, session_b = node_pair.pair()
    assert session_a.pin == session_b.pin
    assert len(session_a.pin) == 6


def test_pin_mismatch_refuses_trust(tmp_path):
    """MITM simulation: an attacker swaps the public keys in transit, so
    the two honest devices derive different shared secrets (hence different
    PINs). When the human detects the mismatch and refuses confirmation,
    no trust is stored on either side."""
    pair_a = Node(
        name="Alice",
        data_dir=os.path.join(str(tmp_path), "a"),
        port=49600,
        keyring_enabled=False,
    )
    sessions_b = []
    pair_b = Node(
        name="Bob",
        data_dir=os.path.join(str(tmp_path), "b"),
        port=49601,
        keyring_enabled=False,
        on_incoming_pair=sessions_b.append,
    )
    pair_a.start()
    pair_b.start()

    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization

    attacker = ec.generate_private_key(ec.SECP256R1())
    attacker_pub = attacker.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")

    # A MITM proxy between Alice and Bob that swaps the public keys.
    proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy.bind(("127.0.0.1", 49602))
    proxy.listen(1)
    proxy.settimeout(20)

    def mitm():
        conn_a, _ = proxy.accept()
        req = json.loads(recv_frame(conn_a).decode("utf-8"))
        assert req["type"] == "pair_request"
        req["pubkey"] = attacker_pub  # swap!
        up = socket.create_connection(("127.0.0.1", 49601), timeout=10)
        send_frame(up, req)
        resp = json.loads(recv_frame(up).decode("utf-8"))
        assert resp["type"] == "pair_response"
        resp["pubkey"] = attacker_pub  # swap!
        send_frame(conn_a, resp)
        time.sleep(0.5)
        conn_a.close()
        up.close()

    threading.Thread(target=mitm, daemon=True).start()

    result = {}

    def run():
        result["session"] = pair_a.pair_with("127.0.0.1", 49602)

    t = threading.Thread(target=run)
    t.start()
    deadline = time.monotonic() + 15
    while not sessions_b and time.monotonic() < deadline:
        time.sleep(0.05)
    assert sessions_b, "Bob never saw the request"
    session_b = sessions_b[0]
    session_b.accept()
    t.join(timeout=10)
    session_a = result["session"]

    # The honest humans see DIFFERENT PINs -> refuse.
    assert session_a.pin != session_b.pin, "MITM must produce mismatched PINs"
    session_a.confirm(matches=False)

    time.sleep(0.5)
    assert not pair_a.store.is_paired(pair_b.store.fingerprint())
    assert not pair_b.store.is_paired(pair_a.store.fingerprint())
    pair_a.stop()
    pair_b.stop()


def test_deny_before_accept(tmp_path):
    pair_a = Node(
        name="Alice", data_dir=os.path.join(str(tmp_path), "a"), port=49610, keyring_enabled=False
    )
    sessions_b = []
    pair_b = Node(
        name="Bob",
        data_dir=os.path.join(str(tmp_path), "b"),
        port=49611,
        keyring_enabled=False,
        on_incoming_pair=sessions_b.append,
    )
    pair_a.start()
    pair_b.start()
    try:
        outcome = {}

        def run():
            try:
                outcome["session"] = pair_a.pair_with("127.0.0.1", 49611)
            except Exception as exc:
                outcome["error"] = exc

        t = threading.Thread(target=run)
        t.start()
        deadline = time.monotonic() + 10
        while not sessions_b and time.monotonic() < deadline:
            time.sleep(0.05)
        session_b = sessions_b[0]
        session_b.deny()
        t.join(timeout=10)
        assert "session" not in outcome
        assert isinstance(outcome["error"], PairingDenied)
        assert not pair_a.store.is_paired(pair_b.store.fingerprint())
        assert not pair_b.store.is_paired(pair_a.store.fingerprint())
    finally:
        pair_a.stop()
        pair_b.stop()