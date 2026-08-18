"""Unit tests for core.crypto."""

import os

import pytest
from cryptography.exceptions import InvalidTag

from core import crypto


def test_encrypt_decrypt_roundtrip():
    key = os.urandom(32)
    sealed = crypto.encrypt(key, b"hello world")
    assert crypto.decrypt(key, sealed) == b"hello world"
    assert len(sealed) == 12 + len(b"hello world") + 16


def test_decrypt_detects_tampering():
    key = os.urandom(32)
    sealed = bytearray(crypto.encrypt(key, b"payload"))
    sealed[-1] ^= 0xFF
    with pytest.raises(InvalidTag):
        crypto.decrypt(key, bytes(sealed))


def test_decrypt_detects_aad_tampering():
    key = os.urandom(32)
    sealed = crypto.encrypt(key, b"payload", aad=b"header")
    with pytest.raises(InvalidTag):
        crypto.decrypt(key, sealed, aad=b"HEADER")


def test_derived_keys_are_distinct_and_deterministic():
    shared = os.urandom(32)
    trust1 = crypto.derive_trust_key(shared)
    trust2 = crypto.derive_trust_key(shared)
    assert trust1 == trust2
    assert len(trust1) == 32

    n1, n2 = os.urandom(8), os.urandom(8)
    k1, k2 = crypto.derive_transfer_key(trust1, n1), crypto.derive_transfer_key(trust1, n2)
    assert k1 != k2
    assert crypto.derive_transfer_key(trust1, n1) == k1  # deterministic

    sync_k = crypto.derive_sync_key(trust1, os.urandom(12))
    assert len(sync_k) == 32
    assert sync_k != k1


def test_pin_derivation():
    shared = os.urandom(32)
    pin = crypto.derive_pin(shared)
    assert pin.isdigit() and len(pin) == 6
    assert crypto.derive_pin(shared) == pin  # deterministic both sides
    assert crypto.derive_pin(os.urandom(32)) != pin


def test_chunk_nonces_unique_and_bounded():
    nonce8 = os.urandom(8)
    nonces = {crypto.chunk_nonce(nonce8, i) for i in range(1000)}
    assert len(nonces) == 1000
    for n in nonces:
        assert len(n) == 12
    other = crypto.chunk_nonce(os.urandom(8), 0)
    assert other not in nonces


def test_explicit_nonce_encrypt():
    key = os.urandom(32)
    nonce = os.urandom(12)
    ct = crypto.encrypt_with_nonce(key, nonce, b"data", aad=b"h")
    assert crypto.decrypt_with_nonce(key, nonce, ct, aad=b"h") == b"data"
    with pytest.raises(InvalidTag):
        crypto.decrypt_with_nonce(key, nonce, ct, aad=b"x")

pytestmark = pytest.mark.unit
