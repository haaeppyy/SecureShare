"""Cryptographic primitives for SecureShare.

ECDH key agreement, HKDF key derivation, AES-GCM authenticated
encryption and out-of-band PIN derivation.
"""

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEY_LENGTH = 32
NONCE_LENGTH = 12
TRUST_INFO = b"secureshare-trust-v1"
TRANSFER_INFO = b"secureshare-transfer-v1"
SYNC_INFO = b"secureshare-sync-v1"
SYNC_CHANNEL_INFO = b"secureshare-sync-channel-v1"
KVM_INFO = b"secureshare-kvm-v1"
_KDF_SALT = b"SecureShare-v1"

PIN_MOD = 1_000_000
CHUNK_NONCE_PREFIX_BYTES = 8
CHUNK_NONCE_COUNTER_BYTES = 4


def _hkdf(material, salt, info, length=KEY_LENGTH):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(material)


def derive_trust_key(shared_secret: bytes) -> bytes:
    """Long-term trust key derived from the ECDH shared secret."""
    return _hkdf(shared_secret, _KDF_SALT, TRUST_INFO)


def derive_transfer_key(trust_key: bytes, nonce8: bytes) -> bytes:
    """Per-transfer key derived from the trust key + a random 8-byte nonce."""
    return _hkdf(trust_key, nonce8, TRANSFER_INFO)


def derive_sync_key(trust_key: bytes, nonce: bytes) -> bytes:
    """Per-message key for the clipboard sync channel."""
    return _hkdf(trust_key, nonce, SYNC_INFO)


def derive_sync_channel_key(trust_key: bytes, salt: bytes) -> bytes:
    """Per-channel key for a clipboard sync connection.

    ``salt`` must bind protocol version, both fingerprints, the role and
    both channel nonces, so a spoofed open produces a key the peer cannot
    derive (the first sealed frame is the key confirmation).
    """
    return _hkdf(trust_key, salt, SYNC_CHANNEL_INFO)


def derive_kvm_channel_key(trust_key: bytes, salt: bytes) -> bytes:
    """Per-channel key for a keyboard/mouse control channel.

    ``salt`` must bind protocol version, both fingerprints, the role and
    both channel nonces, so a tampered handshake produces a key the peer
    cannot derive (the first binary frame is the key confirmation).
    """
    return _hkdf(trust_key, salt, KVM_INFO)


def derive_pin(shared_secret: bytes) -> str:
    """Out-of-band 6-digit confirmation code from the shared secret."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(shared_secret)
    code = int.from_bytes(digest.finalize()[:6], "big") % PIN_MOD
    return f"{code:06d}"


def chunk_nonce(nonce8: bytes, index: int) -> bytes:
    """Per-chunk nonce: 8 random bytes + 32-bit monotonic counter.

    Guarantees a unique AES-GCM nonce for every chunk of every transfer.
    """
    if len(nonce8) != CHUNK_NONCE_PREFIX_BYTES:
        raise ValueError("nonce8 must be exactly 8 bytes")
    return nonce8 + index.to_bytes(CHUNK_NONCE_COUNTER_BYTES, "big")


def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """AES-GCM seal with a fresh random nonce; nonce is prepended."""
    nonce = os.urandom(NONCE_LENGTH)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt(key: bytes, sealed: bytes, aad: bytes = b"") -> bytes:
    """AES-GCM open; raises InvalidTag on tampering."""
    nonce, ciphertext = sealed[:NONCE_LENGTH], sealed[NONCE_LENGTH:]
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


def encrypt_with_nonce(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """AES-GCM seal with an explicit nonce (used for chunked streaming)."""
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt_with_nonce(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    """AES-GCM open with an explicit nonce."""
    return AESGCM(key).decrypt(nonce, ciphertext, aad)