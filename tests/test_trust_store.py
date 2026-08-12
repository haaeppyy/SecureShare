"""Trust store persistence + at-rest protection tests."""

import json
import os

from core.trust_store import TrustStore


def test_identity_persists(tmp_path):
    store = TrustStore(data_dir=str(tmp_path), keyring_enabled=False)
    fp = store.fingerprint()
    store.set_name("TestBox")
    assert store.identity["name"] == "TestBox"

    store2 = TrustStore(data_dir=str(tmp_path), keyring_enabled=False)
    assert store2.fingerprint() == fp
    assert store2.identity["name"] == "TestBox"


def test_peer_roundtrip_and_unpair(tmp_path):
    store = TrustStore(data_dir=str(tmp_path), keyring_enabled=False)
    store.add_peer("fp-1", "Bob", b"t" * 32)
    assert store.is_paired("fp-1")
    assert store.get_peer("fp-1")["trust_key"] == b"t" * 32
    assert store.get_peer("fp-1")["paired_date"]

    store2 = TrustStore(data_dir=str(tmp_path), keyring_enabled=False)
    assert store2.is_paired("fp-1")
    store2.remove_peer("fp-1")
    assert not store2.is_paired("fp-1")
    assert not TrustStore(data_dir=str(tmp_path), keyring_enabled=False).is_paired("fp-1")


def test_keyring_disabled_uses_plaintext_fallback(tmp_path):
    store = TrustStore(data_dir=str(tmp_path), keyring_enabled=False)
    store.add_peer("fp-2", "Carol", b"k" * 32)
    assert store.encrypted is False
    assert store.keyring_used is False
    raw = open(os.path.join(str(tmp_path), "trust.json")).read()
    payload = json.loads(raw)
    assert payload.get("encrypted") is False
    mode = os.stat(os.path.join(str(tmp_path), "trust.json")).st_mode & 0o777
    assert mode == 0o600


def test_sync_enabled_flag_persists(tmp_path):
    store = TrustStore(data_dir=str(tmp_path), keyring_enabled=False)
    assert store.sync_enabled is False
    store.set_sync_enabled(True)
    reloaded = TrustStore(data_dir=str(tmp_path), keyring_enabled=False)
    assert reloaded.sync_enabled is True