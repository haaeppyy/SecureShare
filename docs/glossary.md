# Glossary

| Term | Meaning |
|---|---|
| **AAD** | Authenticated Additional Data — plaintext bound to an AES-GCM encryption so it can't be swapped out. The transfer header bytes and the sync metadata are used as AAD. |
| **AES-GCM** | Authenticated encryption cipher — any tampering is detected with overwhelming probability. |
| **Atomic rename** | Write to a temp file, then `os.replace` to the final name — readers never see a half-written file. |
| **Channel** (sync) | A persistent encrypted TCP connection carrying clipboard frames in sequence order. |
| **Chunk** | 1 MiB unit of a file transfer; each is independently encrypted and authenticated. |
| **Control session** | The active KVM takeover — which machine currently drives the other's input. |
| **Discovery registry** | The live map of announced devices → (address, port, name, id, version), kept fresh by mDNS. |
| **Echo prevention** | Record the fingerprint of every clipboard write the app itself made, so the watcher doesn't re-send it. |
| **Edge latch** | Debounce windows around the screen seam (8 px in, 3 px at corners) so cursor wobble doesn't trigger a handoff. |
| **Escape chord** | Ctrl+Alt+Space on the target — the universal way to break a KVM session. |
| **Fingerprint** | A shortened SHA-256 of the trust key (e.g. `abcd-1234`); the stable identity used in messages and menus. |
| **Framed protocol** | `[4-byte length][JSON header][payload]` — the envelope every protocol uses on the wire. |
| **Handoff** | The takeover dance: `CONTROL_REQUEST → CONTROL_READY → CONTROL_BEGIN → ACTIVE`. |
| **HKDF** | Key-derivation function; turns the trust key + session randomness into per-protocol session keys. |
| **KVM** | Keyboard, Video, Mouse — here, sharing keyboard + mouse between two machines (no video). |
| **Keyring** | OS credential store (Keychain / Credential Manager) holding the master secret that protects trust.json. |
| **Link** (KVM) | The persistent KVM connection to a peer, distinct from the shorter-lived control session. |
| **Nonce8** | 8 random bytes generated per session; combined with a counter to make per-chunk nonces. |
| **Pairing** | The once-only, human-verified establishment of a shared trust key between two devices. |
| **Peer** | Another paired device on the LAN. |
| **PIN** | 6 digits derived from the ECDH shared secret (SHA-256 mod 1,000,000), shown on both screens and compared by both humans. |
| **Registry** | See *Discovery registry*. |
| **Seam** | The shared screen edge between two monitors (left/right of your screen, right/left of the peer's). |
| **SENTINEL** | The fake input signature (0x5E4C0DE5 + OS event type) the app stamps on its own injections, so it can ignore them. |
| **Sequence number** | Monotonic per-channel counter; `last+1` accepted, duplicates dropped, gaps kill the channel. |
| **Sync** | The clipboard mirroring feature. |
| **Token bucket** | Rate-limit primitive: 40 unauthenticated frames/sec/IP with 1-second refill. |
| **Transfer key** | One-time key derived for a single file transfer (trust key + random nonce8). |
| **Trust key** | The 32-byte shared secret stored at pairing; the root of all session keys. |
| **trust.json** | The encrypted-at-rest store: this device's id/name, the keyring-protected trust key, paired peers. |
| **Trust store** | The module (`core/trust_store.py`) managing trust.json. |
| **Watchdog** | The KVM thread that enforces timeouts (active-session keepalive, controller heartbeat, keyboard health) and heals stuck states. |
| **Withdraw** | Simultaneous takeover loser gracefully backing out, leaving the winner's request alive. |