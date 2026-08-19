# 11. Important Processing and Business Logic

This chapter collects the places where real computation happens — the
calculations, decisions, and rules that make the system work. For each:
**Input → Processing → Decision → Output → Next step.**

## 11.1 PIN derivation (pairing)

- **Input:** the ECDH shared secret (same bytes on both machines).
- **Processing:** SHA-256 of the secret; take the first 6 bytes as a
  big-endian integer; modulo 1,000,000; zero-pad to 6 digits.
- **Decision:** none — deterministic.
- **Output:** the 6-digit string shown on both screens.
- **Next step:** humans compare; then Accept/Confirm.

*Confirmed from code: `core/crypto.py:71-76`.*

## 11.2 Trust key derivation (pairing)

- **Input:** ECDH shared secret.
- **Processing:** HKDF-SHA256 with fixed salt `SecureShare-v1` and info
  `secureshare-trust-v1`, 32 bytes.
- **Output:** the long-term trust key, stored encrypted at rest.
- **Next step:** every protocol derives *its own* key from this one.

*Confirmed from code: `core/crypto.py:36-38`.*

## 11.3 Transfer chunking and per-chunk nonces

- **Input:** file path (sender), header frame + chunks (receiver).
- **Processing:**
  - Sender: read 1 MiB blocks; for block *i*, nonce = `nonce8[i]` (8
    random bytes from the header) + `i` as a 4-byte counter; AES-GCM
    encrypt with the transfer key; send `[8-byte length][ciphertext]`.
  - Receiver: check chunk length bounds (0 < len ≤ chunk_size + 16,
    ≤ 4 MiB), decrypt with the same nonce construction, verify size.
- **Decision:** any `InvalidTag` → abort with "chunk authentication
  failed"; received bytes ≠ declared size → abort; chunk larger than
  declared → abort.
- **Output:** verified file bytes; `ok`/`error` ack.
- **Next step:** atomic rename; completion callback.

*Confirmed from code: `core/transfer.py:139-152` (send),
`core/transfer.py:390-428` (receive), `core/crypto.py:79-87` (nonce).*

## 11.4 Transfer admission checks (receiver)

Ordered decisions in `_handle_transfer`:

1. Sender's fingerprint in trust store? → else refuse `not_paired`.
2. Header well-formed (nonce8 8 bytes, chunk_size ≤ 4 MiB, size
   positive and ≤ 2^42)? → else refuse `bad_header`.
3. Size ≤ configured max (default 10 GiB)? → else refuse `too_large`.
4. Free disk space ≥ size + 1 MiB margin? → else refuse `no_space`.
5. Final path collision-safe (suffix `-1`, `-2`…) and claimed against
   concurrent transfers.

*Confirmed from code: `core/transfer.py:327-364, 440-456`.*

## 11.5 Sync frame validation (anti-replay)

For every inbound clipboard frame:

1. Type is `clipboard_text`/`clipboard_image`? sync enabled? version
   matches? sender fingerprint equals the channel's peer? peer_fp is me?
2. Sequence number: must equal `last_incoming + 1`.
   - ≤ last → duplicate/stale → drop silently.
   - > last + 1 → gap → **close the channel** (the stream is considered
     compromised).
3. Decrypt with the channel key using the exact metadata JSON as
   authenticated data. Failure → close the channel.

**Input → Processing → Decision → Output:** frame bytes → metadata check +
AES-GCM open → accept (write clipboard) or drop/close → new last sequence.

*Confirmed from code: `core/sync.py:294-330`, `core/sync.py:77-88`
(AAD construction).*

## 11.6 KVM handoff decision (target)

Already enumerated in [10-kvm-deep-dive.md](10-kvm-deep-dive.md) §10.3 —
an 8-step ordered decision chain producing `READY` or one of several
refusal codes. The key business rules:

- **One active control at a time** (globally, not just per peer).
- **Simultaneous takeovers:** deterministic tiebreak by fingerprint; the
  loser *withdraws* (which must not be mistaken for a refusal, so the
  winner's request stays alive).
- **Consent is per peer and re-checked at every takeover.**

*Confirmed from code: `core/kvm.py:1491-1553`.*

## 11.7 Seam math (KVM geometry)

- **Input:** my cursor position, my layout, my side, peer's layout.
- **Processing:**
  - Jump-zone test: within 3 px of an edge? (horizontal first at
    corners).
  - Fraction: position along the seam, normalized 0..1.
  - Entry point: peer's opposite edge at the same fraction, inset
    48 px into the peer's screen.
  - Return point: my seam edge at the same fraction, inset 4 px
    (`JUMP_ZONE + 1`).
  - Topology: `my_side` must equal `opposite(peer_side)`.
- **Output:** entry coordinates for the takeover; latch-clearing zone
  checks; mismatch toast state.

*Confirmed from code: `core/kvm_geometry.py` (whole file).*

## 11.8 Echo prevention (clipboard sync)

- **Problem:** app writes clipboard → its own watcher sees a change →
  would re-send → peer writes back → loop.
- **Processing:** after *every* clipboard write (own copy or received
  frame), immediately re-read and record the content signature
  (`(type, hash)` tuples). The watcher compares snapshots against the
  last-seen signature; identical signatures are skipped.
- **Cheap gate:** where the OS provides a clipboard revision counter, it
  is compared first so full reads only happen on actual changes.
- **File-copy gate:** snapshots flagged `file_copy` are never sent.

*Confirmed from code: `core/sync.py:423-470`, `core/clipboard.py:19-33`.*

## 11.9 Rate limiting and connection caps (listener admission)

- **Per-IP connection cap:** 8 concurrent connections per source IP;
  excess refused with `busy`.
- **Token-bucket rate limit:** 40 unauthenticated frames/sec/IP with
  1-second window refill; excess refused with `rate_limited`.
- **Subnet gate:** optional `--trusted-subnets`; any IP outside refused
  with `refused` before any data is read.

*Confirmed from code: `core/limits.py` (whole file),
`core/transfer.py:262-297`.*

## 11.10 Path collision resolution (received files)

- **Input:** requested filename.
- **Processing:** while the candidate path exists on disk *or* is
  claimed by an in-flight transfer, append `-1`, `-2`, … before the
  extension. The claim set is released on every exit path.
- **Output:** a guaranteed-nonexistent final path, reserved for this
  transfer.

*Confirmed from code: `core/transfer.py:440-456`.*

## 11.11 Keyboard-modifier reconciliation (KVM)

- **Problem:** both machines must agree on modifier state (Shift/Ctrl/
  Alt/Meta/AltGr), especially across handoffs, so a chord pressed on one
  machine arrives correctly on the other.
- **Processing:** modifiers are tracked as a 5-bit mask on the
  controller; a full `modifiers` frame is sent on any change; on the
  target, the difference between the received mask and the currently
  injected mask is computed and only the changed keys are pressed/
  released. The escape chord is detected as Ctrl+Alt held + Space pressed
  (mask + key set, with an armed/one-shot latch).
- **Key-state reconciliation:** `all_keys_up` on hand-back/drop releases
  everything held on either side.

*Confirmed from code: `core/kvm_keymap.py:21-49`, `core/kvm.py:1237-1289`
(capture side), `core/kvm.py:1903-1944` (injection side).*

## 11.12 File size and throughput reporting (UI)

- **Input:** bytes sent/received, timestamps.
- **Processing:** the tray computes percentage, rate (bytes/elapsed),
  and ETA; progress posts are throttled to one per 200 ms per transfer
  so the ~1 MiB chunk firehose cannot flood the UI queue; transfers
  stale for 30 s are pruned.
- **Output:** the menu progress row and the transfer window bars.

*Confirmed from code: `tray/app.py:632-692, 754-771`.*