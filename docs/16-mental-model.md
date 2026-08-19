# 16. Mental Model — Think About the App This Way

The whole system is easier to keep in your head as three layered
pictures. If you understand these, you understand the app.

## Picture 1 — One connection, four protocols

Every machine runs exactly **one TCP listener**. Every conversation on
the LAN — pairing, file transfer, clipboard sync, KVM — is a distinct
connection to that one port, identified by the first frame's `type`.
Each protocol has its own **key derived from the shared trust key** and
its own **anti-replay discipline**:

| Protocol | Key | Anti-replay |
|---|---|---|
| transfer | one-time, from trust key + random nonce8 | random nonce, message auth, byte-count checks |
| pair_request | ephemeral ECDH | nothing — must be confirmed by both humans |
| sync | from trust key + random nonce8 + fixed salt | monotonically increasing sequence numbers; gap → channel killed |
| kvm | from trust key + random nonce8 + fixed salt | peer check + exclusive control; events carried on the same encrypted stream |

## Picture 2 — One trust root, many ephemeral secrets

Pairing is the *only* moment human eyes are involved. Everything
afterward derives from what pairing planted:

```
human PIN check
      │  (ECDH shared secret)
      ▼
  trust key ── stored in trust.json (encrypted at rest)
      │
      ├── transfer key  = HKDF(trust, salt, "secureshare-transfer-v1")
      ├── sync key      = HKDF(trust, random nonce8, "secureshare-sync-v1")
      └── kvm key       = HKDF(trust, random nonce8, "secureshare-kvm-v1")
```

So "trust a device once" is literally a persistent 32-byte key stored
once, and every later session is a fresh per-session secret.

## Picture 3 — The app is a coordinator, not a server

Nothing in the system is a server with accounts, quotas, or a database.
The app:

1. **Advertises and discovers** — mDNS says "I'm here", the registry
   keeps that fresh.
2. **Admits** — one listener gates everything: subnets, connection caps,
   rate limits, then per-protocol checks.
3. **Derives** — every secret comes from the trust key + per-session
   randomness.
4. **Streams** — files in framed authenticated chunks; clipboard in
   authenticated frames; KVM in binary events; all over the same framing
   primitives (`send_frame`/`recv_frame`).
5. **Tells the UI** — callbacks push into the tray's single-threaded
   queue; the pump rebuilds the menu (throttled, signature-checked) and
   fires notifications (only errors, coalesced).

## The state machines that keep everything sane

- **Pairing** — `Idle → WaitingForAcceptance → WaitingForConfirmation →
  Confirmed/Rejected/Aborted` (driven by both humans).
- **KVM control** — `Idle → Requested → Ready → Active → (Reversing) →
  Idle`; link states `Idle → Initiating → Established → Closing`.
- **Clipboard sync** — the *fingerprint* of the clipboard is the state;
  everything else is a stream with strict sequencing.

## Rules of thumb when reading the code

- **`core/` never touches UI; `tray/` owns all UI.** Tests exercise
  `core/` with no display at all.
- **The queue is the UI's backbone.** Every thread hands results to
  `Node._dispatch_ui_callback`; only the pump touches widgets.
- **Framing is shared.** Learn `send_frame`/`recv_frame` in
  `core/transfer.py` and every protocol's wire format is just a payload.
- **Refuse early, cleanly.** Admission checks happen before any data is
  read; failure deletes only temp files.
- **Anything that crosses the wire is authenticated.** Plaintext is
  AAD or never sent; integrity failure means abort or close, never
  retry.

## What to remember about each subsystem

| Subsystem | One-liner |
|---|---|
| `discovery.py` | Keeps "who's online and where" fresh via mDNS |
| `pairing.py` | Turns a human-confirmed PIN into a stored trust key |
| `transfer.py` | The framed protocol, the listener, and encrypted file streaming |
| `sync.py` | Watches, authenticates, and forwards clipboard changes |
| `kvm.py` | Coordinates the acknowledged handoff of keyboard/mouse |
| `kvm_platform_*` | OS-specific capture/injection; everything else is cross-platform |
| `trust_store.py` | The only persistence; encrypted; one file |
| `tray/app.py` | Everything the user sees, driven by a single-threaded queue |

## The seven-line version

> Two machines pair once over the LAN, proving identity with a PIN both
> humans read. That moment plants a shared key. Every later action —
> sending a file, mirroring the clipboard, borrowing the other's
> keyboard — is a fresh encrypted session over one TCP port, derived
> from that key, admitted by one gated listener, surfaced through one
> UI queue. No accounts, no cloud, no servers: trust is a file, and
> everything else is math.