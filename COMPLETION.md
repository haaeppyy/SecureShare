# SecureShare — completion report

Rebuilt the legacy `Cyber-Project` codebase as **secure-share**: a LAN-only,
end-to-end encrypted file transfer + clipboard sync tray app for macOS and
Windows. The old project (MySQL credential store, web UI) is retired; the
directory `Cyber-Project-main` is untouched.

## Deliverables

| Item | Location |
|---|---|
| Source | repository root (this directory) |
| macOS app bundle | `dist/SecureShare.app` (43 MB, arm64, built on this Mac) |
| macOS zip | `dist/SecureShare-macOS-arm64.zip` (70 MB) |
| Windows build recipe | `secure-share-win.spec` (build on Windows) |
| Test suite | `tests/` — **104 passed** on macOS |
| Windows manual checklist | `tests/manual_checklist.md` |

## What was built

- `core/crypto.py` — HKDF key derivation, AES-256-GCM, 6-digit PIN from
  ECDH shared secret, per-chunk nonce (8 random + 32-bit counter).
- `core/pairing.py` — ECDH P-256 handshake; trust stored only after a human
  confirms the PIN matches on both screens (defeats LAN MITM).
- `core/transfer.py` — chunked streaming transfers (1 MiB chunks), header
  bytes as AAD for every chunk, refuses unpaired senders.
- `core/discovery.py` — mDNS/DNS-SD via zeroconf, resolution in a dedicated
  thread (callback-thread `get_service_info` deadlock was fixed early on).
- `core/trust_store.py` — Fernet-encrypted trust store keyed by a keyring
  master secret, chmod-600 fallback.
- `core/sync.py` — clipboard mirroring (text + images) over persistent
  encrypted channels; OFF by default; echo prevention via post-write
  signature seeding; file copies never synced.
- `core/clipboard_mac.py` / `clipboard_win.py` — NSPasteboard (PNG/TIFF)
  and CF_DIB/CF_HDROP image support.
- `core/kvm.py` + `kvm_events.py` + `kvm_geometry.py` + `kvm_keymap.py`
  — keyboard/mouse sharing: one persistent AES-GCM channel per peer with
  the protocol version, both fingerprints, roles and both channel nonces
  bound into the channel key (HKDF over the trust key); monotonic
  per-direction nonce counters; control state machine (local/controlling/
  remote) with seam-edge takeovers, hand-back on the peer edge, the
  Ctrl+Alt+Space escape chord, ALL_KEYS_UP reconciliation, per-peer
  consent enforced at takeover time, deterministic fingerprint tiebreak
  for simultaneous takeovers, and screen-layout topology checks with a
  mismatch toast. Keycodes travel as USB HID usages; macOS converts
  virtual keycodes both ways, Windows injects PS/2 scan codes (extended
  flag) to preserve the remote layout. Seam alignment is proportional
  (fraction of edge length) so unequal screen sizes line up; monitor
  union bounds v1, multi-monitor exactness v2.
- `core/kvm_platform_mac.py` / `kvm_platform_win.py` — CGEvent taps
  (mouse move / key up+down / scroll), CGEventsSetUnlocalizedKeyboardType
  for layout-independent HID codes, NSEvent.modifierFlags capture,
  SetCursorPos + SendInput + GetKeyState scan-code capture (Windows).
- `tray/app.py` — pystray menu (pair / send / unpair / sync toggle),
  tkinter PIN and file dialogs on the main thread, thread-safe queue pump.
- KVM tray menu: sharing on/off toggle, per-peer "Allow control from this
  device" consent toggle and left/right/top/bottom seam-side radios
  (change-driven menu refresh includes KVM state).
- PyInstaller recipes + icon assets + README + requirements.txt.

## Bugs found and fixed during this session

1. `trust_store._keyring_faster` -> `_keyring_fetch` (crash on keyring save).
2. Encrypted store could not be reloaded: save wrote `{"encrypted": true,
   "blob": ...}` but load Fernet-decrypted the whole file — peers were lost
   across restarts whenever keyring was used.
3. `Discovery.stop()` set `_stop` which `start()` never cleared — after a
   stop/start (app restart) the resolve loop exited immediately and no
   devices were ever discovered again.
4. Same `_stop` bug in `SyncEngine` — after restart, channels never
   re-established (connect loop dead).
5. Frozen app failed to import `core` — `pathex=["."]` missing from the
   PyInstaller specs; `sys.path` hack now only applies when not frozen.
6. Tkinter created off the macOS main thread crashed the app; tray now
   drives Tk on the main thread and runs pystray detached with the shared
   NSApplication.
7. Double pairing dialog: `_start_pairing` re-posted the session that
   `pair_with` already posted via `on_session`.
8. **Menu frozen at startup state ("No devices found", sync toggle stuck
   OFF) on real LAN:** per-device menu actions used 3-argument lambdas
   (`lambda icon, item, p=peer: ...`), which pystray rejects
   (`_assert_action` allows at most 2). The moment a peer was discovered,
   `_build_menu` raised `ValueError` on every 2 s refresh, and the silent
   `except Exception: pass` froze the menu forever — discovery itself was
   fine (proven with debug logging: peers resolved, store toggled). Fixed
   to 2-argument closures; refresh failures now log instead of silently
   freezing.
9. Tests were not hermetic on a real LAN: fixtures and transfer tests
   picked `list(discovery.peers())[0]`, which could be another live
   SecureShare instance on the network instead of the loopback test peer
   (observed: pairing and tamper tests failed while the user's Windows
   device was online). `NodePair.test_peer()` now selects peers by test
   port (PORT_BASE/PORT_BASE+1).
10. **Pairing to a real device failed with "No route to host":** connect
    used the first resolved address, which could be an IPv6 link-local
    (`fe80::`, needs a zone index — unreachable cross-host) or a stale
    cached address. `_pick_address()` now prefers IPv4 and skips
    link-local/unspecified/multicast; `_resolve()` does a live DNS query
    first with the cache only as fallback. Pairing errors now include
    the exact host:port.
11. **Multiple pairing PIN popups (5+):** each "Pair with device" click
    created a new session/dialog, and the initiating side had no feedback
    so users clicked repeatedly. Pairing UI moved fully into the tray
    menu — a "Pairing with/from <name>" entry shows the PIN with
    Confirm/Accept/Deny inline — sessions are deduped per peer (older
    ones closed) and pruned when done or after 70 s; duplicate
    initiation is refused with a toast.
12. **File picker / message boxes opened clipped off-screen:** native
    dialogs were parented to the withdrawn hidden root window, so macOS
    panels and Windows dialogs positioned against an off-screen owner.
    `_prepare_dialog()` places the hidden root on-screen first, and the
    file picker no longer passes a parent on macOS (standalone panel).
13. **Menu rebuilt every 2 s even while open:** on Windows this raced
    pystray's `TrackPopupMenuEx` (destroyed/recreated HMENUs mid-click).
    The refresh is now change-driven (peer set, sessions, sync state)
    instead of unconditional.
14. **No transfer progress UI:** sending showed only a 10 % toast and
    receiving showed nothing at all. `TransferServer.on_progress` now
    carries the transfer identity (`info` dict), `Node` exposes
    `on_transfer_start`/`on_transfer_progress`, and the tray app tracks
    both directions (`send|recv:{fp}:{name}`). A "Transfers" section in
    the tray menu shows live text bars (`↑ photo.jpg 67% [███████░░░]`),
    and an always-on-top "SecureShare Transfers" window shows real
    progress bars with percentage, MB/s and ETA. Progress posts are
    throttled (~0.2 s per transfer) so 1 MiB chunks do not flood the UI
    queue; entries go stale after 30 s (covers receiver failures, which
    carry no identity).

## KVM session follow-up (this session)

### Pairing popups restored

Item #11 moved pairing into the tray menu only, which left the responder
with no visible way to accept a request (the session was hidden in a
submenu and pruned after 70 s). The pairing windows are back: the
responder gets an **Accept / Deny** popup ("Pairing from <name>", PIN
shown), the initiator gets a **Confirm / Deny** popup ("Pairing with
<name>"), one dialog per peer, auto-closed on done/denied/replace/prune.
The inline menu entries stay as a fallback; the protocol and
`core/pairing.py` are unchanged.

### What was added

- Full KVM engine (`core/kvm.py`): encrypted channel handshake, control
  state machine, seam-edge takeover/hand-back, escape chord, key
  reconciliation, stall watchdog, consent + topology enforcement.
- Event codec (`kvm_events.py`), keycode tables (`kvm_keymap.py`) with
  macOS VK ↔ HID and HID ↔ PS/2-scan bijections, seam geometry
  (`kvm_geometry.py`), and the macOS/Windows input platforms
  (`kvm_platform_mac.py`, `kvm_platform_win.py`).
- Tray menu: sharing toggle, per-peer consent + seam side radios.
- Tests: 39 unit (codec/keymap/geometry) + 9 engine integration tests
  (two real Nodes on loopback with a fake input platform driving take
  control, streaming, hand-back, key release, consent refusal, topology
  mismatch, simultaneous-takeover tiebreak, escape chord, display
  resync) + 6 tray-menu KVM tests + 4 pairing-popup tests. Full suite: **104 passed**.

### Bugs found and fixed during KVM testing

1. `seam_fraction` and `edge_point` used the full extent as the
   denominator, so the bottom/right edge never produced fraction 1.0
   and fraction 1.0 could land one pixel off-screen. Fixed to `h-1`
   / `w-1` extents; the engine's hand-back warp mirrors the peer edge
   position within ±1 px.
2. Pause (HID 0x48) and Num Lock share PS/2 scan code 0x45, which broke
   the `WIN_SCAN_TO_HID` inverse (asserted 104 == 105). Pause now
   excluded from Windows injection (it needs the E1 1D 45 sequence).
3. The escape chord was detected against `_local_pressed`, which never
   contains modifiers — Ctrl+Alt+Space could never fire. Detection now
   uses the held modifier mask plus Space.
4. `_on_edge_hit` compared the decoded int direction against a string
   side; hand-back never fired. Directions now map through
   EDGE_* → side names.
5. Simultaneous takeover race: the winner's CONTROL_REVERT could arrive
   at the loser after it had already entered remote via the TAKE_CONTROL
   tiebreak, spuriously reverting it to local while the winner kept
   streaming. The winner now stays silent; the loser resolves the race
   on its side (fingerprint tiebreak) and both sides converge.
6. Engine `enabled` was snapshotted at construction; store-level
   `set_kvm_enabled` alone left the connect loop dead. All writes now go
   through `KVMEngine.set_enabled` (updates engine + store), and the
   tests use it.
7. `TrustStore.list_peers` omitted `kvm_allowed`/`kvm_side`, so the tray
   KVM menu always showed defaults. Fields added to the peer snapshot.
8. The first tray KVM menu draft used lambdas with defaulted extra args;
   pystray rejects callables with more than two parameters
   (`ValueError` on every menu rebuild — the same class of bug as #8 in
   the earlier session). Rewritten with `functools.partial` + optional
   `icon/item` parameters; the tray test suite pins it.

### Verified on this Mac

- Engine integration suite (loopback, fake platform): take control over
  the seam, rel/abs mouse, buttons, wheel, keys stream to the peer;
  hand-back on the peer edge with mirrored cursor position; held keys
  released on the far side; consent refusal; layout-mismatch refusal;
  deterministic winner under simultaneous takeover; escape chord
  revert; display-change resync.
- Keymap bijections both directions; geometry math pinned by unit tests.
- Tray menu: KVM section renders, toggles and radios update the store.

## Verified on this Mac (macOS 27 arm64)

- Pairing happy path (PIN match), unpaired-send refusal.
- 5 MB transfer, sha256 match, ~635 MB/s loopback.
- Clipboard sync both directions with real NSPasteboard clipboard
  (genuine-sync integration, text + image, no echo loop).
- Keyring-encrypted store: pair, restart both nodes, still paired, sync
  re-establishes and relays (unique-value probe).
- Packaged `SecureShare.app` launches and runs.
- Transfer progress UI: tracker + menu text bars + progress window
  (send and receive directions).
- KVM engine suite on loopback with a fake input platform (see above);
  the macOS input platform (CGEvent taps) needs a real Accessibility
  grant and two machines — see `tests/manual_checklist.md` §9.
- `pytest`: 104 passed (incl. `test_tray_menu.py` regression for the
  3-arg lambda bug, the inline pairing menu, the transfer tracker, and
  the KVM unit/engine/tray tests; suite runs even with the user's
  Windows device live on the LAN).

## Remaining (needs the Windows machine)

- Windows build (`pyinstaller --clean --noconfirm secure-share-win.spec`)
  and the manual checklist in `tests/manual_checklist.md` — pywin32
  clipboard, Credential Manager keyring, win32 tray backend and the KVM
  Windows input platform are Windows-only and unverified here.
- Real two-machine LAN test (mDNS across hosts; loopback tested only),
  including KVM across hosts with real Accessibility-granted CGEvent
  taps on macOS.
- Multi-monitor seam geometry (v2; v1 uses monitor union bounds).
- Code signing / notarization if distributing outside the LAN.
