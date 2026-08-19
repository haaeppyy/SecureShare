# 14. Project Structure Explained (by Concept)

This chapter explains *why* the files exist, grouped by what they do. The
raw tree is small enough to keep in mind; the groupings are the useful
part.

## The two faces of the app

The codebase is deliberately split into a UI-free core and a tray layer:

- **`core/`** — everything that works without a screen: protocols,
  crypto, storage, discovery, clipboard access, KVM. Fully testable
  headlessly (the tests build real Nodes with no UI).
- **`tray/`** — the only user-facing layer: pystray menu, tkinter
  dialogs, the queue pump, notifications, the diagnostics log window.

The split is enforced at import level too: `core` never imports `tray`;
`tray` imports `core`.

## Conceptual groupings

### User Interface
| File | Why it exists |
|---|---|
| `tray/app.py` | The whole UI: menu construction, all dialogs, the main-thread pump, single-instance IPC, notifications policy |
| `tray/logbook.py` | Diagnostics window for the KVM engine (status stream + diagnostics dump) |
| `tray/icons/` | Tray icon assets (a fallback icon is drawn in code if missing) |

### System entry & composition
| File | Why it exists |
|---|---|
| `core/node.py` | The composition root: constructs and wires every subsystem, defines start/stop, exposes high-level operations (pair, send) and routes inbound connection types |
| `core/version.py` | Single source of truth for the version label (manual version + build-time git tag) |
| `core/_build_tag.py` | Generated at build time by the PyInstaller specs (git short hash); not in git |

### Wire protocol & networking
| File | Why it exists |
|---|---|
| `core/transfer.py` | The framed protocol, the TCP listener (all connection types), the file send/receive logic, framing helpers used by *every* other protocol (`send_frame`, `recv_frame`) |
| `core/limits.py` | Admission control: trusted subnets, per-IP connection caps, token-bucket rate limiting |
| `core/discovery.py` | mDNS advertise/browse/resolve; the online-peer registry |

### Security & trust
| File | Why it exists |
|---|---|
| `core/crypto.py` | The cryptographic primitives: ECDH, HKDF derivations, AES-GCM seal/open, PIN derivation, the chunk-nonce scheme |
| `core/pairing.py` | The pairing handshake and the PIN-confirmation session state machine |
| `core/trust_store.py` | Persistent identity + paired peers + trust keys, encrypted at rest via keyring |

### Clipboard
| File | Why it exists |
|---|---|
| `core/clipboard.py` | Cross-platform facade: snapshot model (text/image/file-copy), read/write/change-count dispatch, safe wrappers |
| `core/clipboard_mac.py` | macOS specifics: NSPasteboard types, TIFF→PNG, file-copy detection |
| `core/clipboard_win.py` | Windows specifics: CF_DIB↔PNG, CF_HDROP file-copy detection |
| `core/sync.py` | The clipboard sync engine: watcher, channels, handshake, sequence/anti-replay validation |

### Keyboard & mouse sharing (KVM)
| File | Why it exists |
|---|---|
| `core/kvm.py` | The engine: link/control state machines, handoff protocol, event routing, watchdog, diagnostics |
| `core/kvm_events.py` | The binary wire codec for events (compact, high-rate) |
| `core/kvm_geometry.py` | Screen-seam math: jump zones, fractions, entry/return points, topology checks |
| `core/kvm_keymap.py` | Key-code tables: HID ↔ macOS virtual keycodes ↔ Windows scan codes; modifier masks; the escape-chord definition |
| `core/kvm_platform_mac.py` | macOS input capture/injection: CGEventTap, cursor association, permissions, Secure Input health |
| `core/kvm_platform_win.py` | Windows input capture/injection: low-level hooks, SendInput, warp bookkeeping |

### OS integration & packaging
| File | Why it exists |
|---|---|
| `scripts/embed_share_extension.sh` | Post-build: compile + embed the Swift Share Extension into `SecureShare.app` |
| `scripts/build_share_extension.sh` | Builds the extension bundle with `swiftc` |
| `scripts/install_windows_share.ps1` / `uninstall_windows_share.ps1` | Register/remove the "Send with SecureShare" Explorer verb |
| `native/share_extension/` | The Swift Share Extension itself (`ShareViewController.swift` + `Info.plist`), handed off to the app via the `secureshare://` URL scheme |
| `secure-share-mac.spec` / `secure-share-win.spec` | PyInstaller recipes (hidden imports, data, Info.plist, build tag) |
| `.github/workflows/ci.yml` | CI: unit+socket tests on macOS/Windows × Python 3.10/3.12 |

### Tests
| File group | Why it exists |
|---|---|
| `tests/conftest.py` | Fixtures: two real loopback Nodes, pairing helper, temp dirs, socket-availability guard |
| `tests/test_crypto.py`, `test_trust_store.py`, `test_kvm_keymap.py`, `test_kvm_geometry.py`, `test_kvm_events.py`, `test_kvm_platform_*.py`, `test_tray_menu.py` | Pure unit tests (marker `unit`) |
| `tests/test_pairing.py`, `test_transfer.py`, `test_sync.py`, `test_sync_auth.py`, `test_limits.py`, `test_share_ipc.py`, `test_kvm.py` | Loopback integration tests (marker `socket`) |
| `tests/test_discovery.py` | Real mDNS test (marker `manual`, self-skipping) |

### Documentation & process
| File | Why it exists |
|---|---|
| `README.md` | User-facing description: features, security model, usage, build/test instructions |
| `COMPLETION.md` | Completion report of the rebuild from the legacy codebase (deliverables, bugs found/fixed) |
| `RELEASE.md` | Ship checklist: automated gates, two-device LAN checks, physical KVM checks, packaging |
| `docs/` | This documentation set |

## File inventory (complete)

```
core/            __init__.py        version guard + package doc
                 _build_tag.py      build-time git tag (generated)
                 clipboard.py       cross-platform clipboard facade
                 clipboard_mac.py   macOS pasteboard implementation
                 clipboard_win.py   Windows clipboard implementation
                 crypto.py          crypto primitives
                 discovery.py       mDNS discovery
                 kvm.py             KVM engine
                 kvm_events.py      binary event codec
                 kvm_geometry.py    seam math
                 kvm_keymap.py      key-code tables
                 kvm_platform_mac.py  macOS input platform
                 kvm_platform_win.py  Windows input platform
                 limits.py          admission control
                 node.py            composition root
                 pairing.py         pairing handshake
                 sync.py            clipboard sync engine
                 transfer.py        protocol + listener + file transfer
                 trust_store.py     persistent trust data
                 version.py         version label
tray/            app.py             tray application (UI)
                 logbook.py         KVM diagnostics window
                 icons/             tray icon assets
native/          share_extension/   macOS Share Extension (Swift)
scripts/         embed_share_extension.sh   post-build embed
                 build_share_extension.sh   extension build
                 install_windows_share.ps1  Explorer verb install
                 uninstall_windows_share.ps1 verb removal
tests/           17 test files + conftest.py + manual_checklist.md
secure-share-mac.spec / secure-share-win.spec   PyInstaller recipes
pyproject.toml / requirements.txt   packaging + dependencies
.github/workflows/ci.yml            CI
```

## Leftover / dev-only code worth knowing about

- `KIND_TAKE_CONTROL` in `kvm_events.py:30` — a **deprecated legacy
  event**, never emitted by the current engine; kept for table
  completeness.
- `kvm_events.KIND_EDGE_HIT` + `_on_edge_hit` in `kvm.py:1856` — a
  legacy informational hint (warp toward the seam); superseded by the
  acknowledged handoff. The engine still handles incoming edge hits but
  never sends them.
- `kvm_platform_mac.py` ships a **demo CLI** (`--spike`, `--controller`)
  for verifying cursor-association behavior on real hardware — dev
  tooling, not part of the app flow.
- `tray/logbook.py` — its own docstring says "temporary … remove after
  use"; currently shipped and wired to the tray menu.
- `COMPLETION.md` — historical rebuild report; the legacy
  `Cyber-Project` codebase it replaced is not part of this repository.

*Confirmed from code: `core/kvm_events.py:30`, `core/kvm.py:1856-1883`,
`core/kvm_platform_mac.py` (CLI block), `tray/logbook.py:1-2`,
`COMPLETION.md`.*