# SecureShare

LAN-only file transfer and clipboard sync between your own devices, with a
menu-bar / tray app. No accounts, no cloud, no Internet — devices find each
other on the local network and are trusted only after a PIN handshake you
verify out of band.

> Replaces the legacy `Cyber-Project` codebase. That project's MySQL-based
> credential store and PHP-style web UI are retired; nothing is imported
> from it.

## Features

- **Pairing with PIN verification** — ECDH (P-256) key exchange over TCP,
  both screens show the same 6-digit PIN, and trust is only stored after a
  human confirms the codes match (defeats LAN man-in-the-middle).
- **Encrypted file transfer** — AES-256-GCM per 1 MiB chunk with a
  random nonce prefix + chunk counter; the header bytes authenticate every
  chunk, so tampering is detected. Files stream with flat memory use.
- **Clipboard sync (optional, off by default)** — text and images are
  mirrored to paired devices over a persistent encrypted channel; images
  use NSPasteboard on macOS and CF_DIB/CF_HDROP on Windows.
- **Keyboard & mouse sharing (optional, off by default)** — drive a paired
  device's pointer and keyboard from one machine: move the cursor past the
  seam edge to take control, and back again to release. The seam side is
  per-device (`left/right/top/bottom`), unequal screen sizes align by
  proportional position, and control is handed back with the same gesture,
  the escape chord (Ctrl+Alt+Space), or automatically on link loss.
- **LAN discovery** — mDNS/DNS-SD via `zeroconf`; no server required.
- **Trust store** — trust keys are encrypted at rest with a Fernet key
  derived from a keyring-managed master secret (macOS Keychain / Windows
  Credential Manager). If the keyring is unavailable, falls back to a
  chmod-600 plaintext file.
- **Tray app** — menu-bar / system-tray icon with pair/send/unpair actions,
  clipboard-sync toggle, KVM menu (sharing toggle, per-peer "allow control"
  consent and seam side), and PIN dialogs.

## Keyboard & mouse sharing (KVM)

Paired devices can share one keyboard and mouse. In the tray menu, check the
single **Mouse & keyboard sharing** switch. Device consent and screen placement
live under **Mouse & keyboard devices…**, where each paired device also shows a
live row of its **KVM status** (`offline`, `connecting`, `linked`, `ready`,
`controlling`, `controlled by peer`, …). Link and control are deliberately
separate: a device that is merely online is never shown as connected.

- **Allow this device to control this Mac** — lets that device take over your
  pointer and keyboard. This is a toggle, and is off by default.
- **This device is on this side of this Mac** — where the peer's screen is
  relative to yours (left/right/top/bottom). Both sides must agree; mismatched
  placements are detected and shown as a layout mismatch toast instead of
  a broken seam.

Usage: move the cursor past the shared edge (a 3 px jump zone) to take
control. Takeover is acknowledged, never a blind grab: your cursor is parked
and hidden at your seam while the peer confirms it is ready; only then does
your local input get suppressed and the peer's cursor appears at the mirrored
position. Move through the far edge of the controlled screen to return in a
smooth, extended-display-style handoff. Moving the physical mouse, clicking,
scrolling, or pressing a key on the controlled device also releases control;
the emergency
chord — **Ctrl+Alt+Space** (Windows / **Ctrl+Option+Space** on macOS) — works
at any time on either machine. A refused,
failed or expired handoff returns both sides to local control, and a refusal
is announced at most once per edge dwell (moving away from the edge resets
it). Keys held on either side are released automatically when control changes
hands or the link drops.

On macOS, enabling this asks for Accessibility permission. If macOS does not
show its prompt, enable SecureShare in System Settings → Privacy & Security →
Accessibility, then turn **Enabled** on again.

## Security model

- Everything is LAN-only; the listener binds to local interfaces.
- Pairing: ephemeral ECDH per handshake; the shared secret is HKDF-derived
  into a long-term trust key; the PIN is a hash of the shared secret, so a
  MITM that swapped public keys produces different PINs on the two screens.
- Transfer: per-chunk AES-GCM with a fresh nonce (8 random bytes + a
  32-bit chunk counter) — no nonce reuse. The exact header frame bytes are
  AAD for every chunk.
- Sync: each message is sealed with AES-GCM using a key derived (HKDF) from
  the trust key plus a fresh 12-byte random nonce prepended to the message.
- KVM: one persistent encrypted binary channel per peer. The channel key
  binds protocol version, both fingerprints, the roles and both channel
  nonces into the trust key (HKDF); the first binary frame is the
  authenticated key confirmation, and every event after it is AES-GCM with
  a monotonic per-direction nonce counter. Control always reverts to local
  on channel loss, peer refusal, the escape chord or a stall, and
  ALL_KEYS_UP reconciles both sides' key states. Consent is per peer and
  enforced on the would-be controlled side at takeover time.
- Trust keys are stored encrypted at rest (keyring). If the keyring is
  removed or the secret is wrong, the store starts empty rather than
  crashing (documented tradeoff).

## Layout

```
core/            protocol + logic (no UI): crypto, discovery, transfer,
                 pairing, trust_store, node, sync, clipboard_*, kvm_*
                 (kvm_events, kvm_geometry, kvm_keymap, kvm_platform_*)
tray/app.py      pystray + tkinter tray application (incl. KVM menu)
tray/icons/      tray icon assets
tests/           pytest suite
secure-share-mac.spec / secure-share-win.spec   PyInstaller recipes
```

## Run from source

Requirements: **Python 3.10+ (3.12 recommended)**. Older interpreters are
refused with a clear message at startup.

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python tray/app.py --name "My Mac"
```

Optional flags: `--data-dir`, `--download-dir`, `--port` (default 48620,
the listener searches upward if busy), `--max-transfer-size` (bytes,
default 10 GiB), `--trusted-subnets` (comma-separated CIDRs, e.g.
`192.168.1.0/24`; default: any LAN peer).

## Network exposure

SecureShare is LAN-only but it **is** a TCP server: it listens on
`0.0.0.0:48620` on all interfaces. Do **not** port-forward it or expose it
through a VPN gateway. To restrict who may connect:

- `--trusted-subnets 192.168.1.0/24` refuses connections from any other
  subnet at the listener before any data is read (also disables KVM, sync
  and pairing from outside the allowed networks).
- The listener caps concurrent connections per IP and rate-limits
  unauthenticated requests to limit LAN denial-of-service.
- Host firewall: on macOS allow the app only for the local network
  (`pf`/Application Firewall: block incoming, allow only your LAN range);
  on Windows use Windows Defender Firewall and restrict the rule to your
  private profile and local subnets.

## Tests

```bash
python -m pytest tests -q                      # unit group (default)
python -m pytest tests -m "unit or socket" -q  # unit + loopback integration
```

Tests are grouped by marker: `unit` (pure logic), `socket` (loopback
integration: transfers, sync, pairing, KVM engine), and `manual` (real
mDNS, real clipboard, physical KVM). Groups that need sockets or mDNS
**skip** with a clear reason instead of failing when the environment
cannot provide them.

Notes: `tests/test_discovery.py` skips if loopback mDNS does not resolve;
`tests/test_pairing.py::test_pin_mismatch_refuses_trust` uses a MITM proxy
on `127.0.0.1:49602`. The KVM engine tests (`tests/test_kvm.py`) run two
real nodes on loopback with a fake input platform; the keymap, geometry
and event-codec tests are pure unit tests.

## Build

macOS (build on macOS):

```bash
pyinstaller --clean --noconfirm secure-share-mac.spec
# -> dist/SecureShare.app
# register Finder integration (services + optional Share Extension):
./scripts/embed_share_extension.sh
```

Windows (build on Windows):

```bat
pyinstaller --clean --noconfirm secure-share-win.spec
:: -> dist\SecureShare.exe
:: add "Send with SecureShare" to the right-click menu:
powershell -ExecutionPolicy Bypass -File scripts\install_windows_share.ps1
```

The app is unsigned; on first launch macOS Gatekeeper may require
right-click → Open.

## Share a file from the OS file pickers

- **macOS**: right-click a file → Quick Actions/Services → **Send to
  SecureShare** (via the `NSServices` entry; macOS 26+ no longer enumerates
  ad-hoc-signed Share Extensions — the native `com.apple.share-services`
  extension in `native/share_extension/` is embedded for when the app is
  signed with a Developer ID).
- **Windows**: right-click a file → **Send with SecureShare** (registry
  verb registered by `scripts/install_windows_share.ps1`).
- Either way the file lands in the tray app's single "Send to device"
  dialog; pick a paired device and it transfers with the normal send path.
  A single instance always handles the request (loopback IPC on
  `127.0.0.1:48625`; extra instances forward and exit).

## Known limitations

- Clipboard file copies (Finder/Explorer drag-copy) are detected and never
  synced (out of scope).
- Sync is currently always-on LAN-only; there is no WAN mode.
- KVM supports the standard 104-key US set; media keys, IME and dead keys
  are not forwarded. The seam is computed against the union bounds of all
  monitors (exact for single-monitor setups; multi-monitor layouts are v2).
- Legacy `Cyber-Project-main` stays untouched in the parent directory.
