# 1. Overview — What SecureShare Actually Is

## The problem it solves

People who own several computers (a laptop and a desktop, a work Mac and a
home Windows PC) constantly want to move things between them: a file, a
URL, a password, an image. The usual routes are USB sticks, emailing
yourself, or cloud services — all of which are slow, or require an account,
or send your data through someone else's servers.

SecureShare moves data **directly between your own devices over your local
network** (Wi-Fi or wired LAN). There are no accounts, no cloud, and the
Internet is not involved. Two machines that have never met cannot talk to
each other until a human on both sides explicitly approves the
relationship using a short PIN — the same idea as pairing Bluetooth
headphones or confirming a Signal contact.

The project goes one step further than file transfer: paired devices can
also **share a clipboard** (copy on one machine, paste on the other) and
**share one keyboard and mouse** (drive machine B from machine A by moving
the cursor across the edge of the screen, like an old multi-monitor
KVM-switch — the "KVM" in the name).

## Who uses it

The user is the owner of two or more desktop/laptop computers on the same
LAN, running macOS or Windows, who wants them to behave like one seamless
workspace. There is no server, no admin, and no third party anywhere in the
loop.

## What the user can do

- **Pair devices** — permanently establish trust between two machines
  using a PIN both screens display.
- **Send files** — from the tray menu, or straight from the OS: right-click
  a file in Finder/Explorer → "Send to SecureShare".
- **Receive files** — anything sent arrives in a `SecureShare` folder
  inside Downloads, verified intact and untampered.
- **Toggle clipboard sync** — when on, any text or image you copy on one
  device appears in the clipboard of all paired, online devices.
- **Toggle mouse & keyboard sharing** — move the pointer past the screen
  edge to drive the paired machine; grant or deny each device permission
  individually.
- **Unpair, download-folder shortcuts, and a diagnostics log** — all from
  the menu-bar / tray icon.

## The major parts of the system

```
┌──────────────────────────────────────────────────────────────┐
│                    Your machine (macOS or Windows)            │
│                                                              │
│  ┌──────────────────────┐                                    │
│  │  Tray application    │  menu-bar icon + dialogs (UI)      │
│  └──────────┬───────────┘                                    │
│             │ posts UI events                                │
│  ┌──────────▼───────────┐                                    │
│  │  Node (core)         │  the "brain": everything runs here │
│  │  ┌─────────┐ ┌─────┐ │                                    │
│  │  │Pairing  │ │Sync │ │  ┌───────┐  ┌────────────────┐     │
│  │  │+crypto  │ │clip │ │  │KVM    │  │Transfer server │     │
│  │  └────┬────┘ │board│ │  │engine │  │+ client        │     │
│  │       │      └──┬──┘ │  └───┬───┘  └───────┬────────┘     │
│  │  ┌────▼──────────▼─────┼─────▼─────────────▼────────┐     │
│  │  │  Discovery (mDNS)   │  Trust store (disk+keyring) │     │
│  │  └─────────────────────┘                            │     │
│  └──────────────────────────────────────────────────────┘    │
│             │                    │                           │
│        LAN (TCP)            LAN (mDNS UDP)                    │
└─────────────┼───────────────────┼────────────────────────────┘
              ▼                   ▼
      Your other machine (identical app)
```

How the parts work together:

1. **Discovery** — every running copy announces itself on the LAN using
   multicast DNS and listens for announcements from other copies. It is the
   "meet-and-greet" layer: it tells you who is online and how to reach them.
2. **Pairing** — when two devices first meet, they exchange cryptographic
   keys and both show a 6-digit PIN. Only after humans on both machines
   confirm the PINs match is the relationship stored.
3. **Trust store** — the permanent record of which devices you trust,
   stored encrypted on disk using your OS credential vault (Keychain /
   Credential Manager) as the master key.
4. **Transfer server** — one TCP listener on every machine handles *all*
   incoming connections: file transfers, pairing requests, sync channel
   openings, and KVM channel openings. Every byte is authenticated with
   AES-GCM encryption keyed by the trust established during pairing.
5. **Sync** — a background watcher polls the local clipboard and mirrors
   changes to paired peers over a persistent encrypted channel.
6. **KVM engine** — when enabled, captures local keyboard/mouse events and
   forwards them to the paired machine over a low-latency encrypted
   channel, and injects events received from the peer. Control is an
   acknowledged handshake, not a blind grab.

## Where information enters

- Files: user picks them in the tray menu, or the OS hands them to the app
  (macOS Share Extension / Finder Services, Windows right-click verb).
- Clipboard content: the OS clipboard, polled by the sync watcher.
- Keyboard/mouse: OS input events, captured by platform hooks.

## Where information is stored

- **Paired-device records and trust keys**: one JSON file
  (`trust.json`) in the OS app-data directory, encrypted with a key
  derived from the OS keyring (fallback: plaintext with `0600`
  permissions).
- **Received files**: `~/Downloads/SecureShare` (configurable).
- Nothing else persists. There is no database server and no cloud.

## The important outputs

- Files written to the peer's download folder, byte-identical and
  tamper-verified.
- Clipboard contents mirrored to paired machines.
- Remote keyboard/mouse events injected into the target machine.
- Status messages shown in the tray menu and (for errors only) as OS
  notifications.

---

## Project in 60 seconds

> SecureShare is a menu-bar / tray app for macOS and Windows that lets one
> person's own computers talk to each other over the local network with no
> accounts and no cloud. When two machines first meet, they perform an
> encrypted handshake and both display the same 6-digit PIN; once a human
> on each side confirms the codes match, the machines trust each other
> forever. From then on they can send files to each other (encrypted in
> 1 MiB chunks, verified piece by piece), mirror clipboard text and images,
> and share one keyboard and mouse across screens. Devices find each other
> by announcing themselves with multicast DNS — no server needed. All
> trust data lives in an encrypted JSON file on each machine, unlocked by
> the OS keychain. Everything else is LAN-only: nothing ever touches the
> Internet.

*Confirmed from code: README.md, core/node.py, core/transfer.py, core/pairing.py, core/discovery.py, core/trust_store.py, core/sync.py, core/kvm.py, tray/app.py.*