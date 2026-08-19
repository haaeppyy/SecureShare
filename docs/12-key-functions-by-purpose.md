# 12. What the Important Parts of the Code Actually Do

Grouped by *purpose*, not by file. Each group: what it accomplishes, then
the implementation references.

## Handling login / starting the app

The app has no user accounts. "Login" is just: parse arguments → decide
single-instance ownership → build the Node → start subsystems → run the
UI pump. The identity is a local UUID, not a credential.

**Implementation references**
- `main()` — `tray/app.py:1233`
- `TrayApp.run()` — `tray/app.py:126`
- `Node.__init__` / `Node.start()` — `core/node.py:33` / `core/node.py:86`
- `TrayApp._pump()` (main UI loop) — `tray/app.py:381`

## Establishing trust between two devices (pairing)

Two ephemeral EC key pairs meet over TCP; both sides derive the same
shared secret, the same trust key, and the same 6-digit PIN; both humans
verify the PIN; only then is the trust key stored. Refusal or timeout
leaves nothing behind.

**Implementation references**
- `PairingManager.initiate()` — initiates toward a discovered device — `core/pairing.py:186`
- `PairingManager.on_pair_request()` — accepts an inbound request — `core/pairing.py:167`
- `PairingSession.accept()/deny()/confirm()/abort()` — the human-driven state machine — `core/pairing.py:101-151`
- `crypto.derive_trust_key()` / `crypto.derive_pin()` — `core/crypto.py:36` / `core/crypto.py:71`
- `TrustStore.add_peer()` — persists the trust key — `core/trust_store.py:186`
- `TrayApp._show_pair_dialog()` — the PIN dialog — `tray/app.py:529`

## Sending a file to a paired peer

Look up the peer in the discovery registry and the trust store; derive a
per-transfer key; stream 1 MiB encrypted, authenticated chunks; await the
ack; report speed and completion.

**Implementation references**
- `Node.send_file()` — resolves peer + trust key, calls the transfer client — `core/node.py:115`
- `transfer.send_file()` — the whole send loop — `core/transfer.py:105`
- `TrayApp._send_to()` — background thread + progress wiring — `tray/app.py:1163`

## Receiving a file from a paired peer

Admission checks (paired? size? space? name?) → per-chunk decrypt +
authenticate into a temp file → fsync → atomic rename → ack. Any failure
deletes only the temp file.

**Implementation references**
- `TransferServer._handle_transfer()` — `core/transfer.py:321`
- `TransferServer._reserve_path()` / `_release_path()` — collision-safe names — `core/transfer.py:440`
- `TransferServer.start()` — binds the listener — `core/transfer.py:207`

## Finding peers on the LAN (discovery)

Announce this device via mDNS; browse for `_secureshare._tcp.local.`;
resolve addresses in a dedicated thread; keep a live registry; notify on
change. Updated announcements re-resolve so sleep/wake, DHCP renewal, and
Wi-Fi/VPN changes are picked up.

**Implementation references**
- `Discovery.start()` / `stop()` — `core/discovery.py:95` / `core/discovery.py:120`
- `Discovery._resolve_loop()` / `_resolve()` — `core/discovery.py:172` / `core/discovery.py:220`
- `Discovery._pick_address()` — skips unusable addresses (link-local v6, etc.) — `core/discovery.py:23`

## Watching and mirroring the clipboard (sync)

A 400 ms watcher uses a cheap revision counter, reads the snapshot only
on change, skips file copies, records its own writes' signatures (echo
prevention), and encrypts+forwards changes over per-peer channels with
monotonic sequence numbers.

**Implementation references**
- `SyncEngine._watch_loop()` / `_watch_once()` — `core/sync.py:423` / `core/sync.py:446`
- `SyncEngine.ensure_connections()` — outbound channel setup — `core/sync.py:350`
- `SyncEngine.on_inbound()` — inbound handshake (challenge/response) — `core/sync.py:210`
- `SyncEngine.handle_frame()` — validation + clipboard write — `core/sync.py:294`
- `SyncChannel.send()` — sealing frames — `core/sync.py:125`

## Sharing the keyboard and mouse (KVM engine)

Capture local input; detect the seam edge; run the acknowledged handoff
(request → ready → begin → active); forward/inject events; revert on any
of four triggers; reconcile key state; watch for stalls.

**Implementation references**
- `KVMEngine.on_local_mouse()` — seam detection + edge latches — `core/kvm.py:1108`
- `KVMEngine._on_control_request()` — the target decision chain — `core/kvm.py:1491`
- `KVMEngine._on_control_active()` — controller enters active — `core/kvm.py:1434`
- `KVMEngine._revert_control()` / `_revert_remote()` — safe return to local — `core/kvm.py:1631` / `core/kvm.py:1658`
- `KVMEngine._watchdog_loop()` — timeouts + keyboard health — `core/kvm.py:1009`
- `KvmChannel._writer_loop()` — priority queues + coalescing — `core/kvm.py:386`

## Capturing and injecting OS input (platform layer)

- **macOS:** CGEventTap capture with per-event suppression decisions;
  CGEventPost injection below the capture tap; cursor decoupling via
  CGAssociate; Accessibility/Input Monitoring permission handling;
  Secure Input health detection with tap restart.
- **Windows:** low-level mouse/keyboard hooks; suppression by returning
  1 from the hook proc; SendInput with scan-code injection and a
  warp-ignore queue.

**Implementation references**
- `MacInputPlatform.start()` / `_handle_tap()` / `set_delegation()` — `core/kvm_platform_mac.py`
- `WindowsInputPlatform.start()` / hook callbacks / `set_delegation()` — `core/kvm_platform_win.py`
- Interface contract — `InputPlatform` — `core/kvm.py:201`

## Storing trust data encrypted at rest

Load the store; encrypt/decrypt with a Fernet key derived from the
keyring master secret; fall back to 0600 plaintext when keyring is
unavailable; write atomically (temp + rename).

**Implementation references**
- `TrustStore._load()` — `core/trust_store.py:120`
- `TrustStore.save()` — `core/trust_store.py:148`
- `_keyring_fetch()` — creates/reads the master secret — `core/trust_store.py:44`

## Routing inbound connections

The single listener reads the first frame and dispatches by type:
`transfer` (file receive), `pair_request` (pairing), `sync_open`
(sync channel), `kvm_open` (KVM channel), anything else (refused).

**Implementation references**
- `TransferServer._handle_connection()` — admission + dispatch — `core/transfer.py:262`
- `Node._on_other()` — routing to pairing/sync/KVM — `core/node.py:160`

## Handling OS share requests (single instance)

Parse `-sendFile`, `secureshare://send?files=...`, and plain paths;
forward to the primary instance over loopback IPC; the primary aggregates
a 1.5 s batch and shows one device picker.

**Implementation references**
- `parse_share_argv()` — `tray/app.py:1203`
- `share_files_from_url()` / `forward_share_request()` — `tray/app.py:47` / `tray/app.py:57`
- `_share_ipc_loop()` / `_handle_share_ipc()` — `tray/app.py:233` / `tray/app.py:245`
- `_show_share_dialog()` — `tray/app.py:299`

## Building and refreshing the tray menu

Rebuilds the menu from live state (peers, pairing sessions, transfers,
sync/KVM toggles, per-peer KVM status/side/consent), but only when the
state signature changed, at most every 2 s.

**Implementation references**
- `TrayApp._build_menu()` — `tray/app.py:775`
- `TrayApp._refresh_menu_if_stale()` — `tray/app.py:462`
- `TrayApp._peer_kvm_status()` — per-peer status labels — `tray/app.py:1015`

## Surfacing errors to the user (notifications policy)

Only error-level messages become OS notifications; errors arriving in the
same short window are combined into one notification; everything else
goes to the log book when open. The idle pump wakes every 1 s, or every
100 ms while anything active.

**Implementation references**
- `TrayApp._toast()` / `_flush_toasts()` — `tray/app.py:411` / `tray/app.py:423`
- `TrayApp._pump_interval()` — `tray/app.py:360`
- `tray/logbook.py` — the diagnostics window