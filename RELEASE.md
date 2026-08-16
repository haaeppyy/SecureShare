# SecureShare release checklist

Every release must be verified on **macOS and Windows** before shipping.
The CI matrix (`unit or socket` groups on Python 3.10 and 3.12) gates
automated checks; the items below are the parts CI cannot do.

## 1. Automated gates (both OSes)

- [ ] `python -m pytest tests -m "unit or socket" -q` passes on Python 3.10
- [ ] `python -m pytest tests -m "unit or socket" -q` passes on Python 3.12
- [ ] No warnings about unknown markers; socket group is NOT skipped on the
      test machine (the skip is only for socket-less sandboxes).

## 2. Two-device checks (one macOS + one Windows, same LAN)

- [ ] mDNS discovery: each device lists the other in the tray menu.
- [ ] Pairing: PIN shown on both screens, matches; trust persists across an
      app restart on both sides.
- [ ] File transfer both directions; a file that already exists in the
      download folder arrives as `name-1.ext` and the original is byte-for
      byte untouched.
- [ ] Clipboard sync: text and an image copy across in both directions with
      no echo loop.
- [ ] `--max-transfer-size` and `--trusted-subnets` flags are accepted and
      enforced (oversized transfer refused; out-of-subnet peer refused).
- [ ] OS share entry (macOS: Quick Actions/Services -> Send to SecureShare;
      Windows: right-click -> Send with SecureShare) opens the single
      device-picker; multi-select sends all files to one device; works
      with the app not running (it starts and picks up the request).
- [ ] Idle posture: with the app running and no transfers or dialogs,
      Activity Monitor / Task Manager shows ~0% CPU after the first minute
      (adaptive main-thread pump, clipboard change-count gate, idle
      discovery resolver).

## 3. Physical KVM (real input hardware)

- [ ] macOS: Accessibility permission granted; enable the sharing toggle
      again if macOS did not prompt.
- [ ] Windows: KVM sharing works without an administrative elevation prompt
      (driver-free SendInput path).
- [ ] Take control over the seam from each side; pointer mirrors position.
- [ ] Hand back via the peer's seam, the escape chord
      (Ctrl+Alt+Space / Ctrl+Option+Space), and link loss.
- [ ] Held keys release on the far side when control changes hands or the
      link drops.
- [ ] A second device that is paired but has consent OFF is refused control
      (one error toast per edge dwell, not a repeat spam).
- [ ] Mid-control link kill (e.g. kill the app on the controller) returns
      the target to local control with the cursor visible and no keys stuck.
- [ ] Stuck-state regression: while one side controls, the peer's control
      attempt shows an error toast ("is busy") and, once the controller
      returns, the peer can take over again (state is never frozen).
- [ ] A failing injection (e.g. temporarily revoke the Accessibility
      permission mid-session) degrades one input event without dropping
      the control session or the link.

## 4. Network posture

- [ ] Listener is reachable on the LAN only; `lsof -iTCP:48620` shows the
      expected interface(s); no port forward exists on the router.
- [ ] Host firewall guidance from README ("Network exposure") was followed;
      the app still works after the firewall rules are applied.
- [ ] macOS and Windows installers (PyInstaller specs) launch and run the
      full suite of checks above.

## 5. Packaging

- [ ] `pyinstaller --clean --noconfirm secure-share-mac.spec` builds on macOS.
- [ ] `pyinstaller --clean --noconfirm secure-share-win.spec` builds on Windows.
- [ ] macOS: `scripts/embed_share_extension.sh` ran (registers the
      NSServices entry; embeds the Share Extension for Developer-ID builds).
- [ ] Windows: `scripts/install_windows_share.ps1` ran against the built exe.
- [ ] The frozen app starts, pairs, transfers and syncs (smoke test of the
      whole suite on the packaged binary).
- [ ] Signed/notarized if distributing outside the LAN (out of scope
      otherwise).