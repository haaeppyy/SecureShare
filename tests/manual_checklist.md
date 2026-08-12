# SecureShare Windows verification checklist

These steps must be run on a real Windows machine (the code paths are
Windows-only: pywin32 clipboard, keyring Credential Manager, pystray win32
backend, PyInstaller one-file build). Run with **two Windows machines on the
same LAN** for the cross-machine items.

## 0. Prerequisites

- Python 3.12 installed (`py -3.12 --version`).
- `pip install -r requirements.txt`
- Turn off Windows Defender Firewall for the app or allow inbound TCP on
  port 48620 (private networks only).

## 1. Build

```
pyinstaller --clean --noconfirm secure-share-win.spec
```

Expect: `dist\SecureShare.exe` (one-file, console-less). If pyinstaller is
not on PATH: `py -3.12 -m PyInstaller ...`.

- [ ] Build completes without errors
- [ ] `SecureShare.exe` launches; tray icon appears in the notification
      area (may need to expand the tray / "show hidden icons")
- [ ] Menu shows device name and "0 devices, 0 paired"

## 2. Discovery (two machines)

- [ ] Machine A and B on the same LAN, both running SecureShare
- [ ] Within ~15s both menus show "1 device(s), 0 paired" and the other
      machine's name appears under "Pair with device"

## 3. Pairing

- [ ] On A: "Pair with device" -> B's name -> PIN dialog appears
- [ ] On B: incoming pairing dialog appears with same PIN
- [ ] Confirm on both: both stores show "1 device(s), 1 paired"
- [ ] Negative test: confirm on A, deny on B -> pairing refused, no trust
      stored on either side (both still "0 paired")

## 4. File transfer

- [ ] A sends a file (any size, try >100 MB) to B: "Sent ... MB/s" toast
- [ ] File lands in `%USERPROFILE%\Downloads\SecureShare`, sha256 matches
- [ ] B sends a file to A: same result
- [ ] Negative test: unpaired machine sends -> transfer refused

## 5. Clipboard sync (text)

- [ ] Toggle "Clipboard sync" ON on both
- [ ] Copy text on A -> appears on B within ~1s; no echo loop (A's
      clipboard does not keep "changing")
- [ ] Copy text on B -> appears on A

## 6. Clipboard sync (images)

- [ ] Copy an image (e.g. screenshot via Win+Shift+S) on A -> appears on B
- [ ] Copy an image on B -> appears on A
- [ ] Copy a file in Explorer (Ctrl+C on a file) -> NOT synced (file
      copies are excluded by design)

## 7. Trust store

- [ ] After pairing, `%APPDATA%\SecureShare\trust.json` exists and is
      encrypted (contains "encrypted": true)
- [ ] Restart the app: peers are still paired (keyring persisted)
- [ ] "Unpair device" removes the entry after confirmation

## 8. Quit / restart

- [ ] Quit removes the tray icon and stops the process cleanly
- [ ] Second instance while first is running: binds next free port
      (48620+), still works

## 9. Keyboard & mouse sharing (KVM) — macOS

macOS injection needs Accessibility permission (System Settings →
Privacy & Security → Accessibility); the app toasts when it is missing.

- [ ] Enable sharing on A and B: check "Mouse & keyboard sharing"
- [ ] On B: menu → "Mouse & keyboard devices…" → A's device entry → check
      "Allow this device to control this Mac"
- [ ] Both sides set the seam: A's entry on B says "Right", B's entry on
      A says "Left" (defaults; adjust if your screens are laid out
      differently)
- [ ] Move the cursor past A's right edge → A's cursor is parked and
      hidden at the seam and the peer shows "ready"; only after B
      confirms is A's input suppressed ("controlling" toast) and B's
      cursor jumps to the mirrored position
- [ ] Type and scroll on A → input appears on B; B's clipboard / focus
      follow the shared cursor
- [ ] Check the tray menu on B during takeover → B's entry under "Mouse &
      keyboard devices…" shows "controlled by peer"; on A it shows
      "controlling"
- [ ] Move the cursor to B's left edge → control returns to B, cursor
      reappears on A parked just inside the seam
- [ ] Negative: while controlling, your keyboard input still reaches B
      instantly, but A's own mouse stops working (suppressed) only after
      the takeover was confirmed — no blind grabs
- [ ] Take control again, press the escape chord (Ctrl+Option+Space on
      macOS, Ctrl+Alt+Space on Mac control of Windows) → control returns
- [ ] Escape chord on the *controlled* machine also forces control back
- [ ] Negative: with "Allow control" OFF on B, moving past A's right
      edge does not take control and B shows a "refused" toast; moving
      away from the edge and back only ever announces it once per edge
      dwell
- [ ] Negative: disconnect A from the network mid-takeover → B regains
      local control and no stuck keys remain
- [ ] Negative: set A's seam for B to "Top" and B's seam for A to "Top"
      → both sides show a layout-mismatch toast and takeover is refused
      until fixed

## 10. Keyboard & mouse sharing (KVM) — Windows

The Windows platform (`kvm_platform_win.py`, scan-code injection,
SetCursorPos plus SendInput fallback, win32 hooks) is unverified here;
run the same checks as section 9. Notes:

- [ ] Windows capture uses `SendInput` with PS/2 scan codes so the
      remote keyboard follows the local layout
- [ ] Sentinel-tagged injected events are never re-forwarded, and hooks
      pass everything through while KVM is stopped (no eaten input
      after quit)
- [ ] SetCursorPos is verified after every warp; when the session is
      locked the SendInput fallback is exercised without error
- [ ] Extra side (AltGr/right Alt) is preserved by staying on the right
      variant; verify AltGr dead keys type correctly on a non-US layout
- [ ] Verify extended keys (arrows, Insert/Delete/Home/End, keypad
      Enter) work when controlling from macOS
- [ ] If Windows Defender SmartScreen blocks the unsigned exe: More info
      → Run anyway (dev build)
