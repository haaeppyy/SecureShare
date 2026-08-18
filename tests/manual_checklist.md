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

## 2b. Right-click share (macOS)

- [ ] Right-click a file -> Quick Actions/Services -> "Send to SecureShare"
      (after `./scripts/embed_share_extension.sh` + lsregister)
- [ ] Picker appears listing paired devices; picking one sends the file
- [ ] Select 3 files -> ONE picker; all 3 send to the chosen device
- [ ] Send while the app is NOT running -> app starts, picker appears
- [ ] With a Developer ID signing identity: `SIGN_IDENTITY="Developer ID
      Application: ..." ./scripts/embed_share_extension.sh` -> extension
      also lists under Finder Share menu (macOS 26+ ignores ad-hoc)

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

## 4b. Right-click share (Windows)

- [ ] `powershell -ExecutionPolicy Bypass -File scripts\install_windows_share.ps1`
      ran; right-click any file shows "Send with SecureShare"
- [ ] Right-click a file -> Send with SecureShare -> picker appears listing
      paired devices; choosing one sends the file (sha256 matches)
- [ ] Select 3 files -> Send with SecureShare -> ONE picker dialog appears;
      picking a device sends all 3
- [ ] Send while the app is NOT running -> the app starts, shows the picker
- [ ] `uninstall_windows_share.ps1` removes the menu item

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
- [ ] Move the physical mouse, click, or scroll on B → control returns to B,
      cursor reappears on A parked just inside the seam
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
- [ ] Negative: while A controls B, move a third paired device C (consent
      on) onto B's edge → B shows a "busy" error toast, and once A hands
      back, C can take over immediately (no frozen state)
- [ ] Negative: revoke Accessibility from the app mid-takeover → a key
      press on A degrades without killing the session; restoring the
      permission resumes injection
- [ ] Negative: set A's seam for B to "Top" and B's seam for A to "Top"
      → both sides show a layout-mismatch toast and takeover is refused
      until fixed

## 9b. KVM handoff diagnostics — macOS controller cursor

Problem A: while a Mac controls Windows the Mac cursor must stay parked at
the seam center; physical Mac movement is swallowed and forwarded only. The
engine now records every `CGAssociateMouseAndMouseCursorPosition` attempt
(`assoc_false/assoc_true/assoc_errors/assoc_calls` in the platform
diagnostics), plus edge latches (`blocked_edges`) and transition reasons.

- [ ] Isolated platform check: `python -m core.kvm_platform_mac --controller 10`
      on the Mac. Move the physical mouse during the 10 s run.
      Expected: `mode=controlling`, `cursor=(center)` stays parked while the
      `mouse rel=(dx,dy)` lines keep printing (forwarded, not applied);
      `assoc_false=1`, `assoc_true=0`, no `NEW_ASSOC` lines while running;
      final line shows `assoc_true=1` after the restore. A cursor that moves
      despite `assoc_false=1` and a clean record points at macOS/device/
      external software, not this code path.
- [ ] Full-flow check in the real app (Mac controls Windows):
      - A controls B; while controlling, move the Mac mouse for ~10 s.
      - A's cursor must remain parked (hidden at the seam center) and
        Windows' cursor must follow the movements.
      - Read the F6 diagnostics (engine state, `platform.mode`,
        `assoc_false/assoc_true`, `blocked_edges`, recent transitions).
      - Expected: engine `state=controlling`, `platform.mode=controlling`,
        `assoc_false == 1`, `assoc_true == 0` while active, and no
        `set_delegation("local")`/True association until revert.
- [ ] Handback latch (Problem B): with A controlling B, wiggle B's physical
      mouse → both devices become local; A's menu shows "local" and A does
      NOT immediately re-take B even though A's cursor sits near the seam;
      A must move clearly away from the edge and back to take control again.
      Check `blocked_edges` shows A's side latched right after the revert
      and empty after A's cursor left the latch zone.
- [ ] B then moves its own mouse to its edge and controls A (the
      former-controller latch must not block the new direction).
- [ ] Regression: escape chord (Ctrl+Option+Space), channel loss mid-
      takeover, and repeated deliberate edge handoffs all still behave as
      in section 9.

## 9c. KVM regression check — held keys, jitter, reverse direction

F6 diagnostics now expose `handoffs` (id/role/stage per peer),
`denial_latch`, `last_request` / `last_revert` and the `request_log` /
`revert_log` rings (16 entries each). Request decisions: `accepted`,
`rejected reason=denied|topology|busy|unavailable|closed`,
`ignored reason=denial_latch|duplicate`. Reverts record `accepted` on
wire-match, then `completed` once both sides are local.

Version parity: both devices must show the SAME `Version: x.y.z (hash)`
in the tray menu (hash = git short hash baked in at build time); rebuild
with `git pull origin KVM` + the spec when they differ.

Log book: tray menu → `KVM log book…` shows the timestamped status
stream (control taken/released on both sides, refusals with reasons);
`Dump diagnostics` prints the engine + platform records.

- [ ] Version parity: Mac and Windows tray menus show identical
      `Version:` labels.
- [ ] Log book: Mac controls Windows → Mac's log book shows
      "Took control of <Windows>"; Windows' shows "<Mac> took control of
      this device".
- [ ] Revert with reason: Windows physical mouse moves → both log books
      show the release with "physical mouse moved on the controlled
      device"; escape chord shows the chord reason.
- [ ] Held keys repeat (Regression 1): Mac controls Windows, hold
      Backspace → characters delete repeatedly (Windows does not
      auto-repeat SendInput, the Mac forwards autorepeat events now).
- [ ] No jitter / no handback under a sustained stream (Regression 2):
      Mac controls Windows and moves the mouse continuously for ~30 s →
      the Windows cursor is smooth, no flicker, no "Released control"
      toast; Windows' `reverts_sent` stays 0 and `request_log` shows no
      new request mid-stream.
- [ ] Windows physical reclaim: while Mac controls Windows, move the
      Windows mouse → both become local, `revert_log` shows
      `accepted` then `completed state=local` on the Mac.
- [ ] Mac re-take after handback (Regression 3 fix): after Windows
      reclaims, move the Mac cursor straight to the edge again (no need
      to pull it away first) → Mac takes control again once the 2 s
      grace has passed.
- [ ] Reverse direction (Windows controls Mac): with the Windows cursor
      away from its edge, cross Windows' seam once → Windows controls
      the Mac; Mac's `last_request` decision is `accepted` even while its
      former-controller edge latch is set (`blocked_edges` non-empty).
      If it fails, read `last_request` / `request_log` on the Mac:
      `rejected reason=denied` (consent off) vs `topology` (seam
      mismatch) vs `busy` (stuck active handoff) vs `unavailable` /
      `closed` (no platform / channel) vs nothing at all (Windows never
      sent: check Windows' own `last_request` for `busy`/`denied`).
- [ ] Regression: escape chord, channel loss, and repeated deliberate
      edge handoffs still behave as in section 9.

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
