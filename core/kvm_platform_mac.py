"""macOS input platform for keyboard/mouse sharing.

Capture is a Quartz CGEventTap on a dedicated CFRunLoop thread. The tap
runs whenever the engine is started; ``set_delegation`` decides what the
callback does with each event:

    local       return the original event (apps see it normally) while
                also forwarding it watch-only to the engine, which uses
                it for seam detection
    controlling forward it to the engine (swallowed at the tap) and hide
                the cursor
    remote      physical mouse movement, clicks, and wheel input release
                control locally; keys still reach the engine so physical
                keyboard input releases control before input is swallowed

Injected events carry a kCGEventSourceUserData sentinel and the
native pid; the tap drops anything marked like that, so input never
echoes. The return seam is detected at injection time (the peer drives
our cursor with absolute moves), not by a poller.

Requires Accessibility permission for both the event tap and CGEventPost
(CGPreflightListenEventAccess / CGPreflightPostEventAccess).
"""

import os
import threading
import time

from .kvm_geometry import Monitor, ScreenLayout, in_jump_zone

SENTINEL = 0x5E4C0DE5

try:
    import Quartz
    from AppKit import NSScreen
    from CoreFoundation import (
        CFMachPortCreateRunLoopSource,
        CFMachPortInvalidate,
        CFRunLoopAddSource,
        CFRunLoopGetCurrent,
        CFRunLoopRemoveSource,
        CFRunLoopRun,
        CFRunLoopStop,
        kCFRunLoopCommonModes,
    )

    _QUARTZ_OK = True
except ImportError:  # pragma: no cover - non-macOS
    Quartz = None
    NSScreen = None
    CFMachPortCreateRunLoopSource = None
    CFMachPortInvalidate = None
    CFRunLoopAddSource = None
    CFRunLoopGetCurrent = None
    CFRunLoopRemoveSource = None
    CFRunLoopRun = None
    CFRunLoopStop = None
    kCFRunLoopCommonModes = None
    _QUARTZ_OK = False


class MacPlatformError(Exception):
    pass


def _q():
    if not _QUARTZ_OK:
        raise MacPlatformError("Quartz unavailable (not macOS or pyobjc missing)")
    return Quartz


class MacInputPlatform:
    def __init__(self):
        self.engine = None
        self._tap_port = None
        self._tap_runloop = None
        self._tap_thread = None
        self._mode = "local"
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._callback_ref = None
        self._soft_x = 0
        self._soft_y = 0
        self._soft_valid = False

    # -- lifecycle ------------------------------------------------------------

    def start(self, engine) -> None:
        if not self.permission_ok():
            self.request_permission()
        if not self.permission_ok():
            raise MacPlatformError("missing Accessibility permission")
        self.engine = engine
        self._stop.clear()
        self._callback_ref = self._make_callback()
        self._tap_thread = threading.Thread(target=self._tap_main, name="kvm-tap", daemon=True)
        self._tap_thread.start()

    def stop(self) -> None:
        # Never leave the user's pointing device decoupled if sharing stops
        # while this Mac is being controlled remotely.
        if _QUARTZ_OK:
            try:
                Quartz.CGAssociateMouseAndMouseCursorPosition(True)
            except Exception:
                pass
        self._stop.set()
        with self._lock:
            rl = self._tap_runloop
        if rl is not None:
            try:
                CFRunLoopStop(rl)
            except Exception:
                pass
        if self._tap_thread is not None:
            self._tap_thread.join(timeout=2)
        with self._lock:
            self._tap_port = None
            self._tap_runloop = None

    def permission_ok(self) -> bool:
        if not _QUARTZ_OK:
            return False
        try:
            listen = bool(Quartz.CGPreflightListenEventAccess())
            post = bool(Quartz.CGPreflightPostEventAccess())
        except AttributeError:  # pragma: no cover - very old macOS
            return True
        return listen and post

    def request_permission(self) -> bool:
        """Ask macOS for the required permissions when sharing is enabled."""
        if not _QUARTZ_OK:
            return False
        try:
            request_listen = getattr(Quartz, "CGRequestListenEventAccess", None)
            request_post = getattr(Quartz, "CGRequestPostEventAccess", None)
            if request_listen is not None:
                request_listen()
            if request_post is not None:
                request_post()
        except Exception:
            pass
        return self.permission_ok()

    def permission_detail(self) -> str:
        if not _QUARTZ_OK:
            return "Quartz unavailable (not macOS or pyobjc missing)"
        missing = []
        try:
            if not bool(Quartz.CGPreflightListenEventAccess()):
                missing.append("Input Monitoring")
        except AttributeError:
            pass
        try:
            if not bool(Quartz.CGPreflightPostEventAccess()):
                missing.append("Accessibility")
        except AttributeError:
            pass
        if not missing:
            return "all permissions granted"
        return "missing macOS permission: " + " and ".join(missing)

    # -- tap ------------------------------------------------------------------

    def _make_callback(self):
        def cb(proxy, etype, event, refcon):
            if event is None:
                return None
            if etype in (Quartz.kCGEventTapDisabledByTimeout, Quartz.kCGEventTapDisabledByUserInput):
                with self._lock:
                    port = self._tap_port
                if port is not None:
                    Quartz.CGEventTapEnable(port, True)
                return None
            return self._handle_tap(etype, event)

        return cb

    def _tap_main(self) -> None:
        q = _q()
        tap = q.CGEventTapCreate(
            q.kCGHIDEventTap,
            q.kCGHeadInsertEventTap,
            q.kCGEventTapOptionDefault,
            q.kCGEventMaskForAllEvents,
            self._callback_ref,
            None,
        )
        if tap is None:  # pragma: no cover - permission revoked mid-run
            self._stop.set()
            self.engine.on_status("KVM: Accessibility permission missing - tap failed")
            return
        with self._lock:
            self._tap_port = tap
            self._tap_runloop = CFRunLoopGetCurrent()
        source = CFMachPortCreateRunLoopSource(None, tap, 0)
        CFRunLoopAddSource(self._tap_runloop, source, kCFRunLoopCommonModes)
        q.CGEventTapEnable(tap, True)
        CFRunLoopRun()
        CFRunLoopRemoveSource(self._tap_runloop, source, kCFRunLoopCommonModes)
        CFMachPortInvalidate(tap)

    def _handle_tap(self, etype, event):
        if self._mode == "local":
            # Pass-through: return the original event so apps see it
            # normally, but still forward it watch-only to the engine
            # (seam detection).
            self._forward_local(event, etype)
            return event
        if self._mode == "controlling":
            self._forward(event, etype)
            return None
        if self._mode == "remote":
            self._forward_remote_input(event, etype)
            return None
        return None

    def _forward_local(self, event, etype) -> None:
        """Watch-only copy of local-mode input (never suppresses anything)."""
        self._forward(event, etype)

    def _forward_keys(self, event, etype) -> None:
        q = _q()
        engine = self.engine
        if engine is None:
            return
        user = q.CGEventGetIntegerValueField(event, q.kCGEventSourceUserData)
        pid = q.CGEventGetIntegerValueField(event, q.kCGEventSourceUnixProcessID)
        if user == SENTINEL or (pid and pid == os.getpid()):
            return
        try:
            if etype == q.kCGEventKeyDown:
                vk = q.CGEventGetIntegerValueField(event, q.kCGKeyboardEventKeycode)
                hid = _mac_vk_to_hid(vk)
                if hid is not None:
                    engine.on_local_key(hid, True)
            elif etype == q.kCGEventKeyUp:
                if q.CGEventGetIntegerValueField(event, q.kCGKeyboardEventAutorepeat):
                    return
                vk = q.CGEventGetIntegerValueField(event, q.kCGKeyboardEventKeycode)
                hid = _mac_vk_to_hid(vk)
                if hid is not None:
                    engine.on_local_key(hid, False)
            elif etype == q.kCGEventFlagsChanged:
                self._forward_flags(event)
        except Exception:
            pass

    def _forward_remote_input(self, event, etype) -> None:
        """Release remote control on real local pointer input.

        The injected CGEvents carry our sentinel, so they never take this
        path.  That avoids treating an injected cursor landing at an edge as
        a request to immediately hand control back.
        """
        q = _q()
        engine = self.engine
        if engine is None:
            return
        user = q.CGEventGetIntegerValueField(event, q.kCGEventSourceUserData)
        pid = q.CGEventGetIntegerValueField(event, q.kCGEventSourceUnixProcessID)
        if user == SENTINEL or (pid and pid == os.getpid()):
            return
        pointer_events = (
            q.kCGEventMouseMoved,
            q.kCGEventLeftMouseDragged,
            q.kCGEventRightMouseDragged,
            q.kCGEventOtherMouseDragged,
            q.kCGEventLeftMouseDown,
            q.kCGEventLeftMouseUp,
            q.kCGEventRightMouseDown,
            q.kCGEventRightMouseUp,
            q.kCGEventOtherMouseDown,
            q.kCGEventOtherMouseUp,
            q.kCGEventScrollWheel,
        )
        if etype in pointer_events:
            engine.on_remote_local_input()
            return
        self._forward_keys(event, etype)

    def _forward(self, event, etype) -> None:
        q = _q()
        engine = self.engine
        if engine is None:
            return
        user = q.CGEventGetIntegerValueField(event, q.kCGEventSourceUserData)
        pid = q.CGEventGetIntegerValueField(event, q.kCGEventSourceUnixProcessID)
        if user == SENTINEL or (pid and pid == os.getpid()):
            return
        try:
            if etype == q.kCGEventKeyDown:
                vk = q.CGEventGetIntegerValueField(event, q.kCGKeyboardEventKeycode)
                hid = _mac_vk_to_hid(vk)
                if hid is not None:
                    engine.on_local_key(hid, True)
            elif etype == q.kCGEventKeyUp:
                if q.CGEventGetIntegerValueField(event, q.kCGKeyboardEventAutorepeat):
                    return  # the peer auto-repeats
                vk = q.CGEventGetIntegerValueField(event, q.kCGKeyboardEventKeycode)
                hid = _mac_vk_to_hid(vk)
                if hid is not None:
                    engine.on_local_key(hid, False)
            elif etype == q.kCGEventFlagsChanged:
                self._forward_flags(event)
            elif etype in (
                q.kCGEventMouseMoved,
                q.kCGEventLeftMouseDragged,
                q.kCGEventRightMouseDragged,
                q.kCGEventOtherMouseDragged,
            ):
                dx = q.CGEventGetIntegerValueField(event, q.kCGMouseEventDeltaX)
                dy = q.CGEventGetIntegerValueField(event, q.kCGMouseEventDeltaY)
                pos = q.CGEventGetLocation(event)
                engine.on_local_mouse(dx, dy, int(pos.x), int(pos.y))
            elif etype in (
                q.kCGEventLeftMouseDown,
                q.kCGEventLeftMouseUp,
                q.kCGEventRightMouseDown,
                q.kCGEventRightMouseUp,
                q.kCGEventOtherMouseDown,
                q.kCGEventOtherMouseUp,
            ):
                button = _event_button(q, etype, event)
                down = etype in (
                    q.kCGEventLeftMouseDown,
                    q.kCGEventRightMouseDown,
                    q.kCGEventOtherMouseDown,
                )
                engine.on_local_button(button, down)
            elif etype == q.kCGEventScrollWheel:
                dy = q.CGEventGetIntegerValueField(event, q.kCGScrollWheelEventDeltaAxis1)
                dx = q.CGEventGetIntegerValueField(event, q.kCGScrollWheelEventDeltaAxis2)
                engine.on_local_wheel(int(round(dy * 120)), int(round(dx * 120)))
        except Exception:
            pass

    def _forward_flags(self, event) -> None:
        """FlagsChanged carries the keycode of the modifier that changed,
        so left/right variants (incl. AltGr) are identified exactly."""
        q = _q()
        vk = q.CGEventGetIntegerValueField(event, q.kCGKeyboardEventKeycode)
        hid = _mac_vk_to_hid(vk)
        if hid is None:
            return
        bit = _VK_FLAG_BITS.get(int(vk))
        if bit is None:
            return
        self.engine.on_local_key(hid, bool(q.CGEventGetFlags(event) & bit))

    # -- delegation ------------------------------------------------------------

    def set_delegation(self, state: str) -> None:
        with self._lock:
            self._mode = state
        q = _q()
        if state in ("remote", "controlling"):
            # Decouples hardware mouse deltas from the on-screen cursor.
            # Needed in both directions: "remote" so injected absolute moves
            # aren't fought by the local trackpad's own accumulator, and
            # "controlling" so the cursor actually stops moving locally -
            # swallowing the CGEvent in the tap callback only stops apps
            # from seeing it, it does not stop WindowServer from moving the
            # cursor sprite off raw HID deltas.
            q.CGAssociateMouseAndMouseCursorPosition(False)
            if state == "remote":
                with self._lock:
                    # Handoff entry: the next relative move re-derives the
                    # software position from the real cursor, so the injected
                    # stream and the real cursor agree before accumulating.
                    self._soft_valid = False
        elif state == "local":
            q.CGAssociateMouseAndMouseCursorPosition(True)
            self.show_cursor()

    # -- geometry ---------------------------------------------------------------

    def screen_layout(self) -> ScreenLayout:
        if NSScreen is None:
            raise MacPlatformError("AppKit unavailable")
        monitors = []
        for screen in NSScreen.screens():
            f = screen.frame()
            monitors.append(
                Monitor(
                    int(f.origin.x),
                    int(f.origin.y),
                    int(f.size.width),
                    int(f.size.height),
                    float(screen.backingScaleFactor()),
                )
            )
        return ScreenLayout(monitors, primary=0)

    def cursor_position(self) -> tuple[int, int]:
        q = _q()
        ev = q.CGEventCreate(None)
        loc = q.CGEventGetLocation(ev)
        return int(loc.x), int(loc.y)

    def warp_cursor(self, x: int, y: int) -> None:
        q = _q()
        q.CGWarpMouseCursorPosition((x, y))

    def hide_cursor(self) -> None:
        q = _q()
        q.CGDisplayHideCursor(q.CGMainDisplayID())

    def show_cursor(self) -> None:
        q = _q()
        q.CGDisplayShowCursor(q.CGMainDisplayID())

    # -- injection ---------------------------------------------------------------

    def inject_move_rel(self, dx: int, dy: int) -> None:
        q = _q()
        with self._lock:
            if not self._soft_valid:
                # Handoff entry: derive the software position from the real
                # cursor exactly once. Per-event warping is what made the old
                # cursor drift - with the hardware decoupled, every warp is
                # applied on top of the previous one and the sprite races
                # toward the accumulated position.
                try:
                    sx, sy = self.cursor_position()
                except Exception:
                    sx, sy = 0, 0
                self._soft_x, self._soft_y = sx, sy
                self._soft_valid = True
            nx = self._soft_x + dx
            ny = self._soft_y + dy
            self._soft_x, self._soft_y = nx, ny
        try:
            layout = self.screen_layout()
            nx = min(max(nx, layout.left()), layout.right() - 1)
            ny = min(max(ny, layout.top()), layout.bottom() - 1)
            self._soft_x, self._soft_y = nx, ny
        except Exception:
            pass
        ev = q.CGEventCreateMouseEvent(None, q.kCGEventMouseMoved, (nx, ny), q.kCGMouseButtonLeft)
        q.CGEventSetIntegerValueField(ev, q.kCGEventSourceUserData, SENTINEL)
        # Session-tap posting is below our HID capture tap, so the injected
        # event reaches the target app without being mistaken for local input.
        q.CGEventPost(q.kCGSessionEventTap, ev)
        self._report_edge(nx, ny)

    def inject_move_abs(self, x: int, y: int) -> None:
        q = _q()
        self.warp_cursor(x, y)
        ev = q.CGEventCreateMouseEvent(None, q.kCGEventMouseMoved, (x, y), q.kCGMouseButtonLeft)
        q.CGEventSetIntegerValueField(ev, q.kCGEventSourceUserData, SENTINEL)
        q.CGEventPost(q.kCGSessionEventTap, ev)
        self._report_edge(x, y)

    def _report_edge(self, x: int, y: int) -> None:
        """Seam detection at injection time: the controller drives our
        cursor with warps, so check the landing point for the return edge
        instead of polling."""
        if self._mode != "remote" or self.engine is None:
            return
        try:
            side = in_jump_zone(self.screen_layout(), x, y)
            if side is not None:
                self.engine.on_remote_edge(side, x, y)
        except Exception:
            pass

    def inject_button(self, button: int, down: bool) -> None:
        q = _q()
        if button == 0:
            etype = q.kCGEventLeftMouseDown if down else q.kCGEventLeftMouseUp
            field = 0
        elif button == 1:
            etype = q.kCGEventRightMouseDown if down else q.kCGEventRightMouseUp
            field = 1
        else:
            etype = q.kCGEventOtherMouseDown if down else q.kCGEventOtherMouseUp
            field = button
        pos = self.cursor_position()
        ev = q.CGEventCreateMouseEvent(None, etype, pos, field)
        q.CGEventSetIntegerValueField(ev, q.kCGEventSourceUserData, SENTINEL)
        q.CGEventPost(q.kCGSessionEventTap, ev)

    def inject_wheel(self, dy: int, dx: int) -> None:
        q = _q()
        ev = q.CGEventCreateScrollWheelEvent(None, q.kCGScrollEventUnitLine, 2, dy / 120.0, dx / 120.0)
        q.CGEventSetIntegerValueField(ev, q.kCGEventSourceUserData, SENTINEL)
        q.CGEventPost(q.kCGSessionEventTap, ev)

    def inject_key(self, hid: int, down: bool) -> None:
        q = _q()
        from .kvm_keymap import hid_to_mac_vk

        vk = hid_to_mac_vk(hid)
        if vk is None:
            return
        ev = q.CGEventCreateKeyboardEvent(None, vk, down)
        q.CGEventSetIntegerValueField(ev, q.kCGEventSourceUserData, SENTINEL)
        q.CGEventPost(q.kCGSessionEventTap, ev)


# -- module helpers --------------------------------------------------------------

def _event_button(q, etype, event) -> int:
    if etype in (q.kCGEventLeftMouseDown, q.kCGEventLeftMouseUp):
        return 0
    if etype in (q.kCGEventRightMouseDown, q.kCGEventRightMouseUp):
        return 1
    return int(q.CGEventGetIntegerValueField(event, q.kCGMouseEventButtonNumber))


def _mac_vk_to_hid(vk: int):
    from .kvm_keymap import mac_vk_to_hid

    return mac_vk_to_hid(vk)


# macOS virtual keycode -> CGEvent flag bit (only for modifier keys).
_VK_FLAG_BITS = {
    0x38: 0x00020000,  # Left Shift    kCGEventFlagMaskShift
    0x3C: 0x00020000,  # Right Shift
    0x3B: 0x00040000,  # Left Control  kCGEventFlagMaskControl
    0x3E: 0x00040000,  # Right Control
    0x3A: 0x00080000,  # Left Option   kCGEventFlagMaskAlternate
    0x3D: 0x00080000,  # Right Option
    0x37: 0x00100000,  # Left Command  kCGEventFlagMaskCommand
    0x36: 0x00100000,  # Right Command
}


# -- spike CLI ---------------------------------------------------------------------

def main():
    """Standalone verification of capture/inject/filter/cursor on this Mac.

        python core/kvm_platform_mac.py --spike

    Prints permission state and the local layout, then for N seconds
    prints captured mouse deltas, buttons, wheel and keys. Two seconds in
    it injects a relative move, an absolute move and an "a" keystroke;
    the injected events must NOT appear in the capture output
    (self-filter). Finally it hides/shows the cursor and warps it to
    (600, 400).
    """
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--spike", action="store_true")
    parser.add_argument("--seconds", type=int, default=6)
    args = parser.parse_args()

    class _Engine:
        def on_status(self, msg):
            print(f"[status] {msg}", flush=True)

        def on_local_mouse(self, dx, dy, x, y):
            print(f"  mouse rel=({dx},{dy}) abs=({x},{y})", flush=True)

        def on_local_button(self, button, down):
            print(f"  button {button} {'down' if down else 'up'}", flush=True)

        def on_local_wheel(self, dy, dx):
            print(f"  wheel dy={dy} dx={dx}", flush=True)

        def on_local_key(self, hid, down):
            print(f"  key hid=0x{hid:02x} {'down' if down else 'up'}", flush=True)

        def on_remote_edge(self, side, x, y):
            print(f"  edge {side} at ({x},{y})", flush=True)

    platform = MacInputPlatform()
    print(f"listen permission: {platform.permission_ok()}", flush=True)
    layout = platform.screen_layout()
    print(f"layout: {layout.to_monitors()}", flush=True)
    platform.start(_Engine())

    def inject():
        time.sleep(2)
        print("  [spike] injecting rel move, abs move, 'a' key", flush=True)
        platform.inject_move_rel(120, -60)
        platform.inject_move_abs(600, 400)
        platform.inject_key(0x04, True)
        platform.inject_key(0x04, False)
        time.sleep(1.5)
        print("  [spike] hiding cursor...", flush=True)
        platform.hide_cursor()
        time.sleep(1.0)
        print("  [spike] showing cursor + warp to (600,400)", flush=True)
        platform.show_cursor()
        platform.warp_cursor(600, 400)

    threading.Thread(target=inject, daemon=True).start()
    time.sleep(args.seconds)
    platform.stop()
    print("spike done", flush=True)


if __name__ == "__main__":
    main()
