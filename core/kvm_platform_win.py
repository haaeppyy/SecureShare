"""Windows input platform for keyboard/mouse sharing.

Capture: WH_MOUSE_LL + WH_KEYBOARD_LL low-level hooks on a dedicated
message-pump thread. The hooks never cancel injected (sentinel) input and
pass everything through while the engine is stopped; in ``local`` mode
they forward events to the engine (seam detection, chord arming) and pass
them through; in ``controlling``/``remote`` mode they block local input
(return 1) so local apps never see it.

Injection: SendInput (ctypes) with MOUSEEVENTF_ABSOLUTE|VIRTUALDESK
mouse moves, scan-code keyboard events (layout-independent) and
dwExtraInfo = SENTINEL on everything, which the hooks filter so our own
injection never echoes back into the engine. Cursor warps use
SetCursorPos and verify the landing position, falling back to SendInput
when the warp silently failed. The return seam is detected at injection
time, not by a poller.
"""

import ctypes
import ctypes.wintypes as wt
from collections import deque
import threading
import time

from .kvm_geometry import Monitor, ScreenLayout, in_jump_zone

SENTINEL = 0x5E4C0DE5

try:
    import win32api
    import win32gui

    _WIN_OK = True
except ImportError:  # pragma: no cover - non-Windows
    win32api = None
    win32gui = None
    _WIN_OK = False

if _WIN_OK:
    _user32 = ctypes.windll.user32
    _shcore = ctypes.windll.shcore

    ULONG_PTR = wt.WPARAM

    class MOUSEINPUT(ctypes.Structure):
        _fields_ = [
            ("dx", ctypes.c_long),
            ("dy", ctypes.c_long),
            ("mouseData", ctypes.c_ulong),
            ("dwFlags", ctypes.c_ulong),
            ("time", ctypes.c_ulong),
            ("dwExtraInfo", ULONG_PTR),
        ]

    class KEYBDINPUT(ctypes.Structure):
        _fields_ = [
            ("wVk", wt.WORD),
            ("wScan", wt.WORD),
            ("dwFlags", ctypes.c_ulong),
            ("time", ctypes.c_ulong),
            ("dwExtraInfo", ULONG_PTR),
        ]

    class HARDWAREINPUT(ctypes.Structure):
        _fields_ = [("uMsg", ctypes.c_ulong), ("wParamL", wt.WORD), ("wParamH", wt.WORD)]

    class _INPUTUNION(ctypes.Union):
        _fields_ = [("mi", MOUSEINPUT), ("ki", KEYBDINPUT), ("hi", HARDWAREINPUT)]

    class INPUT(ctypes.Structure):
        _anonymous_ = ("u",)
        _fields_ = [("type", ctypes.c_ulong), ("u", _INPUTUNION)]

    class POINT(ctypes.Structure):
        _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]

    class MSLLHOOKSTRUCT(ctypes.Structure):
        _fields_ = [
            ("pt", POINT),
            ("mouseData", ctypes.c_ulong),
            ("flags", ctypes.c_ulong),
            ("time", ctypes.c_ulong),
            ("dwExtraInfo", ULONG_PTR),
        ]

    class KBDLLHOOKSTRUCT(ctypes.Structure):
        _fields_ = [
            ("vkCode", ctypes.c_ulong),
            ("scanCode", ctypes.c_ulong),
            ("flags", ctypes.c_ulong),
            ("time", ctypes.c_ulong),
            ("dwExtraInfo", ULONG_PTR),
        ]

    _user32.SendInput.restype = ctypes.c_uint
    _user32.SendInput.argtypes = (ctypes.c_uint, ctypes.POINTER(INPUT), ctypes.c_int)
    _user32.GetCursorPos.argtypes = (ctypes.POINTER(POINT),)
    _user32.GetCursorPos.restype = ctypes.c_int
    _user32.SetCursorPos.argtypes = (ctypes.c_int, ctypes.c_int)
    _user32.SetCursorPos.restype = ctypes.c_int
    _user32.ShowCursor.argtypes = (ctypes.c_int,)
    _user32.ShowCursor.restype = ctypes.c_int
    # CallNextHookEx without argtypes truncates wParam/lParam to 32 bits on
    # 64-bit Windows, corrupting the event we pass down the chain.  The
    # lParam of a low-level hook is the pointer to the hook struct; passing
    # the struct object re-derived via from_address works, but the raw
    # LPARAM is what the OS gave us, so forward that untouched.
    _user32.CallNextHookEx.argtypes = (wt.HHOOK, ctypes.c_int, wt.WPARAM, wt.LPARAM)
    _user32.CallNextHookEx.restype = wt.LPARAM

    # Input types / flags
    INPUT_MOUSE = 0
    INPUT_KEYBOARD = 1
    MOUSEEVENTF_MOVE = 0x0001
    MOUSEEVENTF_ABSOLUTE = 0x8000
    MOUSEEVENTF_VIRTUALDESK = 0x4000
    MOUSEEVENTF_LEFTDOWN = 0x0002
    MOUSEEVENTF_LEFTUP = 0x0004
    MOUSEEVENTF_RIGHTDOWN = 0x0008
    MOUSEEVENTF_RIGHTUP = 0x0010
    MOUSEEVENTF_MIDDLEDOWN = 0x0020
    MOUSEEVENTF_MIDDLEUP = 0x0040
    MOUSEEVENTF_XDOWN = 0x0080
    MOUSEEVENTF_XUP = 0x0100
    MOUSEEVENTF_WHEEL = 0x0800
    MOUSEEVENTF_HWHEEL = 0x1000
    XBUTTON1 = 0x0001
    XBUTTON2 = 0x0002
    KEYEVENTF_EXTENDEDKEY = 0x0001
    KEYEVENTF_KEYUP = 0x0002
    KEYEVENTF_SCANCODE = 0x0008

    WH_MOUSE_LL = 14
    WH_KEYBOARD_LL = 13
    WM_QUIT = 0x0012
    WM_MOUSEMOVE = 0x0200
    WM_LBUTTONDOWN = 0x0201
    WM_LBUTTONUP = 0x0202
    WM_RBUTTONDOWN = 0x0204
    WM_RBUTTONUP = 0x0205
    WM_MBUTTONDOWN = 0x0207
    WM_MBUTTONUP = 0x0208
    WM_MOUSEWHEEL = 0x020A
    WM_XBUTTONDOWN = 0x020B
    WM_XBUTTONUP = 0x020C
    WM_MOUSEHWHEEL = 0x020E
    WM_KEYDOWN = 0x0100
    WM_KEYUP = 0x0101
    WM_SYSKEYDOWN = 0x0104
    WM_SYSKEYUP = 0x0105
    LLKHF_EXTENDED = 0x01
    LLKHF_INJECTED = 0x10
    LLMHF_INJECTED = 0x01


class WindowsPlatformError(Exception):
    pass


class WindowsInputPlatform:
    def __init__(self):
        self.engine = None
        self._hook_thread = None
        self._hook_ids = []
        self._mouse_proc = None
        self._kbd_proc = None
        self._mode = "local"
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._last_pos = None
        # Recent untaggable SetCursorPos moves. A single slot races when the
        # hook queue receives a burst of remote cursor updates.
        self._ignore_warps = deque()
        self._physical_pressed = set()  # physical keys held (hook dedupe)
        self._injected_pressed = set()  # keys we injected that are still down
        self._virtual = None  # virtual-desktop pixel bounds (l, t, r, b)
        self._cursor_hidden = False
        self._send_input_failures = 0
        self._last_send_input_error = 0.0
        self._first_exception = None
        if _WIN_OK:
            try:
                ctypes.windll.user32.SetProcessDPIAware()
            except Exception:
                pass
            self._refresh_virtual_bounds()

    # -- lifecycle ------------------------------------------------------------

    def start(self, engine) -> None:
        if not _WIN_OK:
            raise WindowsPlatformError("pywin32 unavailable")
        self.engine = engine
        engine._capture_origin = "win"
        self._stop.clear()
        self._hook_thread = threading.Thread(target=self._hook_main, name="kvm-hooks", daemon=True)
        self._hook_thread.start()

    def stop(self) -> None:
        self._stop.set()
        for h in self._hook_ids:
            try:
                win32gui.UnhookWindowsHookEx(h)
            except Exception:
                pass
        self._hook_ids = []
        thread_id = self._hook_thread.ident if self._hook_thread else None
        if thread_id:
            try:
                _user32.PostThreadMessageW(thread_id, WM_QUIT, 0, 0)
            except Exception:
                pass
        if self._hook_thread is not None:
            self._hook_thread.join(timeout=2)

    def permission_ok(self) -> bool:
        """Return whether the Windows input backend is available.

        Low-level hooks and ``SendInput`` work for a normal desktop process;
        requiring an elevated token here disabled KVM for almost every
        Windows user before a channel could be opened.  Windows can prevent
        a non-elevated process from controlling an *elevated* target app, but
        that is an OS security boundary, not a prerequisite for sharing.
        """
        return _WIN_OK

    def permission_detail(self) -> str:
        if not _WIN_OK:
            return "pywin32 unavailable"
        return "all permissions granted"

    # -- hooks ------------------------------------------------------------------

    def _hook_main(self) -> None:
        # Keep strong references: pywin32 does not hold the callback, and a
        # garbage-collected proc makes the hook silently dead.
        try:
            self._mouse_proc = self._make_mouse_proc()
            self._kbd_proc = self._make_kbd_proc()
            hooks = [
                win32gui.SetWindowsHookEx(WH_MOUSE_LL, self._mouse_proc, None, 0),
                win32gui.SetWindowsHookEx(WH_KEYBOARD_LL, self._kbd_proc, None, 0),
            ]
            if not all(hooks):
                raise WindowsPlatformError(
                    f"SetWindowsHookEx failed (handles: {[h for h in hooks]})"
                )
            self._hook_ids = hooks
            win32gui.PumpMessages()
        except Exception as exc:
            self._note_exception(exc)

    def _note_exception(self, exc: Exception) -> None:
        """Surface a hook-thread failure instead of dying silently.

        The previous behaviour left a dead hook thread with no trace: the
        app ran, the engine believed input capture was alive, and KVM
        silently did nothing (diagnostics showed hook_thread_alive False).
        """
        engine = self.engine
        if engine is None:
            return
        first = False
        with self._lock:
            if self._first_exception is None:
                self._first_exception = f"{type(exc).__name__}: {exc}"
                first = True
        if first:
            try:
                engine.on_platform_input_lost()
            except Exception:
                pass
            try:
                engine.on_status(
                    f"KVM: input capture failed on this device ({self._first_exception}) - "
                    "see diagnostics for details",
                    level="error",
                )
            except Exception:
                pass

    def _make_mouse_proc(self):
        def mouse_proc(nCode, wParam, lParam):
            if nCode >= 0:
                try:
                    return self._handle_mouse(wParam, lParam)
                except Exception:
                    pass
            return _user32.CallNextHookEx(None, nCode, wParam, lParam)

        return mouse_proc

    def _make_kbd_proc(self):
        def kbd_proc(nCode, wParam, lParam):
            if nCode >= 0:
                try:
                    return self._handle_key(wParam, lParam)
                except Exception:
                    pass
            return _user32.CallNextHookEx(None, nCode, wParam, lParam)

        return kbd_proc

    def _handle_mouse(self, wParam, lParam) -> int:
        info = MSLLHOOKSTRUCT.from_address(lParam)
        if info.dwExtraInfo == SENTINEL or (info.flags & LLMHF_INJECTED):
            # Ignore injected input for transport, but let Windows deliver it
            # to the remote app. Returning 1 here cancels the injection.
            return _user32.CallNextHookEx(None, 0, wParam, lParam)
        engine = self.engine
        if engine is None:
            return _user32.CallNextHookEx(None, 0, wParam, lParam)
        mode = self._mode
        x, y = int(info.pt.x), int(info.pt.y)
        if wParam == WM_MOUSEMOVE and self._consume_warp_move(x, y):
            # A warp landed; follow it so the next *physical* delta is
            # relative to the actual cursor, not a stale position.
            self._last_pos = (x, y)
            return _user32.CallNextHookEx(None, 0, wParam, lParam)
        if mode == "remote":
            # Explicit ownership: physical pointer input never ends the
            # session.  The cursor is hidden and events pass through to
            # local apps (invisible), so nothing is forwarded.
            return _user32.CallNextHookEx(None, 0, wParam, lParam)
        try:
            if wParam == WM_MOUSEMOVE:
                if self._last_pos is not None:
                    dx, dy = x - self._last_pos[0], y - self._last_pos[1]
                else:
                    # First move after a delegation change: no baseline, so
                    # discard the delta (the cursor may have been parked).
                    dx = dy = 0
                self._last_pos = (x, y)
                engine.observe_local_mouse(dx, dy, x, y)
                if mode == "controlling":
                    engine.send_controlled_mouse(dx, dy)
            elif wParam == WM_LBUTTONDOWN:
                engine.observe_local_button(0, True)
                if mode == "controlling":
                    engine.send_controlled_button(0, True)
            elif wParam == WM_LBUTTONUP:
                engine.observe_local_button(0, False)
                if mode == "controlling":
                    engine.send_controlled_button(0, False)
            elif wParam == WM_RBUTTONDOWN:
                engine.observe_local_button(1, True)
                if mode == "controlling":
                    engine.send_controlled_button(1, True)
            elif wParam == WM_RBUTTONUP:
                engine.observe_local_button(1, False)
                if mode == "controlling":
                    engine.send_controlled_button(1, False)
            elif wParam == WM_MBUTTONDOWN:
                engine.observe_local_button(2, True)
                if mode == "controlling":
                    engine.send_controlled_button(2, True)
            elif wParam == WM_MBUTTONUP:
                engine.observe_local_button(2, False)
                if mode == "controlling":
                    engine.send_controlled_button(2, False)
            elif wParam == WM_XBUTTONDOWN or wParam == WM_XBUTTONUP:
                button = 2 + (info.mouseData >> 16)
                engine.observe_local_button(button, wParam == WM_XBUTTONDOWN)
                if mode == "controlling":
                    engine.send_controlled_button(button, wParam == WM_XBUTTONDOWN)
            elif wParam == WM_MOUSEWHEEL:
                dy = ctypes.c_short(info.mouseData >> 16).value
                engine.observe_local_wheel(dy, 0)
                if mode == "controlling":
                    engine.send_controlled_wheel(dy, 0)
            elif wParam == WM_MOUSEHWHEEL:
                dx = ctypes.c_short(info.mouseData >> 16).value
                engine.observe_local_wheel(0, dx)
                if mode == "controlling":
                    engine.send_controlled_wheel(0, dx)
        except Exception:
            pass
        if mode == "local":
            return _user32.CallNextHookEx(None, 0, wParam, lParam)
        return 1  # suppress while controlling

    def _handle_key(self, wParam, lParam) -> int:
        info = KBDLLHOOKSTRUCT.from_address(lParam)
        if info.dwExtraInfo == SENTINEL or (info.flags & LLKHF_INJECTED):
            return _user32.CallNextHookEx(None, 0, wParam, lParam)
        engine = self.engine
        if engine is None:
            return _user32.CallNextHookEx(None, 0, wParam, lParam)
        mode = self._mode
        try:
            from .kvm_keymap import win_scan_to_hid

            hid = win_scan_to_hid(int(info.scanCode), bool(info.flags & LLKHF_EXTENDED))
            if hid is not None:
                down = wParam in (WM_KEYDOWN, WM_SYSKEYDOWN)
                if down:
                    if hid in self._physical_pressed:
                        # OS autorepeat: already forwarded, never twice.
                        return (
                            _user32.CallNextHookEx(None, 0, wParam, lParam)
                            if mode != "controlling"
                            else 1
                        )
                    self._physical_pressed.add(hid)
                else:
                    self._physical_pressed.discard(hid)
                engine.observe_local_key(hid, down)
                if mode == "controlling":
                    engine.send_controlled_key(hid, down)
        except Exception:
            pass
        if mode == "remote":
            # Explicit ownership: keys pass through to local apps; they were
            # reported to the engine only for ownership-chord recognition.
            return _user32.CallNextHookEx(None, 0, wParam, lParam)
        if mode == "local":
            return _user32.CallNextHookEx(None, 0, wParam, lParam)
        return 1  # suppress while controlling

    # -- delegation --------------------------------------------------------------

    def set_delegation(self, state: str) -> bool:
        with self._lock:
            old = self._mode
            self._mode = state
            if old == "remote" and state != "remote":
                # Defense in depth: keys/buttons we injected while remote are
                # released locally so nothing stays stuck if the engine's own
                # release path is interrupted.
                self._release_injected_keys()
            if state == "controlling":
                # A delegation change parks/restores the cursor; the first
                # physical move afterwards has no baseline, so its delta is
                # discarded (otherwise a stale position yields a huge jump).
                self._last_pos = None
                self._ignore_warps.clear()
            if state == "local":
                self.show_cursor()
        return True

    def _release_injected_keys(self) -> None:
        for hid in sorted(self._injected_pressed):
            self._inject_key_inner(hid, False)
        self._injected_pressed.clear()

    def diagnostics(self) -> dict:
        with self._lock:
            return {
                "family": "win",
                "mode": self._mode,
                "hook_thread_alive": bool(self._hook_thread and self._hook_thread.is_alive()),
                "ignore_warps": len(self._ignore_warps),
                "send_input_failures": self._send_input_failures,
                "cursor_hidden": self._cursor_hidden,
                "first_exception": self._first_exception,
            }

    # -- geometry -----------------------------------------------------------------

    def _refresh_virtual_bounds(self) -> None:
        try:
            monitors = win32api.EnumDisplayMonitors()
            xs = [r[0] for _, _, r in monitors]
            ys = [r[1] for _, _, r in monitors]
            xe = [r[2] for _, _, r in monitors]
            ye = [r[3] for _, _, r in monitors]
            self._virtual = (min(xs), min(ys), max(xe), max(ye))
        except Exception:
            self._virtual = (0, 0, 1920, 1080)

    def screen_layout(self) -> ScreenLayout:
        if not _WIN_OK:
            raise WindowsPlatformError("pywin32 unavailable")
        self._refresh_virtual_bounds()
        monitors = []
        for hmon, _, rect in win32api.EnumDisplayMonitors():
            scale = self._monitor_scale(hmon)
            x, y, r, b = rect
            monitors.append(Monitor(x, y, r - x, b - y, scale))
        return ScreenLayout(monitors, primary=0)

    def _monitor_scale(self, hmon) -> float:
        try:
            dpi_x = ctypes.c_uint()
            dpi_y = ctypes.c_uint()
            if _shcore.GetDpiForMonitor(hmon, 0, ctypes.byref(dpi_x), ctypes.byref(dpi_y)) == 0:
                return dpi_x.value / 96.0
        except Exception:
            pass
        return 1.0

    def cursor_position(self) -> tuple[int, int]:
        pt = POINT()
        if not _user32.GetCursorPos(ctypes.byref(pt)):
            return (0, 0)
        return int(pt.x), int(pt.y)

    def warp_cursor(self, x: int, y: int) -> None:
        self._ignore_warps.append((int(x), int(y), time.monotonic() + 0.25))
        while len(self._ignore_warps) > 64:
            self._ignore_warps.popleft()
        if not _user32.SetCursorPos(int(x), int(y)):
            self._warp_fallback(x, y)
            return
        # Verify: SetCursorPos can silently fail when the session is locked.
        got = self.cursor_position()
        if abs(got[0] - x) > 4 or abs(got[1] - y) > 4:
            self._warp_fallback(x, y)

    def _consume_warp_move(self, x: int, y: int) -> bool:
        now = time.monotonic()
        matched = False
        remaining = deque()
        for expected_x, expected_y, expiry in self._ignore_warps:
            if expiry <= now:
                continue
            if not matched and abs(x - expected_x) <= 1 and abs(y - expected_y) <= 1:
                matched = True
                continue
            remaining.append((expected_x, expected_y, expiry))
        self._ignore_warps = remaining
        return matched

    def _warp_fallback(self, x: int, y: int) -> None:
        self._send_abs_move(x, y)

    def _send_abs_move(self, x: int, y: int) -> None:
        """Absolute pointer move via SendInput, normalized to the virtual
        desktop (MOUSEEVENTF_ABSOLUTE|VIRTUALDESK)."""
        if self._virtual is None:
            return
        vx, vy, vr, vb = self._virtual
        nx = int((x - vx) * 65535.0 / max(1, vr - vx))
        ny = int((y - vy) * 65535.0 / max(1, vb - vy))
        nx = max(0, min(65535, nx))
        ny = max(0, min(65535, ny))
        self._send_input(
            [
                INPUT(
                    type=INPUT_MOUSE,
                    mi=MOUSEINPUT(
                        dx=nx,
                        dy=ny,
                        mouseData=0,
                        dwFlags=MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
                        dwExtraInfo=SENTINEL,
                    ),
                )
            ]
        )

    def hide_cursor(self) -> None:
        """Hide the local cursor while we control the peer (one visible
        cursor at a time). ShowCursor uses a global display count, so the
        loop keeps decrementing until the cursor is actually gone."""
        if self._cursor_hidden or not _WIN_OK:
            return
        for _ in range(40):
            if _user32.ShowCursor(False) < 0:
                break
        self._cursor_hidden = True

    def show_cursor(self) -> None:
        if not self._cursor_hidden or not _WIN_OK:
            return
        for _ in range(40):
            if _user32.ShowCursor(True) >= 0:
                break
        self._cursor_hidden = False

    # -- injection -----------------------------------------------------------------

    def inject_move_rel(self, dx: int, dy: int) -> None:
        if not dx and not dy:
            return
        # SendInput *relative* moves apply the user's pointer acceleration,
        # so injected deltas would be wrong.  Compute the absolute landing
        # point from the current position and send an exact absolute move.
        cx, cy = self.cursor_position()
        self._send_abs_move(cx + dx, cy + dy)

    def inject_move_abs(self, x: int, y: int) -> None:
        self.warp_cursor(x, y)
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
        flags = {
            0: (MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP, 0),
            1: (MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, 0),
            2: (MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, 0),
            3: (MOUSEEVENTF_XDOWN, MOUSEEVENTF_XUP, XBUTTON1),
            4: (MOUSEEVENTF_XDOWN, MOUSEEVENTF_XUP, XBUTTON2),
        }.get(button)
        if flags is None:
            return
        down_flag, up_flag, data = flags
        self._send_input(
            [
                INPUT(
                    type=INPUT_MOUSE,
                    mi=MOUSEINPUT(
                        dx=0,
                        dy=0,
                        mouseData=data,
                        dwFlags=(down_flag if down else up_flag),
                        dwExtraInfo=SENTINEL,
                    ),
                )
            ]
        )

    def inject_wheel(self, dy: int, dx: int) -> None:
        inputs = []
        if dy:
            inputs.append(
                INPUT(
                    type=INPUT_MOUSE,
                    mi=MOUSEINPUT(
                        dx=0,
                        dy=0,
                        mouseData=ctypes.c_ulong(dy & 0xFFFFFFFF).value,
                        dwFlags=MOUSEEVENTF_WHEEL,
                        dwExtraInfo=SENTINEL,
                    ),
                )
            )
        if dx:
            inputs.append(
                INPUT(
                    type=INPUT_MOUSE,
                    mi=MOUSEINPUT(
                        dx=0,
                        dy=0,
                        mouseData=ctypes.c_ulong(dx & 0xFFFFFFFF).value,
                        dwFlags=MOUSEEVENTF_HWHEEL,
                        dwExtraInfo=SENTINEL,
                    ),
                )
            )
        if inputs:
            self._send_input(inputs)

    def inject_key(self, hid: int, down: bool) -> None:
        if down:
            self._injected_pressed.add(hid)
        else:
            self._injected_pressed.discard(hid)
        self._inject_key_inner(hid, down)

    def _inject_key_inner(self, hid: int, down: bool) -> None:
        from .kvm_keymap import hid_to_win_scan

        entry = hid_to_win_scan(hid)
        if entry is None:
            return
        scan, extended = entry
        flags = KEYEVENTF_SCANCODE | (KEYEVENTF_EXTENDEDKEY if extended else 0)
        if not down:
            flags |= KEYEVENTF_KEYUP
        self._send_input(
            [
                INPUT(
                    type=INPUT_KEYBOARD,
                    ki=KEYBDINPUT(wVk=0, wScan=scan, dwFlags=flags, dwExtraInfo=SENTINEL),
                )
            ]
        )

    def _send_input(self, inputs: list) -> None:
        if not inputs:
            return
        arr = (INPUT * len(inputs))(*inputs)
        sent = _user32.SendInput(len(inputs), arr, ctypes.sizeof(INPUT))
        if sent != len(inputs):
            self._send_input_failures += 1
            now = time.monotonic()
            if now - self._last_send_input_error > 10.0:
                self._last_send_input_error = now
                try:
                    if self.engine is not None:
                        self.engine.on_status(
                            f"KVM: SendInput delivered {sent}/{len(inputs)} events "
                            f"(error {ctypes.get_last_error()})",
                            level="error",
                        )
                except Exception:
                    pass
