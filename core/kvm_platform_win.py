"""Windows input platform for keyboard/mouse sharing.

Capture: WH_MOUSE_LL + WH_KEYBOARD_LL low-level hooks on a dedicated
message-pump thread. The hooks never cancel injected (sentinel) input and
pass everything through while the engine is stopped; in ``local`` mode
they forward events to the engine (seam detection) and pass
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

# Low-level WH_*_LL hooks run in the calling thread, so call user32 directly
# via ctypes (as the rest of this module does).  pywin32's win32gui has never
# exposed SetWindowsHookEx/UnhookWindowsHookEx, so routing the hook API
# through it raised AttributeError on every modern pywin32 and the hook
# thread died silently right after start (hook_thread_alive False).
try:
    import win32api

    _WIN_API_OK = hasattr(win32api, "EnumDisplayMonitors")
    _WIN_OK = _WIN_API_OK
except ImportError:  # pragma: no cover - non-Windows
    win32api = None
    _WIN_API_OK = False
    _WIN_OK = False

_WIN_IMPORT_HINT = (
    "pywin32 unavailable - install pywin32>=306 and rebuild"
    if not _WIN_API_OK
    else "pywin32 too old (win32api.EnumDisplayMonitors missing) - install pywin32>=306 and rebuild"
)

# Plain constants that are safe to reference on any OS (used by tests too).
LLKHF_EXTENDED = 0x01
LLKHF_INJECTED = 0x10

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

    # Low-level hook installation and the message pump the hook thread runs.
    # Callbacks are wrapped in HOOKPROC and kept as strong references (the
    # hook-thread locals in _hook_main); a garbage-collected callback makes
    # the hook silently dead.
    HOOKPROC = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, ctypes.c_int, wt.WPARAM, wt.LPARAM)

    class MSG(ctypes.Structure):
        _fields_ = [
            ("hwnd", wt.HWND),
            ("message", ctypes.c_uint),
            ("wParam", wt.WPARAM),
            ("lParam", wt.LPARAM),
            ("time", ctypes.c_ulong),
            ("pt", POINT),
        ]

    # CallNextHookEx without argtypes truncates wParam/lParam to 32 bits on
    # 64-bit Windows, corrupting the event passed down the chain, so the raw
    # LPARAM is forwarded untouched.
    _user32.CallNextHookEx.argtypes = (wt.HHOOK, ctypes.c_int, wt.WPARAM, wt.LPARAM)
    _user32.CallNextHookEx.restype = wt.LPARAM

    _user32.SetWindowsHookExW.restype = ctypes.c_ssize_t
    _user32.SetWindowsHookExW.argtypes = (ctypes.c_int, HOOKPROC, wt.HINSTANCE, wt.DWORD)
    _user32.UnhookWindowsHookEx.restype = ctypes.c_int
    _user32.UnhookWindowsHookEx.argtypes = (ctypes.c_ssize_t,)
    _user32.GetMessageW.restype = ctypes.c_int
    _user32.GetMessageW.argtypes = (ctypes.POINTER(MSG), wt.HWND, ctypes.c_uint, ctypes.c_uint)
    _user32.TranslateMessage.restype = ctypes.c_int
    _user32.TranslateMessage.argtypes = (ctypes.POINTER(MSG),)
    _user32.DispatchMessageW.restype = wt.LPARAM
    _user32.DispatchMessageW.argtypes = (ctypes.POINTER(MSG),)

    _user32.SendInput.restype = ctypes.c_uint
    _user32.SendInput.argtypes = (ctypes.c_uint, ctypes.POINTER(INPUT), ctypes.c_int)
    _user32.GetCursorPos.argtypes = (ctypes.POINTER(POINT),)
    _user32.GetCursorPos.restype = ctypes.c_int
    _user32.SetCursorPos.argtypes = (ctypes.c_int, ctypes.c_int)
    _user32.SetCursorPos.restype = ctypes.c_int
    _user32.ShowCursor.argtypes = (ctypes.c_int,)
    _user32.ShowCursor.restype = ctypes.c_int


# Input types / flags (plain constants, safe to reference on any OS)
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

# Custom message posted to the hook thread to re-arm hooks that Windows
# silently uninstalled (a slow callback trips LowLevelHooksTimeout).
WM_REINSTALL_HOOKS = 0x8001
HOOK_STALL_TIMEOUT = 10.0  # no hook activity at all -> assume OS dropped the hooks


class WindowsPlatformError(Exception):
    pass


class WindowsInputPlatform:
    def __init__(self):
        self.engine = None
        self._hook_thread = None
        self._hook_ids = []
        self._mode = "local"
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._last_pos = None
        # Recent untaggable SetCursorPos moves. A single slot races when the
        # hook queue receives a burst of remote cursor updates.
        self._ignore_warps = deque()
        self._edge_hits = 0
        self._layout_cache = None  # (monotonic ts, ScreenLayout)
        self._pressed = set()
        self._virtual = None  # virtual-desktop pixel bounds (l, t, r, b)
        self._cursor_hidden = False
        self._anchor = None  # recenter anchor while controlling (layout center)
        self._hook_activity = time.monotonic()
        self._watchdog_thread = None
        if _WIN_OK:
            try:
                ctypes.windll.user32.SetProcessDPIAware()
            except Exception:
                pass
            self._refresh_virtual_bounds()

    # -- lifecycle ------------------------------------------------------------

    def start(self, engine) -> None:
        if not _WIN_OK:
            raise WindowsPlatformError(_WIN_IMPORT_HINT or "pywin32 unavailable")
        self.engine = engine
        self._stop.clear()
        self._hook_thread = threading.Thread(target=self._hook_main, name="kvm-hooks", daemon=True)
        self._hook_thread.start()
        self._watchdog_thread = threading.Thread(target=self._watchdog_loop, name="kvm-hook-watchdog", daemon=True)
        self._watchdog_thread.start()

    def stop(self) -> None:
        self._stop.set()
        for h in self._hook_ids:
            try:
                _user32.UnhookWindowsHookEx(h)
            except Exception:
                pass
        self._hook_ids = []
        thread_id = self._hook_thread.ident if self._hook_thread else None
        if thread_id:
            try:
                _user32.PostThreadMessageW(thread_id, WM_QUIT, 0, 0)
            except Exception:
                pass
        if self._watchdog_thread is not None:
            self._watchdog_thread.join(timeout=2)
        if self._hook_thread is not None:
            self._hook_thread.join(timeout=2)
        with self._lock:
            self._pressed.clear()

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
            return _WIN_IMPORT_HINT or "pywin32 unavailable"
        return "all permissions granted"

    # -- hooks ------------------------------------------------------------------

    def _hook_main(self) -> None:
        def mouse_proc(nCode, wParam, lParam):
            if nCode >= 0:
                try:
                    return self._handle_mouse(wParam, lParam)
                except Exception:
                    pass
            return _user32.CallNextHookEx(None, nCode, wParam, lParam)

        def kbd_proc(nCode, wParam, lParam):
            if nCode >= 0:
                try:
                    return self._handle_key(wParam, lParam)
                except Exception:
                    pass
            return _user32.CallNextHookEx(None, nCode, wParam, lParam)

        # Low-level hooks require their callbacks to survive; HOOKPROC
        # wrappers are kept as strong refs on the platform object (a
        # garbage-collected callback makes the hook silently dead).
        self._mouse_proc = HOOKPROC(mouse_proc)
        self._kbd_proc = HOOKPROC(kbd_proc)
        self._install_hooks()
        self._pump_messages()

    def _install_hooks(self) -> None:
        self._hook_ids = [
            _user32.SetWindowsHookExW(WH_MOUSE_LL, self._mouse_proc, None, 0),
            _user32.SetWindowsHookExW(WH_KEYBOARD_LL, self._kbd_proc, None, 0),
        ]
        self._hook_activity = time.monotonic()

    def _watchdog_loop(self) -> None:
        """Re-arm hooks Windows silently uninstalled.

        The OS drops a low-level hook with no notification when a callback
        runs longer than LowLevelHooksTimeout (default 300 ms).  The Mac
        tap self-heals via kCGEventTapDisabledByTimeout; the hooks need the
        same net here, otherwise capture dies until the app restarts while
        hook_thread_alive still reports True.
        """
        while not self._stop.is_set():
            self._stop.wait(5)
            with self._lock:
                stale = time.monotonic() - self._hook_activity > HOOK_STALL_TIMEOUT
                thread_id = self._hook_thread.ident if self._hook_thread else None
            if stale and thread_id:
                try:
                    _user32.PostThreadMessageW(thread_id, WM_REINSTALL_HOOKS, 0, 0)
                except Exception:
                    pass

    def _pump_messages(self) -> None:
        """Run the message loop for the hook thread (user32.GetMessageW).

        Low-level hooks require their owning thread to pump messages;
        GetMessageW returns 0 on WM_QUIT, which stop() posts to end the
        thread."""
        msg = MSG()
        while _user32.GetMessageW(ctypes.byref(msg), 0, 0, 0) != 0:
            if msg.message == WM_REINSTALL_HOOKS:
                self._reinstall_hooks()
                continue
            _user32.TranslateMessage(ctypes.byref(msg))
            _user32.DispatchMessageW(ctypes.byref(msg))

    def _reinstall_hooks(self) -> None:
        for h in self._hook_ids:
            try:
                _user32.UnhookWindowsHookEx(h)
            except Exception:
                pass
        self._hook_ids = []
        self._install_hooks()
        with self._lock:
            # Hook-side bookkeeping is gone with the old hooks; start clean
            # so stale state can never suppress input or fabricate deltas.
            self._pressed.clear()
            self._last_pos = None
            self._ignore_warps.clear()
            self._edge_hits = 0

    def _handle_mouse(self, wParam, lParam) -> int:
        info = MSLLHOOKSTRUCT.from_address(lParam)
        self._hook_activity = time.monotonic()
        if info.dwExtraInfo == SENTINEL:
            # Ignore injected input for transport, but let Windows deliver it
            # to the remote app. Returning 1 here cancels the injection.
            return _user32.CallNextHookEx(None, 0, wParam, lParam)
        engine = self.engine
        if engine is None:
            return _user32.CallNextHookEx(None, 0, wParam, lParam)
        x, y = int(info.pt.x), int(info.pt.y)
        if wParam == WM_MOUSEMOVE and self._consume_warp_move(x, y):
            # A warp landed; follow it so the next *physical* delta is
            # relative to the actual cursor, not a stale pre-warp position.
            self._last_pos = (x, y)
            return _user32.CallNextHookEx(None, 0, wParam, lParam)
        if self._mode == "remote":
            # Physical input on the controlled computer intentionally ends
            # sharing. SentInput events were returned above by their sentinel.
            engine.on_remote_local_input()
            return 1
        try:
            if wParam == WM_MOUSEMOVE:
                if self._last_pos is not None:
                    dx, dy = x - self._last_pos[0], y - self._last_pos[1]
                else:
                    dx = dy = 0
                self._last_pos = (x, y)
                engine.on_local_mouse(dx, dy, x, y)
                if self._mode == "controlling" and (dx or dy) and self._anchor is not None:
                    # Re-park the cursor on a center anchor: with the sprite
                    # pinned there the physical range is unbounded - it can
                    # never reach a screen edge and stall the delta stream
                    # ("stubborn" cursor). The landing warp is consumed by
                    # _consume_warp_move and the baseline is already set to
                    # the anchor, so the next physical delta stays exact.
                    self._last_pos = self._anchor
                    self.warp_cursor(*self._anchor)
            elif wParam == WM_LBUTTONDOWN:
                engine.on_local_button(0, True)
            elif wParam == WM_LBUTTONUP:
                engine.on_local_button(0, False)
            elif wParam == WM_RBUTTONDOWN:
                engine.on_local_button(1, True)
            elif wParam == WM_RBUTTONUP:
                engine.on_local_button(1, False)
            elif wParam == WM_MBUTTONDOWN:
                engine.on_local_button(2, True)
            elif wParam == WM_MBUTTONUP:
                engine.on_local_button(2, False)
            elif wParam == WM_XBUTTONDOWN or wParam == WM_XBUTTONUP:
                button = 2 + (info.mouseData >> 16)
                engine.on_local_button(button, wParam == WM_XBUTTONDOWN)
            elif wParam == WM_MOUSEWHEEL:
                dy = ctypes.c_short(info.mouseData >> 16).value
                engine.on_local_wheel(dy, 0)
            elif wParam == WM_MOUSEHWHEEL:
                dx = ctypes.c_short(info.mouseData >> 16).value
                engine.on_local_wheel(0, dx)
        except Exception:
            pass
        if self._mode == "local":
            return _user32.CallNextHookEx(None, 0, wParam, lParam)
        return 1  # suppress in controlling/remote

    def _handle_key(self, wParam, lParam) -> int:
        info = KBDLLHOOKSTRUCT.from_address(lParam)
        self._hook_activity = time.monotonic()
        if info.dwExtraInfo == SENTINEL:
            return _user32.CallNextHookEx(None, 0, wParam, lParam)
        engine = self.engine
        if engine is None:
            return _user32.CallNextHookEx(None, 0, wParam, lParam)
        try:
            from .kvm_keymap import win_scan_to_hid

            hid = win_scan_to_hid(int(info.scanCode), bool(info.flags & LLKHF_EXTENDED))
            if hid is not None:
                down = wParam in (WM_KEYDOWN, WM_SYSKEYDOWN)
                if down:
                    if hid in self._pressed:
                        # OS autorepeat: a held key must keep typing on the
                        # peer, so forward repeats while controlling. Local
                        # apps repeat on their own (never send them twice).
                        if self._mode == "controlling":
                            engine.on_local_key(hid, True)
                        return 1 if self._mode != "local" else _user32.CallNextHookEx(None, 0, wParam, lParam)
                    self._pressed.add(hid)
                else:
                    self._pressed.discard(hid)
                engine.on_local_key(hid, down)
        except Exception:
            pass
        if self._mode == "local":
            return _user32.CallNextHookEx(None, 0, wParam, lParam)
        return 1

    # -- delegation --------------------------------------------------------------

    def set_delegation(self, state: str) -> None:
        with self._lock:
            old = self._mode
            self._mode = state
            if state == "controlling":
                # A delegation change parks/restores the cursor; the first
                # physical move afterwards has no baseline, so its delta is
                # discarded (otherwise a stale position yields a huge jump).
                self._last_pos = None
                self._ignore_warps.clear()
                self._anchor = self._layout_center()
            if state != old:
                # Key bookkeeping can go stale across handoffs (a keyup lost
                # in a handoff window must not suppress future keydowns).
                self._pressed.clear()
        if state == "local":
            self.show_cursor()

    def _layout_center(self) -> tuple[int, int]:
        """Center of the virtual desktop, used as the controlling anchor."""
        try:
            layout = self.screen_layout()
            return layout.left() + layout.width() // 2, layout.top() + layout.height() // 2
        except Exception:
            try:
                return self.cursor_position()
            except Exception:
                return (0, 0)

    def diagnostics(self) -> dict:
        with self._lock:
            return {
                "family": "win",
                "mode": self._mode,
                "hook_thread_alive": bool(self._hook_thread and self._hook_thread.is_alive()),
                "ignore_warps": len(self._ignore_warps),
                "edge_hits": self._edge_hits,
                "cursor_hidden": self._cursor_hidden,
                "hook_stall_age": round(time.monotonic() - self._hook_activity, 1),
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
        now = time.monotonic()
        with self._lock:
            cached = self._layout_cache
            if cached is not None and now - cached[0] < 0.5:
                return cached[1]
        self._refresh_virtual_bounds()
        monitors = []
        for hmon, _, rect in win32api.EnumDisplayMonitors():
            scale = self._monitor_scale(hmon)
            x, y, r, b = rect
            monitors.append(Monitor(x, y, r - x, b - y, scale))
        layout = ScreenLayout(monitors, primary=0)
        with self._lock:
            self._layout_cache = (time.monotonic(), layout)
        return layout

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
        desktop (MOUSEEVENTF_ABSOLUTE|VIRTUALDESK).

        Absolute moves are exact: unlike relative moves they bypass the
        user's pointer speed / "enhance pointer precision" acceleration.
        """
        if self._virtual is None:
            return
        nx, ny = _virtual_normalize(x, y, self._virtual)
        _send_input(
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
        cursor at a time). ShowCursor uses a global display count, so keep
        decrementing until the cursor is actually gone."""
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
        """Injected relative motion as an exact absolute landing point.

        SendInput *relative* moves apply the user's pointer acceleration
        (pointer speed + "enhance pointer precision"), which would distort
        the forwarded deltas; computing the absolute landing point and
        sending an absolute move keeps the peer cursor 1:1 with the
        controller. Injected moves are sentinel-tagged so the hooks can
        never mistake them for physical input.
        """
        if not dx and not dy:
            return
        cx, cy = self.cursor_position()
        self._send_abs_move(cx + dx, cy + dy)
        self._report_edge(*self.cursor_position())

    def inject_move_abs(self, x: int, y: int) -> None:
        self.warp_cursor(x, y)
        self._report_edge(x, y)

    def _report_edge(self, x: int, y: int) -> None:
        """Seam detection at injection time: the controller drives our
        cursor with moves, so check the landing point for the return edge
        instead of polling.

        Debounced: two consecutive landings inside the jump zone are
        required. Injected motion is sentinel-tagged (never treated as
        local input by the hooks), so the only revert trigger from the
        injection path is this check; requiring a stable dwell at the edge
        keeps a single-frame landing from ending a session by accident.
        """
        if self._mode != "remote" or self.engine is None:
            return
        try:
            side = in_jump_zone(self.screen_layout(), x, y)
        except Exception:
            return
        if side is None:
            self._edge_hits = 0
            return
        self._edge_hits += 1
        if self._edge_hits < 2:
            return
        self._edge_hits = 0
        self.engine.on_remote_edge(side, x, y)

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
        _send_input(
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
            _send_input(inputs)

    def inject_key(self, hid: int, down: bool) -> None:
        from .kvm_keymap import hid_to_win_scan

        entry = hid_to_win_scan(hid)
        if entry is None:
            return
        scan, extended = entry
        flags = KEYEVENTF_SCANCODE | (KEYEVENTF_EXTENDEDKEY if extended else 0)
        if not down:
            flags |= KEYEVENTF_KEYUP
        _send_input(
            [
                INPUT(
                    type=INPUT_KEYBOARD,
                    ki=KEYBDINPUT(wVk=0, wScan=scan, dwFlags=flags, dwExtraInfo=SENTINEL),
                )
            ]
        )


def _send_input(inputs: list) -> None:
    if not inputs:
        return
    arr = (INPUT * len(inputs))(*inputs)
    _user32.SendInput(len(inputs), arr, ctypes.sizeof(INPUT))


def _virtual_normalize(x: int, y: int, virtual: tuple) -> tuple[int, int]:
    """Map a virtual-desktop pixel point to SendInput absolute units."""
    vx, vy, vr, vb = virtual
    nx = int((x - vx) * 65535.0 / max(1, vr - vx))
    ny = int((y - vy) * 65535.0 / max(1, vb - vy))
    return max(0, min(65535, nx)), max(0, min(65535, ny))
