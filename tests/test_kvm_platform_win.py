"""Windows input-platform behavior that is safe to test on every OS."""

import ctypes
import threading
import time
from collections import deque

import pytest

from core import kvm_platform_win as win


class _KbdHookLayout(ctypes.Structure):
    """Memory layout matching KBDLLHOOKSTRUCT on 64-bit (and 32-bit)."""

    _fields_ = [
        ("vkCode", ctypes.c_ulong),
        ("scanCode", ctypes.c_ulong),
        ("flags", ctypes.c_ulong),
        ("time", ctypes.c_ulong),
        ("dwExtraInfo", ctypes.c_void_p),
    ]


_LIVE_BUFFERS = []


def _key_lparam(scan=0x0E, flags=0):
    buf = _KbdHookLayout(vkCode=0x08, scanCode=scan, flags=flags, time=0, dwExtraInfo=None)
    _LIVE_BUFFERS.append(buf)  # keep the memory alive for from_address
    return ctypes.addressof(buf)


@pytest.fixture
def win_hook_structs(monkeypatch):
    """KBDLLHOOKSTRUCT exists only when _WIN_OK; supply an identical layout
    on other platforms so _handle_key is testable everywhere."""
    monkeypatch.setattr(win, "KBDLLHOOKSTRUCT", _KbdHookLayout, raising=False)
    return win.KBDLLHOOKSTRUCT


class _FakeUser32:
    @staticmethod
    def CallNextHookEx(*args):
        return 0


def test_normal_windows_desktop_does_not_require_administrator(monkeypatch):
    """KVM must not disable itself merely because the user is not elevated."""
    monkeypatch.setattr(win, "_WIN_OK", True)
    platform = object.__new__(win.WindowsInputPlatform)

    assert platform.permission_ok() is True
    assert platform.permission_detail() == "all permissions granted"


def test_warp_filter_handles_multiple_queued_cursor_updates():
    platform = object.__new__(win.WindowsInputPlatform)
    expiry = time.monotonic() + 1
    platform._ignore_warps = deque([(100, 100, expiry), (120, 120, expiry)])

    assert platform._consume_warp_move(100, 100) is True
    assert platform._consume_warp_move(120, 120) is True


def test_set_delegation_controlling_resets_baseline_and_key_state():
    """Entering controlling must discard the stale baseline (W3) and clear
    hook-side pressed-key bookkeeping (W8) so a stale keyup can never
    suppress future keydowns."""
    platform = object.__new__(win.WindowsInputPlatform)
    platform._lock = threading.RLock()
    platform._mode = "local"
    platform._last_pos = (100, 100)
    platform._ignore_warps = deque([(10, 10, time.monotonic() + 1)])
    platform._pressed = {0x2A}
    platform._anchor = None
    platform._cursor_hidden = False
    platform._layout_center = lambda: (960, 540)

    platform.set_delegation("controlling")

    assert platform._mode == "controlling"
    assert platform._last_pos is None
    assert platform._ignore_warps == deque()
    assert platform._pressed == set()
    assert platform._anchor == (960, 540)


def test_set_delegation_local_shows_cursor_and_clears_key_state():
    platform = object.__new__(win.WindowsInputPlatform)
    platform._lock = threading.RLock()
    platform._mode = "controlling"
    platform._pressed = {0x2A}
    platform._cursor_hidden = True
    shown = []
    platform.show_cursor = lambda: shown.append(1)

    platform.set_delegation("local")

    assert platform._mode == "local"
    assert platform._pressed == set()
    assert shown == [1]


def test_virtual_normalize_maps_to_65535_range():
    v = (0, 0, 1920, 1080)
    assert win._virtual_normalize(0, 0, v) == (0, 0)
    assert win._virtual_normalize(1920, 1080, v) == (65535, 65535)
    assert win._virtual_normalize(960, 540, v) == (32767, 32767)
    assert win._virtual_normalize(-500, 5000, v) == (0, 65535)


def test_handle_key_forwards_autorepeat_while_controlling(win_hook_structs):
    """A held key's repeat WM_KEYDOWNs must reach the peer (W6) or the
    remote never sees continuous registration."""
    platform = object.__new__(win.WindowsInputPlatform)
    platform._mode = "controlling"
    platform._pressed = set()
    events = []

    class _Engine:
        def on_local_key(self, hid, down):
            events.append((hid, down))

    platform.engine = _Engine()
    lparam = _key_lparam()

    assert platform._handle_key(0x0100, lparam) == 1  # first keydown
    assert platform._handle_key(0x0100, lparam) == 1  # autorepeat keydown
    assert platform._handle_key(0x0101, lparam) == 1  # keyup

    from core.kvm_keymap import win_scan_to_hid as to_hid

    assert events == [(to_hid(0x0E, False), True), (to_hid(0x0E, False), True), (to_hid(0x0E, False), False)]


def test_handle_key_repeat_passes_through_locally_without_forwarding(monkeypatch, win_hook_structs):
    """Local-mode repeats are handed to the OS (apps repeat on their own);
    the engine must not see them twice."""
    monkeypatch.setattr(win, "_user32", _FakeUser32, raising=False)
    platform = object.__new__(win.WindowsInputPlatform)
    platform._mode = "local"
    platform._pressed = set()
    events = []

    class _Engine:
        def on_local_key(self, hid, down):
            events.append((hid, down))

    platform.engine = _Engine()
    lparam = _key_lparam()

    platform._handle_key(0x0100, lparam)
    platform._handle_key(0x0100, lparam)  # repeat: pass-through, no forward

    from core.kvm_keymap import win_scan_to_hid as to_hid

    assert events == [(to_hid(0x0E, False), True)]


pytestmark = pytest.mark.unit
