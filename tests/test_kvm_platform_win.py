"""Windows input-platform behavior that is safe to test on every OS."""

import pytest
import threading
import time
from collections import deque

from core import kvm_platform_win as win


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


class _FakeMouseInput:
    def __init__(self, dx, dy, mouseData, dwFlags, dwExtraInfo):
        self.dx, self.dy = dx, dy
        self.mouseData, self.dwFlags, self.dwExtraInfo = mouseData, dwFlags, dwExtraInfo


class _FakeInput:
    def __init__(self, type, mi=None, ki=None):
        self.type, self.mi, self.ki = type, mi, ki


class _FakeKeyInput:
    def __init__(self, wVk, wScan, dwFlags, dwExtraInfo):
        self.wVk, self.wScan, self.dwFlags, self.dwExtraInfo = wVk, wScan, dwFlags, dwExtraInfo


def _install_fake_send_input(monkeypatch, sent):
    monkeypatch.setattr(win, "INPUT", _FakeInput, raising=False)
    monkeypatch.setattr(win, "MOUSEINPUT", _FakeMouseInput, raising=False)
    monkeypatch.setattr(win, "KEYBDINPUT", _FakeKeyInput, raising=False)
    monkeypatch.setattr(win, "INPUT_MOUSE", 0, raising=False)
    monkeypatch.setattr(win, "INPUT_KEYBOARD", 1, raising=False)
    monkeypatch.setattr(win, "MOUSEEVENTF_MOVE", 0x0001, raising=False)
    monkeypatch.setattr(win, "MOUSEEVENTF_ABSOLUTE", 0x8000, raising=False)
    monkeypatch.setattr(win, "MOUSEEVENTF_VIRTUALDESK", 0x4000, raising=False)
    monkeypatch.setattr(
        win.WindowsInputPlatform, "_send_input", lambda self, inputs: sent.extend(inputs)
    )


def test_inject_move_rel_sends_absolute_move(monkeypatch):
    """Relative deltas must be delivered as exact absolute SendInput moves
    (plain relative moves are distorted by pointer acceleration), computed
    from the current position - never a warp, never edge reporting."""
    sent = []
    _install_fake_send_input(monkeypatch, sent)
    platform = object.__new__(win.WindowsInputPlatform)
    platform._ignore_warps = deque()
    platform._virtual = (0, 0, 1920, 1080)
    called = []
    monkeypatch.setattr(platform, "warp_cursor", lambda x, y: called.append(("warp", x, y)))
    monkeypatch.setattr(platform, "cursor_position", lambda: (500, 400))
    monkeypatch.setattr(platform, "_report_edge", lambda x, y: called.append(("report_edge", x, y)))

    platform.inject_move_rel(12, -3)

    assert len(sent) == 1
    assert sent[0].type == 0  # INPUT_MOUSE
    # landing point (512, 397) normalized over the 1920x1080 virtual desktop
    assert sent[0].mi.dx == int(512 * 65535 / 1920)
    assert sent[0].mi.dy == int(397 * 65535 / 1080)
    assert sent[0].mi.dwFlags == 0x0001 | 0x8000 | 0x4000  # MOVE|ABSOLUTE|VIRTUALDESK
    assert sent[0].mi.dwExtraInfo == win.SENTINEL
    assert called == [], "relative injection must not warp or report edges"
    assert len(platform._ignore_warps) == 0, "relative injection must not feed the warp filter"


def test_inject_move_rel_zero_is_noop(monkeypatch):
    sent = []
    _install_fake_send_input(monkeypatch, sent)
    platform = object.__new__(win.WindowsInputPlatform)

    platform.inject_move_rel(0, 0)

    assert sent == []


def test_inject_move_rel_streams_absolute_moves(monkeypatch):
    sent = []
    _install_fake_send_input(monkeypatch, sent)
    platform = object.__new__(win.WindowsInputPlatform)
    platform._virtual = (0, 0, 1920, 1080)
    positions = iter([(500, 400), (503, 402), (506, 404), (509, 406), (512, 408)])
    monkeypatch.setattr(platform, "cursor_position", lambda: next(positions))

    for _ in range(5):
        platform.inject_move_rel(3, 2)

    assert len(sent) == 5
    assert all(s.mi.dwFlags == 0x0001 | 0x8000 | 0x4000 for s in sent)
    # final landing point: (515, 410)
    assert sent[-1].mi.dx == int(515 * 65535 / 1920)
    assert sent[-1].mi.dy == int(410 * 65535 / 1080)


def test_warp_filter_ignores_expired_entries():
    platform = object.__new__(win.WindowsInputPlatform)
    platform._ignore_warps = deque([(100, 100, time.monotonic() - 1)])

    assert platform._consume_warp_move(100, 100) is False
    assert platform._ignore_warps == deque()


def test_warp_filter_ignores_large_mismatch():
    platform = object.__new__(win.WindowsInputPlatform)
    expiry = time.monotonic() + 1
    platform._ignore_warps = deque([(100, 100, expiry)])

    assert platform._consume_warp_move(105, 100) is False
    assert len(platform._ignore_warps) == 1, "unmatched entry must survive for a later move"


def test_warp_filter_consumes_exact_match():
    platform = object.__new__(win.WindowsInputPlatform)
    expiry = time.monotonic() + 1
    platform._ignore_warps = deque([(100, 100, expiry)])

    assert platform._consume_warp_move(100, 100) is True
    assert platform._ignore_warps == deque()


def test_warp_fallback_uses_absolute_virtual_desktop_move(monkeypatch):
    sent = []
    _install_fake_send_input(monkeypatch, sent)
    platform = object.__new__(win.WindowsInputPlatform)
    platform._virtual = (0, 0, 1920, 1080)

    platform._warp_fallback(960, 540)

    assert len(sent) == 1
    assert sent[0].mi.dwFlags == 0x0001 | 0x8000 | 0x4000  # MOVE|ABSOLUTE|VIRTUALDESK
    assert sent[0].mi.dwExtraInfo == win.SENTINEL
    assert sent[0].mi.dx > 0 and sent[0].mi.dy > 0


def test_inject_key_tracks_injected_state(monkeypatch):
    sent = []
    _install_fake_send_input(monkeypatch, sent)
    platform = object.__new__(win.WindowsInputPlatform)
    platform._injected_pressed = set()
    monkeypatch.setattr("core.kvm_keymap.hid_to_win_scan", lambda hid: (0x1E, 0))
    monkeypatch.setattr(win, "KEYEVENTF_SCANCODE", 0x0008, raising=False)
    monkeypatch.setattr(win, "KEYEVENTF_KEYUP", 0x0002, raising=False)
    monkeypatch.setattr(win, "KEYEVENTF_EXTENDEDKEY", 0x0001, raising=False)

    platform.inject_key(0x04, True)
    assert platform._injected_pressed == {0x04}
    platform.inject_key(0x04, False)
    assert platform._injected_pressed == set()


def test_set_delegation_clears_injected_keys_on_remote_exit(monkeypatch):
    sent = []
    _install_fake_send_input(monkeypatch, sent)
    platform = object.__new__(win.WindowsInputPlatform)
    platform._mode = "remote"
    platform._lock = threading.RLock()
    platform._injected_pressed = {0x04}
    platform._cursor_hidden = True
    platform._last_pos = (100, 100)
    platform._ignore_warps = deque()
    monkeypatch.setattr("core.kvm_keymap.hid_to_win_scan", lambda hid: (0x1E, 0))
    monkeypatch.setattr(win, "KEYEVENTF_SCANCODE", 0x0008, raising=False)
    monkeypatch.setattr(win, "KEYEVENTF_KEYUP", 0x0002, raising=False)
    monkeypatch.setattr(win, "KEYEVENTF_EXTENDEDKEY", 0x0001, raising=False)
    monkeypatch.setattr(platform, "show_cursor", lambda: None)

    assert platform.set_delegation("local") is True

    assert platform._injected_pressed == set(), "held injected keys must be released"
    assert sent, "release key-ups must be sent"


def test_set_delegation_controlling_resets_position_baseline():
    platform = object.__new__(win.WindowsInputPlatform)
    platform._mode = "local"
    platform._lock = threading.RLock()
    platform._last_pos = (100, 100)
    platform._ignore_warps = deque([(100, 100, time.monotonic() + 1)])
    platform._injected_pressed = set()
    platform._cursor_hidden = False

    assert platform.set_delegation("controlling") is True

    assert platform._last_pos is None, "baseline must reset on delegation change"
    assert platform._ignore_warps == deque(), "stale warp slots must clear"


pytestmark = pytest.mark.unit
