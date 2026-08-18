"""Windows input-platform behavior that is safe to test on every OS."""

import pytest
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
    def __init__(self, type, mi):
        self.type, self.mi = type, mi


def _install_fake_send_input(monkeypatch, sent):
    monkeypatch.setattr(win, "INPUT", _FakeInput, raising=False)
    monkeypatch.setattr(win, "MOUSEINPUT", _FakeMouseInput, raising=False)
    monkeypatch.setattr(win, "INPUT_MOUSE", 0, raising=False)
    monkeypatch.setattr(win, "MOUSEEVENTF_MOVE", 0x0001, raising=False)
    monkeypatch.setattr(win, "MOUSEEVENTF_ABSOLUTE", 0x8000, raising=False)
    monkeypatch.setattr(win, "MOUSEEVENTF_VIRTUALDESK", 0x4000, raising=False)

    def record(inputs):
        sent.extend(inputs)

    monkeypatch.setattr(win, "_send_input", record)


def test_inject_move_rel_sends_sentinel_relative_move(monkeypatch):
    """Relative injection must be a single MOUSEEVENTF_MOVE SendInput with
    the sentinel: no ABSOLUTE, no warp, no edge reporting, no cursor reads."""
    sent = []
    _install_fake_send_input(monkeypatch, sent)
    platform = object.__new__(win.WindowsInputPlatform)
    platform._ignore_warps = deque()
    called = []
    monkeypatch.setattr(platform, "warp_cursor", lambda x, y: called.append(("warp", x, y)))
    monkeypatch.setattr(platform, "cursor_position", lambda: called.append(("cursor_position",)))
    monkeypatch.setattr(platform, "_report_edge", lambda x, y: called.append(("report_edge", x, y)))

    platform.inject_move_rel(12, -3)

    assert len(sent) == 1
    assert sent[0].type == 0  # INPUT_MOUSE
    assert sent[0].mi.dx == 12 and sent[0].mi.dy == -3
    assert sent[0].mi.dwFlags == 0x0001  # MOUSEEVENTF_MOVE only, never ABSOLUTE
    assert sent[0].mi.dwExtraInfo == win.SENTINEL
    assert called == [], "relative injection must not warp, read, or report edges"
    assert len(platform._ignore_warps) == 0, "relative injection must not feed the warp filter"


def test_inject_move_rel_zero_is_noop(monkeypatch):
    sent = []
    _install_fake_send_input(monkeypatch, sent)
    platform = object.__new__(win.WindowsInputPlatform)

    platform.inject_move_rel(0, 0)

    assert sent == []


def test_inject_move_rel_never_touches_cursor_position(monkeypatch):
    sent = []
    _install_fake_send_input(monkeypatch, sent)
    platform = object.__new__(win.WindowsInputPlatform)

    for _ in range(5):
        platform.inject_move_rel(3, 2)

    assert len(sent) == 5
    assert all(s.mi.dwFlags == 0x0001 for s in sent)


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


pytestmark = pytest.mark.unit
