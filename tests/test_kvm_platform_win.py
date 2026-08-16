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


pytestmark = pytest.mark.unit
