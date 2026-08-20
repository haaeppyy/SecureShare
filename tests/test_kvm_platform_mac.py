"""macOS input-platform behavior that is safe to test without real input."""

import pytest

from core import kvm_platform_mac as mac


class _QuartzForMove:
    kCGEventMouseMoved = 5
    kCGMouseButtonLeft = 0
    kCGEventSourceUserData = 42
    kCGSessionEventTap = 1

    def __init__(self):
        self.created = []
        self.posted = []

    def CGEventCreateMouseEvent(self, source, event_type, point, button):
        event = {"type": event_type, "point": point, "button": button}
        self.created.append(event)
        return event

    def CGEventSetIntegerValueField(self, event, field, value):
        event[field] = value

    def CGEventPost(self, tap, event):
        self.posted.append((tap, event))


class _QuartzForDelegation:
    def __init__(self):
        self.associations = []
        self.show_calls = 0

    def CGAssociateMouseAndMouseCursorPosition(self, associated):
        self.associations.append(associated)

    def CGMainDisplayID(self):
        return 1

    def CGDisplayShowCursor(self, display_id):
        self.show_calls += 1


def test_absolute_move_uses_quartz_mouse_button_constant(monkeypatch):
    """Mouse moves must not reference the nonexistent EventButton constant."""
    quartz = _QuartzForMove()
    monkeypatch.setattr(mac, "Quartz", quartz)
    monkeypatch.setattr(mac, "_QUARTZ_OK", True)
    platform = mac.MacInputPlatform()
    monkeypatch.setattr(platform, "warp_cursor", lambda x, y: None)
    monkeypatch.setattr(platform, "_report_edge", lambda x, y: None)

    platform.inject_move_abs(4, 540)

    assert quartz.created[0]["button"] == quartz.kCGMouseButtonLeft
    assert quartz.posted[0][1]["point"] == (4, 540)


def test_remote_delegation_disassociates_the_physical_pointing_device(monkeypatch):
    quartz = _QuartzForDelegation()
    monkeypatch.setattr(mac, "Quartz", quartz)
    monkeypatch.setattr(mac, "_QUARTZ_OK", True)
    platform = mac.MacInputPlatform()

    platform.set_delegation("remote")
    platform.set_delegation("local")

    assert quartz.associations == [False, True]
    assert quartz.show_calls == 1


def test_controlling_delegation_marks_first_motion_discardable(monkeypatch):
    """Entering controlling decouples the hardware and marks the first
    post-entry motion event as discardable (M1): it can carry a large
    stale pre-handoff delta."""
    quartz = _QuartzForDelegation()
    monkeypatch.setattr(mac, "Quartz", quartz)
    monkeypatch.setattr(mac, "_QUARTZ_OK", True)
    platform = mac.MacInputPlatform()

    platform.set_delegation("controlling")

    assert platform._mode == "controlling"
    assert platform._ignore_next_motion is True
    assert quartz.associations == [False]


def test_remote_delegation_resets_soft_cursor_and_edge_counter(monkeypatch):
    quartz = _QuartzForDelegation()
    monkeypatch.setattr(mac, "Quartz", quartz)
    monkeypatch.setattr(mac, "_QUARTZ_OK", True)
    platform = mac.MacInputPlatform()
    platform._soft_valid = True
    platform._edge_hits = 2

    platform.set_delegation("remote")

    assert platform._mode == "remote"
    assert platform._soft_valid is False
    assert platform._edge_hits == 0


def test_report_edge_requires_two_consecutive_landings():
    """The return seam is debounced like the Windows side (M2): a single
    frame landing inside the jump zone must not end the session."""
    from core.kvm_geometry import Monitor, ScreenLayout

    platform = mac.MacInputPlatform()
    platform._mode = "remote"
    platform.screen_layout = lambda: ScreenLayout([Monitor(0, 0, 1920, 1080)])
    calls = []

    class _Engine:
        def on_remote_edge(self, side, x, y):
            calls.append((side, x, y))

    platform.engine = _Engine()

    platform._report_edge(1919, 540)  # first landing inside the zone
    assert calls == []
    platform._report_edge(1919, 540)  # second consecutive landing fires
    assert calls == [("right", 1919, 540)]
    platform._report_edge(100, 100)  # leaving the zone resets the counter
    platform._report_edge(1919, 540)
    platform._report_edge(1919, 540)
    assert calls == [("right", 1919, 540), ("right", 1919, 540)]


pytestmark = pytest.mark.unit
