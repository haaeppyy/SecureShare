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


pytestmark = pytest.mark.unit
