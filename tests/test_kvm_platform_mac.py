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
    monkeypatch.setattr(platform, "_cache_geometry", lambda: None)

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
    monkeypatch.setattr(platform, "_cache_geometry", lambda: None)

    platform.set_delegation("controlling")

    assert platform._mode == "controlling"
    assert platform._ignore_next_motion is True
    assert quartz.associations == [False]


def test_remote_delegation_resets_soft_cursor_and_edge_counter(monkeypatch):
    quartz = _QuartzForDelegation()
    monkeypatch.setattr(mac, "Quartz", quartz)
    monkeypatch.setattr(mac, "_QUARTZ_OK", True)
    platform = mac.MacInputPlatform()
    monkeypatch.setattr(platform, "_cache_geometry", lambda: None)
    platform._soft_valid = True
    platform._edge_hits = 2

    platform.set_delegation("remote")

    assert platform._mode == "remote"
    assert platform._soft_valid is False
    assert platform._edge_hits == 0


def test_controlling_delegation_caches_anchor_and_scale(monkeypatch):
    """B1: entering controlling caches the layout center as the re-park
    anchor and the display scale used for point/pixel conversion."""
    quartz = _QuartzForDelegation()
    monkeypatch.setattr(mac, "Quartz", quartz)
    monkeypatch.setattr(mac, "_QUARTZ_OK", True)
    platform = mac.MacInputPlatform()
    monkeypatch.setattr(platform, "cursor_position", lambda: (100, 100))
    monkeypatch.setattr(platform, "_screen_scale", lambda x, y: 2.0)
    monkeypatch.setattr(platform, "_layout_center", lambda: (640, 360))

    platform.set_delegation("controlling")

    assert platform._anchor == (640, 360)
    assert platform._scale == 2.0


class _Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y


class _QuartzForForward:
    kCGEventMouseMoved = 5
    kCGEventLeftMouseDragged = 6
    kCGEventRightMouseDragged = 7
    kCGEventOtherMouseDragged = 8
    kCGEventKeyDown = 10
    kCGEventKeyUp = 11
    kCGEventFlagsChanged = 12
    kCGEventLeftMouseDown = 1
    kCGEventLeftMouseUp = 2
    kCGEventRightMouseDown = 3
    kCGEventRightMouseUp = 4
    kCGEventOtherMouseDown = 25
    kCGEventOtherMouseUp = 26
    kCGEventScrollWheel = 22
    kCGKeyboardEventKeycode = 100
    kCGKeyboardEventAutorepeat = 101
    kCGScrollWheelEventDeltaAxis1 = 11
    kCGScrollWheelEventDeltaAxis2 = 12
    kCGEventSourceUserData = 42
    kCGEventSourceUnixProcessID = 43
    kCGMouseEventDeltaX = 1
    kCGMouseEventDeltaY = 2

    def __init__(self):
        self.warps = []
        self.deltas = {}

    def CGEventGetIntegerValueField(self, event, field):
        return self.deltas.get(field, 0)

    def CGEventGetLocation(self, event):
        return _Point(100, 100)

    def CGWarpMouseCursorPosition(self, point):
        self.warps.append(point)


def test_forward_scales_deltas_and_recenters_while_controlling(monkeypatch):
    """A1+B2: point-deltas are scaled to physical pixels for the peer,
    and the sprite is re-parked on the anchor after every forwarded move."""
    quartz = _QuartzForForward()
    monkeypatch.setattr(mac, "Quartz", quartz)
    monkeypatch.setattr(mac, "_QUARTZ_OK", True)
    platform = mac.MacInputPlatform()
    moves = []

    class _Engine:
        def on_local_mouse(self, dx, dy, x, y):
            moves.append((dx, dy, x, y))

    platform.engine = _Engine()
    platform._mode = "controlling"
    platform._scale = 2.0
    platform._anchor = (640, 360)
    quartz.deltas = {mac.Quartz.kCGMouseEventDeltaX: 12, mac.Quartz.kCGMouseEventDeltaY: -8}

    platform._forward({"fake": "event"}, quartz.kCGEventMouseMoved)

    assert moves == [(24, -16, 100, 100)]
    assert quartz.warps == [(640, 360)]


def test_forward_does_not_recenter_in_local_mode(monkeypatch):
    quartz = _QuartzForForward()
    monkeypatch.setattr(mac, "Quartz", quartz)
    monkeypatch.setattr(mac, "_QUARTZ_OK", True)
    platform = mac.MacInputPlatform()
    moves = []

    class _Engine:
        def on_local_mouse(self, dx, dy, x, y):
            moves.append((dx, dy, x, y))

    platform.engine = _Engine()
    platform._mode = "local"
    platform._scale = 2.0
    platform._anchor = (640, 360)
    quartz.deltas = {mac.Quartz.kCGMouseEventDeltaX: 12, mac.Quartz.kCGMouseEventDeltaY: -8}

    platform._forward({"fake": "event"}, quartz.kCGEventMouseMoved)

    assert moves == [(24, -16, 100, 100)]
    assert quartz.warps == []


def test_inject_move_rel_scales_pixel_deltas_to_points(monkeypatch):
    """A2: incoming physical-pixel deltas from the peer are converted to
    points before accumulating the software cursor position."""
    from core.kvm_geometry import Monitor, ScreenLayout

    quartz = _QuartzForMove()
    monkeypatch.setattr(mac, "Quartz", quartz)
    monkeypatch.setattr(mac, "_QUARTZ_OK", True)
    platform = mac.MacInputPlatform()
    monkeypatch.setattr(platform, "cursor_position", lambda: (100, 100))
    monkeypatch.setattr(
        platform, "screen_layout", lambda: ScreenLayout([Monitor(0, 0, 1280, 832)])
    )
    monkeypatch.setattr(platform, "_report_edge", lambda x, y: None)
    platform._scale = 2.0

    platform.inject_move_rel(24, -16)

    assert platform._soft_x == 112  # 100 + 24/2
    assert platform._soft_y == 92  # 100 + (-16)/2
    assert quartz.posted[0][1]["point"] == (112, 92)


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
