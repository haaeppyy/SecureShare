"""macOS input-platform behavior that is safe to test without real input."""

import time

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
        self.hide_calls = 0
        self.show_calls = 0
        self.fail = False

    def CGAssociateMouseAndMouseCursorPosition(self, associated):
        if self.fail:
            raise OSError("association refused")
        self.associations.append(associated)

    def CGMainDisplayID(self):
        return 1

    def CGDisplayHideCursor(self, display_id):
        self.hide_calls += 1

    def CGDisplayShowCursor(self, display_id):
        self.show_calls += 1

    def CGEventCreate(self, source):
        return {"loc": (0, 0)}

    def CGEventGetLocation(self, event):
        return event["loc"]

    def CGWarpMouseCursorPosition(self, point):
        pass


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

    # Remote never hides the cursor, so the local restore shows nothing.
    assert quartz.associations == [False, True]
    assert quartz.hide_calls == 0
    assert quartz.show_calls == 0


def test_controlling_delegation_hides_and_shows_cursor_exactly_once(monkeypatch):
    """CGDisplayHideCursor/ShowCursor are refcounted: hide on controlling
    entry must be matched by exactly one show on local restore - repeated
    unbalanced shows leave the cursor stuck visible."""
    quartz = _QuartzForDelegation()
    monkeypatch.setattr(mac, "Quartz", quartz)
    monkeypatch.setattr(mac, "_QUARTZ_OK", True)
    platform = mac.MacInputPlatform()

    platform.set_delegation("controlling")
    assert quartz.hide_calls == 1 and quartz.show_calls == 0
    platform.set_delegation("controlling")  # idempotent re-apply
    assert quartz.hide_calls == 1 and quartz.show_calls == 0
    platform.set_delegation("local")
    assert quartz.show_calls == 1
    # a second local restore must not show again
    platform.set_delegation("local")
    assert quartz.show_calls == 1


def test_controlling_delegation_records_association_diagnostics(monkeypatch):
    """Problem A diagnostics: every CGAssociate... attempt is timestamped
    with the requested state and whether Quartz raised.  Controlling must
    issue exactly one False association and no True until local/stop."""
    quartz = _QuartzForDelegation()
    monkeypatch.setattr(mac, "Quartz", quartz)
    monkeypatch.setattr(mac, "_QUARTZ_OK", True)
    platform = mac.MacInputPlatform()

    assert platform.set_delegation("controlling") is True
    diag = platform.diagnostics()
    assert diag["mode"] == "controlling"
    assert diag["assoc_false"] == 1
    assert diag["assoc_true"] == 0
    assert diag["assoc_errors"] == 0
    calls = diag["assoc_calls"]
    assert len(calls) == 1
    rec = calls[0]
    assert rec["associate"] is False
    assert rec["state"] == "controlling"
    assert rec["ok"] is True
    assert rec["seq"] == 1

    # Idempotent re-apply while still controlling: still one False, no True.
    assert platform.set_delegation("controlling") is True
    diag = platform.diagnostics()
    assert diag["assoc_false"] == 2 and diag["assoc_true"] == 0
    assert all(c["associate"] is False for c in diag["assoc_calls"])
    assert diag["assoc_calls"][-1]["state"] == "controlling"

    # Local restore: exactly one True, the previous False call kept.
    assert platform.set_delegation("local") is True
    diag = platform.diagnostics()
    assert diag["assoc_false"] == 2 and diag["assoc_true"] == 1
    assert diag["assoc_calls"][-1]["associate"] is True
    assert diag["assoc_calls"][-1]["state"] == "local"

    # stop() re-associates and records it under the "stop" state.
    platform.stop()
    diag = platform.diagnostics()
    assert diag["assoc_true"] == 2
    assert diag["assoc_calls"][-1]["state"] == "stop"


def test_failed_association_recorded_without_flipping_mode(monkeypatch):
    """A raised CGAssociate... call is recorded as ok=False, bumps
    assoc_errors, and must NOT flip _mode (the stuck-cursor lie)."""
    quartz = _QuartzForDelegation()
    monkeypatch.setattr(mac, "Quartz", quartz)
    monkeypatch.setattr(mac, "_QUARTZ_OK", True)
    platform = mac.MacInputPlatform()

    quartz.fail = True
    assert platform.set_delegation("controlling") is False
    assert platform._mode == "local"
    diag = platform.diagnostics()
    assert diag["assoc_errors"] == 1
    assert diag["assoc_calls"][-1]["ok"] is False
    assert diag["assoc_calls"][-1]["associate"] is False
    # the failed entry must not leave the cursor hidden
    assert quartz.hide_calls == 1 and quartz.show_calls == 1


class _QuartzForDelegationFailure:
    def __init__(self):
        self.associations = []
        self.show_calls = 0
        self.fail = False

    def CGAssociateMouseAndMouseCursorPosition(self, associated):
        if self.fail:
            raise OSError("association refused")
        self.associations.append(associated)

    def CGMainDisplayID(self):
        return 1

    def CGDisplayShowCursor(self, display_id):
        self.show_calls += 1


def test_f2_delegation_failure_returns_false_and_keeps_old_mode(monkeypatch):
    """A failed CGAssociate... call must surface as False and must NOT
    flip _mode: the platform is still coupled, so claiming otherwise is
    the stuck-cursor lie."""
    quartz = _QuartzForDelegationFailure()
    monkeypatch.setattr(mac, "Quartz", quartz)
    monkeypatch.setattr(mac, "_QUARTZ_OK", True)
    platform = mac.MacInputPlatform()
    assert platform.set_delegation("remote") is True
    assert platform._mode == "remote"

    quartz.fail = True
    assert platform.set_delegation("local") is False
    assert platform._mode == "remote", "mode must roll back on failure"


def test_f6_diagnostics_reports_counters_and_first_exception(monkeypatch):
    quartz = _QuartzForMove()
    monkeypatch.setattr(mac, "Quartz", quartz)
    monkeypatch.setattr(mac, "_QUARTZ_OK", True)
    platform = mac.MacInputPlatform()

    platform._bump("exceptions")
    platform._bump("tap_keys")
    platform._bump("tap_disables")
    platform._note_exception(RuntimeError("boom"))

    diag = platform.diagnostics()
    assert diag["exceptions"] == 2
    assert diag["tap_keys"] == 1
    assert diag["tap_disables"] == 1
    assert "boom" in diag["first_exception"]
    assert diag["family"] == "mac"


def test_f7_keyboard_health_states(monkeypatch):
    monkeypatch.setattr(mac, "_QUARTZ_OK", True)
    platform = mac.MacInputPlatform()

    assert platform.keyboard_health() == "idle"

    platform._last_any = time.monotonic()
    platform._last_key = time.monotonic()
    assert platform.keyboard_health() == "ok"

    # Mouse events still flowing, keys silent for > 2s: the Secure Input
    # signature. (Deliberately no kCGEvent constants here: the platform
    # records these timestamps in _handle_tap.)
    platform._last_any = time.monotonic()
    platform._last_key = time.monotonic() - 3.0
    assert platform.keyboard_health() == "stalled"

    # Mouse alive but zero key events ever: the ambiguous signature.
    platform._last_any = time.monotonic()
    platform._last_key = 0.0
    assert platform.keyboard_health() == "no_keys"

    # Nothing at all for > 5s is a quiet machine, not a stall.
    platform._last_any = time.monotonic() - 10.0
    platform._last_key = 0.0
    assert platform.keyboard_health() == "idle"


class _QuartzNoKeyRepeat:
    """Mirrors real pyobjc: kCGKeyboardEventKeyRepeat does NOT exist
    (the genuine constant is kCGKeyboardEventAutorepeat). Accessing the
    missing attribute must raise AttributeError, exactly like a module."""

    kCGEventKeyDown = 10
    kCGEventKeyUp = 11
    kCGEventSourceUserData = 42
    kCGEventSourceUnixProcessID = 43
    kCGKeyboardEventAutorepeat = 8
    kCGKeyboardEventKeycode = 9

    def CGEventGetIntegerValueField(self, event, field):
        return event.get(field, 0)


def test_key_forwarding_survives_pyobjc_without_keyrepeat_attr(monkeypatch):
    """The live-Mac spike found every key event raising AttributeError on
    kCGKeyboardEventKeyRepeat: the forward path must use
    kCGKeyboardEventAutorepeat and reach observe_local_key, with the F6
    counters reflecting the mapping instead of an exception."""
    quartz = _QuartzNoKeyRepeat()
    monkeypatch.setattr(mac, "Quartz", quartz)
    monkeypatch.setattr(mac, "_QUARTZ_OK", True)
    platform = mac.MacInputPlatform()
    seen = []

    class Engine:
        def observe_local_key(self, hid, down):
            seen.append((hid, down))

    platform.engine = Engine()
    event = {
        quartz.kCGEventSourceUserData: 0,
        quartz.kCGEventSourceUnixProcessID: 0,
        quartz.kCGKeyboardEventAutorepeat: 0,
        quartz.kCGKeyboardEventKeycode: 0x00,  # 'a'
    }
    # initial key-down, autorepeat key-down, then key-up
    platform._forward(event, quartz.kCGEventKeyDown)
    event[quartz.kCGKeyboardEventAutorepeat] = 1
    platform._forward(event, quartz.kCGEventKeyDown)
    event[quartz.kCGKeyboardEventAutorepeat] = 0
    platform._forward(event, quartz.kCGEventKeyUp)
    assert seen == [(0x04, True), (0x04, True), (0x04, False)], seen

    event[quartz.kCGKeyboardEventAutorepeat] = 1
    platform._forward(event, quartz.kCGEventKeyUp)
    assert seen == [(0x04, True), (0x04, True), (0x04, False)], (
        "anomalous repeat-marked key-up must be ignored"
    )

    assert platform._stats["tap_keys"] == 4
    assert platform._stats["hid_mapped"] == 3
    assert platform._stats["exceptions"] == 0, "no key may raise an exception"


def test_key_forwarding_in_remote_mode_forwards_autorepeat(monkeypatch):
    """_forward_keys (remote mode) must also forward autorepeat key-downs:
    the emergency chord and held-key handling need the repeats."""
    quartz = _QuartzNoKeyRepeat()
    monkeypatch.setattr(mac, "Quartz", quartz)
    monkeypatch.setattr(mac, "_QUARTZ_OK", True)
    platform = mac.MacInputPlatform()
    seen = []

    class Engine:
        def observe_local_key(self, hid, down):
            seen.append((hid, down))

    platform.engine = Engine()
    event = {
        quartz.kCGEventSourceUserData: 0,
        quartz.kCGEventSourceUnixProcessID: 0,
        quartz.kCGKeyboardEventAutorepeat: 0,
        quartz.kCGKeyboardEventKeycode: 0x00,  # 'a'
    }
    platform._forward_keys(event, quartz.kCGEventKeyDown)
    event[quartz.kCGKeyboardEventAutorepeat] = 1
    platform._forward_keys(event, quartz.kCGEventKeyDown)
    event[quartz.kCGKeyboardEventAutorepeat] = 0
    platform._forward_keys(event, quartz.kCGEventKeyUp)
    assert seen == [(0x04, True), (0x04, True), (0x04, False)], seen
    assert platform._stats["exceptions"] == 0


class _QuartzForTap:
    kCGEventKeyDown = 10
    kCGEventKeyUp = 11
    kCGEventFlagsChanged = 12
    kCGEventMouseMoved = 5
    kCGEventLeftMouseDragged = 1
    kCGEventRightMouseDragged = 2
    kCGEventOtherMouseDragged = 3
    kCGEventSourceUserData = 42
    kCGEventSourceUnixProcessID = 43
    kCGKeyboardEventAutorepeat = 8
    kCGKeyboardEventKeycode = 9

    def __init__(self):
        self.retained = []
        self.released = []

    def CGEventGetIntegerValueField(self, event, field):
        return event.get(field, 0)

    def CGEventRetain(self, event):
        self.retained.append(event)

    def CGEventRelease(self, event):
        self.released.append(event)


def test_tap_callback_enqueues_and_worker_forwards(monkeypatch):
    """The Quartz callback must not call the engine: _handle_tap only
    retains, enqueues and returns; the worker translates and forwards."""
    quartz = _QuartzForTap()
    monkeypatch.setattr(mac, "Quartz", quartz)
    monkeypatch.setattr(mac, "_QUARTZ_OK", True)
    platform = mac.MacInputPlatform()
    seen = []

    class Engine:
        def observe_local_key(self, hid, down):
            seen.append((hid, down))

    platform.engine = Engine()
    event = {
        quartz.kCGEventSourceUserData: 0,
        quartz.kCGEventSourceUnixProcessID: 0,
        quartz.kCGKeyboardEventAutorepeat: 0,
        quartz.kCGKeyboardEventKeycode: 0x00,  # 'a'
    }

    assert platform._handle_tap(quartz.kCGEventKeyDown, event) is event
    assert len(quartz.retained) == 1
    # nothing reached the engine yet: the callback never translates
    assert seen == []
    with platform._queue_cv:
        assert len(platform._input_queue) == 1

    platform._process_record(*platform._input_queue.popleft())
    assert seen == [(0x04, True)]
    assert quartz.released == [event], "worker must release the retained event"


def test_queue_overflow_drops_motion_never_keys(monkeypatch):
    monkeypatch.setattr(mac, "_QUARTZ_OK", True)
    platform = mac.MacInputPlatform()
    platform._input_queue.extend(
        ("local", mac.Quartz.kCGEventMouseMoved, {"m": i}) for i in range(mac._TAP_QUEUE_MAX)
    )
    assert len(platform._input_queue) == mac._TAP_QUEUE_MAX

    # a new key-down evicts the oldest motion record
    key = ("local", mac.Quartz.kCGEventKeyDown, {"key": 1})
    platform._handle_queue_overflow(key)
    assert len(platform._input_queue) == mac._TAP_QUEUE_MAX
    assert platform._input_queue[-1] == key
    assert platform._stats["queue_dropped_motion"] == 1
    assert platform._stats["queue_dropped_critical"] == 0

    # new motion while full is dropped outright
    platform._handle_queue_overflow(("local", mac.Quartz.kCGEventMouseMoved, {"m": 999}))
    assert platform._input_queue[-1] == key, "the critical record must survive"
    assert platform._stats["queue_dropped_motion"] == 2

    # a queue of only critical records drops the oldest critical
    platform._input_queue.clear()
    platform._input_queue.extend(("local", mac.Quartz.kCGEventKeyDown, {"key": i}) for i in range(mac._TAP_QUEUE_MAX))
    platform._handle_queue_overflow(("local", mac.Quartz.kCGEventKeyUp, {"key": 99}))
    assert len(platform._input_queue) == mac._TAP_QUEUE_MAX
    assert platform._input_queue[-1][2]["key"] == 99
    assert platform._stats["queue_dropped_critical"] == 1


def test_sentinel_only_filtering_ignores_own_pid(monkeypatch):
    """Injected events are recognized by the source-user-data sentinel
    alone. The process-id must NOT filter: sandboxed/reblessed processes
    report unreliable pids, and wrongly filtered keys would be stuck."""
    quartz = _QuartzNoKeyRepeat()
    monkeypatch.setattr(mac, "Quartz", quartz)
    monkeypatch.setattr(mac, "_QUARTZ_OK", True)
    platform = mac.MacInputPlatform()
    seen = []

    class Engine:
        def observe_local_key(self, hid, down):
            seen.append((hid, down))

    platform.engine = Engine()
    # our own pid, no sentinel: MUST be observed (old code dropped it)
    own = {
        quartz.kCGEventSourceUserData: 0,
        quartz.kCGEventSourceUnixProcessID: 123456,
        quartz.kCGKeyboardEventAutorepeat: 0,
        quartz.kCGKeyboardEventKeycode: 0x00,
    }
    platform._forward(own, quartz.kCGEventKeyDown)
    assert seen == [(0x04, True)], "own-pid without sentinel must be observed"

    # sentinel set: must be dropped even with a foreign pid
    sentinel = {
        quartz.kCGEventSourceUserData: mac.SENTINEL,
        quartz.kCGEventSourceUnixProcessID: 1,
        quartz.kCGKeyboardEventAutorepeat: 0,
        quartz.kCGKeyboardEventKeycode: 0x00,
    }
    platform._forward(sentinel, quartz.kCGEventKeyDown)
    assert seen == [(0x04, True)], "sentinel events must never reach the engine"


class _QuartzForControlling:
    kCGEventKeyDown = 10
    kCGEventKeyUp = 11
    kCGEventFlagsChanged = 12
    kCGEventMouseMoved = 5
    kCGEventLeftMouseDragged = 1
    kCGEventRightMouseDragged = 2
    kCGEventOtherMouseDragged = 3
    kCGEventLeftMouseDown = 25
    kCGEventLeftMouseUp = 26
    kCGEventRightMouseDown = 27
    kCGEventRightMouseUp = 28
    kCGEventOtherMouseDown = 29
    kCGEventOtherMouseUp = 30
    kCGEventScrollWheel = 22
    kCGMouseEventDeltaX = 1
    kCGMouseEventDeltaY = 2
    kCGScrollWheelEventDeltaAxis1 = 11
    kCGScrollWheelEventDeltaAxis2 = 12
    kCGEventSourceUserData = 42

    def __init__(self):
        self.associations = []
        self.hide_calls = 0
        self.show_calls = 0

    def CGEventGetIntegerValueField(self, event, field):
        return event.get(field, 0)

    def CGEventGetLocation(self, event):
        return event["loc"]

    def CGAssociateMouseAndMouseCursorPosition(self, associated):
        self.associations.append(associated)

    def CGMainDisplayID(self):
        return 1

    def CGDisplayHideCursor(self, display_id):
        self.hide_calls += 1

    def CGDisplayShowCursor(self, display_id):
        self.show_calls += 1

    def CGEventCreate(self, source):
        return {"loc": _Point(0, 0)}

    def CGWarpMouseCursorPosition(self, point):
        pass


from collections import namedtuple

_Point = namedtuple("Point", "x y")


def test_controlling_discards_first_motion_after_entry(monkeypatch):
    """The first motion event after disassociation can carry a stale
    pre-entry delta and must be discarded (review F3)."""
    quartz = _QuartzForControlling()
    monkeypatch.setattr(mac, "Quartz", quartz)
    monkeypatch.setattr(mac, "_QUARTZ_OK", True)
    platform = mac.MacInputPlatform()
    moves = []

    class Engine:
        def observe_local_mouse(self, dx, dy, x, y):
            moves.append((dx, dy))

        def send_controlled_mouse(self, dx, dy):
            moves.append(("sent", dx, dy))

    platform.engine = Engine()
    assert platform.set_delegation("controlling") is True

    stale = {quartz.kCGEventSourceUserData: 0, quartz.kCGMouseEventDeltaX: 500, quartz.kCGMouseEventDeltaY: -300, "loc": _Point(50, 60)}
    platform._forward(stale, quartz.kCGEventMouseMoved, mode="controlling")
    assert moves == [], "first motion after entry must be discarded"

    fresh = {quartz.kCGEventSourceUserData: 0, quartz.kCGMouseEventDeltaX: -3, quartz.kCGMouseEventDeltaY: 7, "loc": _Point(50, 60)}
    platform._forward(fresh, quartz.kCGEventMouseMoved, mode="controlling")
    assert moves == [(-3, 7), ("sent", -3, 7)], "second motion must be observed and sent"

    assert platform._ignore_next_motion is False


def test_tap_disable_invalidates_ownership(monkeypatch):
    """When macOS disables the tap, the platform must release everything,
    re-associate the mouse, show the cursor, return to local and tell the
    engine - the peer must not believe it still owns this Mac."""
    quartz = _QuartzForDelegation()
    monkeypatch.setattr(mac, "Quartz", quartz)
    monkeypatch.setattr(mac, "_QUARTZ_OK", True)
    platform = mac.MacInputPlatform()
    lost = []
    released = []

    class Engine:
        def on_platform_input_lost(self):
            lost.append(True)

    def fake_inject_key(hid, down):
        released.append((hid, down))

    platform.engine = Engine()
    monkeypatch.setattr(platform, "inject_key", fake_inject_key)
    monkeypatch.setattr(platform, "inject_button", lambda b, down: None)
    assert platform.set_delegation("controlling") is True
    with platform._lock:
        platform._pressed_keys = {0x04, 0x2C}
        platform._injected_keys = {0xE0}
        platform._injected_buttons = {0}

    platform._on_tap_disabled("timeout")

    assert platform._mode == "local"
    assert lost == [True], "engine must be told ownership is lost"
    assert quartz.associations[-1] is True, "mouse must be re-associated"
    assert quartz.show_calls == 1, "cursor must be shown"
    assert platform._pressed_keys == set() and platform._injected_keys == set()
    assert platform._injected_buttons == set()
    ups = sorted(r for r in released if r[1] is False)
    assert ups == [(0x04, False), (0x2C, False), (0xE0, False)], ups
    assert platform._stats["tap_disables_timeout"] == 1
    assert platform._stats["tap_disables"] == 1


def test_tap_disable_user_input_logged_separately(monkeypatch):
    monkeypatch.setattr(mac, "_QUARTZ_OK", True)
    platform = mac.MacInputPlatform()
    platform._on_tap_disabled("user")
    assert platform._stats["tap_disables_user"] == 1
    assert platform._stats["tap_disables_timeout"] == 0


class _QuartzForSoftwareCursor:
    kCGEventMouseMoved = 5
    kCGMouseButtonLeft = 0
    kCGEventSourceUserData = 42
    kCGSessionEventTap = 1

    def __init__(self):
        self.posted = []

    def CGEventCreateMouseEvent(self, source, event_type, point, button):
        return {"type": event_type, "point": point, "button": button}

    def CGEventSetIntegerValueField(self, event, field, value):
        event[field] = value

    def CGEventPost(self, tap, event):
        self.posted.append((tap, event))


def test_rel_injection_uses_software_cursor_without_warping(monkeypatch):
    """Relative injection must maintain an application-side position and
    post absolute events, never warp the real cursor per event (review
    F3/F4): warping interferes with tap deltas and suppression."""
    quartz = _QuartzForSoftwareCursor()
    monkeypatch.setattr(mac, "Quartz", quartz)
    monkeypatch.setattr(mac, "_QUARTZ_OK", True)
    platform = mac.MacInputPlatform()
    warps = []
    monkeypatch.setattr(platform, "warp_cursor", lambda x, y: warps.append((x, y)))
    monkeypatch.setattr(platform, "cursor_position", lambda: (100, 200))
    monkeypatch.setattr(platform, "_report_edge", lambda x, y: None)

    platform.inject_move_rel(10, -20)
    assert platform._soft_x == 110 and platform._soft_y == 180
    assert warps == [], "per-event warping is forbidden"
    assert quartz.posted[0][1]["point"] == (110, 180)

    platform.inject_move_rel(-5, 5)
    assert platform._soft_x == 105 and platform._soft_y == 185
    assert quartz.posted[1][1]["point"] == (105, 185)
    assert warps == []

    platform.inject_move_abs(400, 300)
    assert platform._soft_x == 400 and platform._soft_y == 300
    assert quartz.posted[2][1]["point"] == (400, 300)
    assert warps == [], "absolute injection must not warp either"


def test_remote_mode_observes_keys_only(monkeypatch):
    """Remote mode: the peer owns the pointer - mouse/buttons/wheel are
    ignored and no physical input hands control back; keys are observed
    for the emergency chord."""
    quartz = _QuartzForTap()
    monkeypatch.setattr(mac, "Quartz", quartz)
    monkeypatch.setattr(mac, "_QUARTZ_OK", True)
    platform = mac.MacInputPlatform()
    seen = []

    class Engine:
        def observe_local_key(self, hid, down):
            seen.append(("key", hid, down))

        def observe_local_mouse(self, dx, dy, x, y):
            seen.append(("mouse", dx, dy))

    platform.engine = Engine()
    platform._mode = "remote"

    key_event = {
        quartz.kCGEventSourceUserData: 0,
        quartz.kCGKeyboardEventAutorepeat: 0,
        quartz.kCGKeyboardEventKeycode: 0x00,
    }
    platform._process_record("remote", quartz.kCGEventKeyDown, key_event)
    assert seen == [("key", 0x04, True)]

    platform._process_record("remote", quartz.kCGEventMouseMoved, {"user": 0})
    assert seen == [("key", 0x04, True)], "mouse input must be ignored in remote mode"

    assert quartz.released == [key_event, {"user": 0}]


pytestmark = pytest.mark.unit
