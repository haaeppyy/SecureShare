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
    kCGKeyboardEventAutorepeat and reach on_local_key, with the F6
    counters reflecting the mapping instead of an exception."""
    quartz = _QuartzNoKeyRepeat()
    monkeypatch.setattr(mac, "Quartz", quartz)
    monkeypatch.setattr(mac, "_QUARTZ_OK", True)
    platform = mac.MacInputPlatform()
    seen = []

    class Engine:
        def on_local_key(self, hid, down):
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
        def on_local_key(self, hid, down):
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


pytestmark = pytest.mark.unit
