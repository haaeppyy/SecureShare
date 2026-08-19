"""macOS input platform for keyboard/mouse sharing.

Capture is a Quartz CGEventTap on a dedicated CFRunLoop thread. The tap
runs whenever the engine is started; ``set_delegation`` decides what the
callback does with each event:

    local       return the original event (apps see it normally) while
                also observing it watch-only (seam detection, chord
                arming). Local-mode input is never transmitted.
    controlling swallow the event (return None) and forward it to the
                engine, which drives the peer; the cursor is hidden and
                the hardware cursor is disassociated before forwarding
                starts, and the first post-entry motion event (which can
                carry a stale delta) is discarded.
    remote      keys pass through (the local user keeps the keyboard and
                the emergency chord) while mouse/buttons/wheel are
                swallowed: the peer owns the pointer.

The Quartz callback must return quickly or macOS disables the tap. It
therefore only reads cheap fields, retains the event, and appends a
compact record to a bounded queue drained by a worker thread. The
overflow policy merges overflowed mouse motion into the last queued
motion record (relative deltas sum exactly, so no movement is lost)
and evicts motion to make room for key/button transitions, which are
never dropped, so a stuck modifier is impossible.

Injected events carry a kCGEventSourceUserData sentinel; the tap drops
anything marked like that, so input never echoes. Only the sentinel is
trusted - the process-id check was removed because sandboxed/reblessed
processes do not reliably report the pid Quartz expects.

Relative remote motion is injected as an absolute MouseMoved posted from
an application-maintained software cursor position (clamped to the
layout), never by warping the real cursor per event. The real cursor is
warped only for placement (handoff entry/return). The return seam is
detected at injection time (the peer drives our cursor with absolute
moves), not by a poller.

If macOS disables the tap (timeout or user input), the platform
immediately: releases all pressed/injected keys and buttons, re-associates
the mouse, shows the cursor, returns to local mode, and tells the engine
so the peer no longer believes it owns this machine. Only then is the tap
re-enabled.

Requires Accessibility permission for both the event tap and CGEventPost
(CGPreflightListenEventAccess / CGPreflightPostEventAccess).
"""

import collections
import os
import threading
import time

from .kvm_geometry import Monitor, ScreenLayout, in_jump_zone

SENTINEL = 0x5E4C0DE5

# Max records waiting for the worker. The tap callback must never block,
# so when this is full the overflow policy merges motion into the last
# queued motion record (never drops it) and only evicts motion to make
# room for key/button transitions.
_TAP_QUEUE_MAX = 512

try:
    import Quartz
    from AppKit import NSScreen
    from CoreFoundation import (
        CFMachPortCreateRunLoopSource,
        CFMachPortInvalidate,
        CFRunLoopAddSource,
        CFRunLoopGetCurrent,
        CFRunLoopRemoveSource,
        CFRunLoopRun,
        CFRunLoopStop,
        kCFRunLoopCommonModes,
    )

    _QUARTZ_OK = True
except ImportError:  # pragma: no cover - non-macOS
    Quartz = None
    NSScreen = None
    CFMachPortCreateRunLoopSource = None
    CFMachPortInvalidate = None
    CFRunLoopAddSource = None
    CFRunLoopGetCurrent = None
    CFRunLoopRemoveSource = None
    CFRunLoopRun = None
    CFRunLoopStop = None
    kCFRunLoopCommonModes = None
    _QUARTZ_OK = False


class MacPlatformError(Exception):
    pass


def _q():
    if not _QUARTZ_OK:
        raise MacPlatformError("Quartz unavailable (not macOS or pyobjc missing)")
    return Quartz


class MacInputPlatform:
    def __init__(self):
        self.engine = None
        self._tap_port = None
        self._tap_runloop = None
        self._tap_thread = None
        self._mode = "local"
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._callback_ref = None
        # Bounded tap queue: the Quartz callback enqueues (mode, etype,
        # retained event) records; the worker thread translates and calls
        # the engine. See module docstring for the overflow policy.
        self._input_queue: collections.deque = collections.deque()
        self._queue_cv = threading.Condition()
        self._tap_worker = None
        # First mouse-motion event after entering "controlling" can carry
        # a stale pre-disassociation delta; it is discarded.
        self._ignore_next_motion = False
        # Software cursor for relative injection (never per-event warping).
        self._soft_x = 0
        self._soft_y = 0
        self._soft_valid = False
        # Physical keys observed at the tap, and keys/buttons this process
        # injected: released together when the tap dies or ownership ends.
        self._pressed_keys: set = set()
        self._injected_keys: set = set()
        self._injected_buttons: set = set()
        self._cursor_hidden = False
        # F6 diagnostics: counters, never toasted per event.
        self._stats = {
            "tap_keys": 0,
            "hid_mapped": 0,
            "hid_unmapped": 0,
            "exceptions": 0,
            "tap_disables": 0,
            "tap_disables_timeout": 0,
            "tap_disables_user": 0,
            "tap_restarts": 0,
            "assoc_false": 0,
            "assoc_true": 0,
            "assoc_errors": 0,
            "queue_dropped_motion": 0,
            "queue_merged_motion": 0,
            "queue_dropped_critical": 0,
            "worker_exceptions": 0,
        }
        self._first_exception = None
        # F6: every CGAssociateMouseAndMouseCursorPosition attempt, whether
        # it raised, and the state that requested it.  Quartz has no useful
        # success return, so "ok" only means "did not raise"; the spike
        # (--controller) verifies the runtime effect on a real Mac.
        self._assoc_seq = 0
        self._assoc_calls: collections.deque = collections.deque(maxlen=32)
        # F7 keyboard health: last event / last key seen at the tap.
        self._last_any = 0.0
        self._last_key = 0.0

    def _bump(self, name: str, amount: int = 1) -> None:
        with self._lock:
            self._stats[name] = self._stats.get(name, 0) + amount

    def diagnostics(self) -> dict:
        with self._lock:
            return {
                "family": "mac",
                "mode": self._mode,
                **dict(self._stats),
                "assoc_calls": list(self._assoc_calls),
                "first_exception": self._first_exception,
                "last_key_age": time.monotonic() - self._last_key if self._last_key else None,
                "last_any_age": time.monotonic() - self._last_any if self._last_any else None,
            }

    # -- lifecycle ------------------------------------------------------------

    def start(self, engine) -> None:
        if not self.permission_ok():
            self.request_permission()
        if not self.permission_ok():
            raise MacPlatformError("missing Accessibility permission")
        self.engine = engine
        engine._capture_origin = "mac"
        self._stop.clear()
        self._callback_ref = self._make_callback()
        self._tap_thread = threading.Thread(target=self._tap_main, name="kvm-tap", daemon=True)
        self._tap_thread.start()
        with self._queue_cv:
            self._input_queue.clear()
        self._tap_worker = threading.Thread(target=self._tap_worker_main, name="kvm-tap-worker", daemon=True)
        self._tap_worker.start()

    def stop(self) -> None:
        # Never leave the user's pointing device decoupled if sharing stops
        # while this Mac is being controlled remotely.
        if _QUARTZ_OK:
            self._record_assoc(True, "stop")
        self._stop.set()
        with self._lock:
            rl = self._tap_runloop
        if rl is not None:
            try:
                CFRunLoopStop(rl)
            except Exception:
                pass
        if self._tap_thread is not None:
            self._tap_thread.join(timeout=2)
        self._release_all_locally()
        # Drain whatever the tap enqueued before it stopped, then stop.
        self._drain_queue()
        worker = self._tap_worker
        if worker is not None:
            worker.join(timeout=2)
        with self._lock:
            self._tap_port = None
            self._tap_runloop = None
            self._tap_worker = None

    def permission_ok(self) -> bool:
        if not _QUARTZ_OK:
            return False
        try:
            listen = bool(Quartz.CGPreflightListenEventAccess())
            post = bool(Quartz.CGPreflightPostEventAccess())
        except AttributeError:  # pragma: no cover - very old macOS
            return True
        return listen and post

    def request_permission(self) -> bool:
        """Ask macOS for the required permissions when sharing is enabled."""
        if not _QUARTZ_OK:
            return False
        try:
            request_listen = getattr(Quartz, "CGRequestListenEventAccess", None)
            request_post = getattr(Quartz, "CGRequestPostEventAccess", None)
            if request_listen is not None:
                request_listen()
            if request_post is not None:
                request_post()
        except Exception:
            pass
        return self.permission_ok()

    def permission_detail(self) -> str:
        if not _QUARTZ_OK:
            return "Quartz unavailable (not macOS or pyobjc missing)"
        missing = []
        try:
            if not bool(Quartz.CGPreflightListenEventAccess()):
                missing.append("Input Monitoring")
        except AttributeError:
            pass
        try:
            if not bool(Quartz.CGPreflightPostEventAccess()):
                missing.append("Accessibility")
        except AttributeError:
            pass
        if not missing:
            return "all permissions granted"
        return "missing macOS permission: " + " and ".join(missing)

    # -- tap ------------------------------------------------------------------

    def _make_callback(self):
        def cb(proxy, etype, event, refcon):
            if event is None:
                return None
            if etype in (Quartz.kCGEventTapDisabledByTimeout, Quartz.kCGEventTapDisabledByUserInput):
                which = "timeout" if etype == Quartz.kCGEventTapDisabledByTimeout else "user"
                self._on_tap_disabled(which)
                return None
            return self._handle_tap(etype, event)

        return cb

    def _on_tap_disabled(self, which: str) -> None:
        """macOS disabled our tap (missed deadline or system/user input).

        Recovery must not leave the peer believing it owns this Mac: the
        input is no longer being captured, so ownership is invalidated,
        everything pressed/injected is released, the mouse is re-associated
        and the cursor shown - and only then is the tap re-enabled. The
        two disable causes are logged separately; "user" input may be a
        system-level condition that will disable the tap again.
        """
        self._bump("tap_disables")
        self._bump("tap_disables_timeout" if which == "timeout" else "tap_disables_user")
        with self._lock:
            mode = self._mode
        if mode != "local":
            self._release_all_locally()
            self._record_assoc(True, f"tap-disable-{which}")
            self.show_cursor()
            with self._lock:
                self._mode = "local"
            engine = self.engine
            if engine is not None:
                try:
                    engine.on_platform_input_lost()
                except Exception:
                    pass
        with self._lock:
            port = self._tap_port
        if port is not None:
            try:
                Quartz.CGEventTapEnable(port, True)
            except Exception:
                pass

    def _tap_main(self) -> None:
        q = _q()
        tap = q.CGEventTapCreate(
            q.kCGHIDEventTap,
            q.kCGHeadInsertEventTap,
            q.kCGEventTapOptionDefault,
            q.kCGEventMaskForAllEvents,
            self._callback_ref,
            None,
        )
        if tap is None:  # pragma: no cover - permission revoked mid-run
            self._stop.set()
            self.engine.on_status("KVM: Accessibility permission missing - tap failed")
            return
        with self._lock:
            self._tap_port = tap
            self._tap_runloop = CFRunLoopGetCurrent()
        source = CFMachPortCreateRunLoopSource(None, tap, 0)
        CFRunLoopAddSource(self._tap_runloop, source, kCFRunLoopCommonModes)
        q.CGEventTapEnable(tap, True)
        CFRunLoopRun()
        CFRunLoopRemoveSource(self._tap_runloop, source, kCFRunLoopCommonModes)
        CFMachPortInvalidate(tap)

    def _handle_tap(self, etype, event):
        """Quartz callback: fast path only.

        Reads cheap fields, captures the mode, retains the event, appends
        a compact record to the bounded queue and returns. Nothing here
        may block, raise, or call the engine: macOS disables taps whose
        callbacks miss their deadline.
        """
        q = _q()
        now = time.monotonic()
        with self._lock:
            self._last_any = now
            if etype in (q.kCGEventKeyDown, q.kCGEventKeyUp, q.kCGEventFlagsChanged):
                self._last_key = now
            mode = self._mode
        retain = getattr(q, "CGEventRetain", None)
        if retain is not None:
            try:
                retain(event)
            except Exception:
                pass
        if not self._enqueue((mode, etype, event)):
            self._handle_queue_overflow((mode, etype, event))
        # Swallow everything unless the local user should see it: local
        # mode passes through, remote mode passes keys through (the user
        # keeps the keyboard and the emergency chord), controlling mode
        # never leaks the physical event to apps.
        return event if mode in ("local", "remote") else None

    def _enqueue(self, record) -> bool:
        with self._queue_cv:
            if len(self._input_queue) < _TAP_QUEUE_MAX:
                self._input_queue.append(record)
                self._queue_cv.notify()
                return True
        return False

    def _is_motion(self, etype) -> bool:
        q = _q()
        return etype in (
            q.kCGEventMouseMoved,
            q.kCGEventLeftMouseDragged,
            q.kCGEventRightMouseDragged,
            q.kCGEventOtherMouseDragged,
        )

    def _release_event(self, event) -> None:
        q = _q()
        release = getattr(q, "CGEventRelease", None)
        if release is not None:
            try:
                release(event)
            except Exception:
                pass

    def _handle_queue_overflow(self, record) -> None:
        """Bounded-queue overflow: never drop key/button transitions, and
        never drop motion - overflowed motion folds into the last queued
        motion record, so no movement is lost (relative deltas sum
        exactly; the drained event moves the cursor by the combined
        distance). A full queue with no motion at all drops new motion
        outright; when the new record is a key/button (critical), the
        oldest motion record is evicted to make room. Only if the queue
        holds nothing but critical records is the oldest one dropped
        (extreme overload; the tap is failing anyway).
        """
        mode, etype, event = record
        if self._is_motion(etype):
            self._merge_motion(record)
            return
        with self._queue_cv:
            for i, (m, et, ev) in enumerate(self._input_queue):
                if self._is_motion(et):
                    del self._input_queue[i]
                    self._bump("queue_dropped_motion")
                    self._input_queue.append(record)
                    self._queue_cv.notify()
                    self._release_event(ev)
                    return
            if self._input_queue:
                evicted = self._input_queue.popleft()
                self._input_queue.append(record)
                self._queue_cv.notify()
                self._bump("queue_dropped_critical")
                self._release_event(evicted)
            else:
                self._input_queue.append(record)
                self._queue_cv.notify()

    def _merge_motion(self, record) -> None:
        """Fold an overflowed motion event into the last queued motion
        event (rewriting its delta/location fields in place) so the
        worker processes one record carrying the combined movement."""
        q = _q()
        mode, etype, event = record
        dx = q.CGEventGetIntegerValueField(event, q.kCGMouseEventDeltaX)
        dy = q.CGEventGetIntegerValueField(event, q.kCGMouseEventDeltaY)
        with self._queue_cv:
            for i in range(len(self._input_queue) - 1, -1, -1):
                m, et, ev = self._input_queue[i]
                if self._is_motion(et):
                    odx = q.CGEventGetIntegerValueField(ev, q.kCGMouseEventDeltaX)
                    ody = q.CGEventGetIntegerValueField(ev, q.kCGMouseEventDeltaY)
                    q.CGEventSetIntegerValueField(ev, q.kCGMouseEventDeltaX, odx + dx)
                    q.CGEventSetIntegerValueField(ev, q.kCGMouseEventDeltaY, ody + dy)
                    old = q.CGEventGetLocation(ev)
                    q.CGEventSetLocation(ev, (old.x + dx, old.y + dy))
                    self._bump("queue_merged_motion")
                    self._release_event(event)
                    return
        # No queued motion to merge into: drop (extreme overload).
        self._bump("queue_dropped_motion")
        self._release_event(event)

    def _drain_queue(self) -> None:
        with self._queue_cv:
            items = list(self._input_queue)
            self._input_queue.clear()
        for item in items:
            try:
                self._process_record(*item)
            except Exception:
                pass

    def _tap_worker_main(self) -> None:
        while not self._stop.is_set():
            with self._queue_cv:
                if self._input_queue:
                    item = self._input_queue.popleft()
                else:
                    item = None
            if item is None:
                self._queue_cv.wait(timeout=0.2)
                continue
            try:
                self._process_record(*item)
            except Exception as exc:
                self._bump("worker_exceptions")
                self._note_exception(exc)

    def _process_record(self, mode, etype, event) -> None:
        try:
            if mode == "controlling":
                self._enqueue_controlled_input(event, etype)
            elif mode == "remote":
                self._observe_remote(event, etype)
            else:
                self._observe_local(event, etype)
        finally:
            self._release_event(event)

    def _observe_local(self, event, etype) -> None:
        """Local mode: watch-only (seam detection, chord arming). Never
        transmits ordinary input to the peer."""
        self._forward(event, etype, mode="local")

    def _enqueue_controlled_input(self, event, etype) -> None:
        """Controlling mode: this machine's input drives the peer."""
        self._forward(event, etype, mode="controlling")

    def _observe_remote(self, event, etype) -> None:
        """Remote mode: the peer owns the pointer, so mouse/buttons/wheel
        are ignored; keys are observed so the emergency chord still works.
        No input here ever releases or hands back control."""
        q = _q()
        engine = self.engine
        if engine is None:
            return
        user = q.CGEventGetIntegerValueField(event, q.kCGEventSourceUserData)
        if user == SENTINEL:
            return
        if etype in (q.kCGEventKeyDown, q.kCGEventKeyUp, q.kCGEventFlagsChanged):
            self._forward_keys(event, etype)

    def _forward_keys(self, event, etype) -> None:
        q = _q()
        engine = self.engine
        if engine is None:
            return
        user = q.CGEventGetIntegerValueField(event, q.kCGEventSourceUserData)
        # Sentinel-only filtering: injected events are recognized solely
        # by the source-user-data sentinel. The old pid check was dropped
        # (sandboxed/reblessed processes do not reliably report the pid).
        if user == SENTINEL:
            return
        try:
            if etype == q.kCGEventKeyDown:
                self._bump("tap_keys")
                vk = q.CGEventGetIntegerValueField(event, q.kCGKeyboardEventKeycode)
                hid = _mac_vk_to_hid(vk)
                if hid is not None:
                    self._bump("hid_mapped")
                    with self._lock:
                        self._pressed_keys.add(hid)
                    engine.observe_local_key(hid, True)
                else:
                    self._bump("hid_unmapped")
            elif etype == q.kCGEventKeyUp:
                self._bump("tap_keys")
                if q.CGEventGetIntegerValueField(event, q.kCGKeyboardEventAutorepeat):
                    return
                vk = q.CGEventGetIntegerValueField(event, q.kCGKeyboardEventKeycode)
                hid = _mac_vk_to_hid(vk)
                if hid is not None:
                    self._bump("hid_mapped")
                    with self._lock:
                        self._pressed_keys.discard(hid)
                    engine.observe_local_key(hid, False)
                else:
                    self._bump("hid_unmapped")
            elif etype == q.kCGEventFlagsChanged:
                self._forward_flags(event)
        except Exception as exc:
            self._note_exception(exc)

    def _forward(self, event, etype, mode=None) -> None:
        """Translate one tapped event for the engine.

        ``mode`` is the delegation captured when the event was enqueued
        (the callback must not re-read state), defaulting to the current
        mode for direct test/injection callers. Observation and control
        are explicit and never share a call path: watch-only modes call
        the engine's observe_* methods, controlling mode additionally
        calls send_controlled_*.
        """
        q = _q()
        engine = self.engine
        if engine is None:
            return
        if mode is None:
            with self._lock:
                mode = self._mode
        user = q.CGEventGetIntegerValueField(event, q.kCGEventSourceUserData)
        # Sentinel-only filtering (see module docstring).
        if user == SENTINEL:
            return
        try:
            if etype == q.kCGEventKeyDown:
                self._bump("tap_keys")
                vk = q.CGEventGetIntegerValueField(event, q.kCGKeyboardEventKeycode)
                hid = _mac_vk_to_hid(vk)
                if hid is not None:
                    self._bump("hid_mapped")
                    with self._lock:
                        self._pressed_keys.add(hid)
                    engine.observe_local_key(hid, True)
                    if mode == "controlling":
                        engine.send_controlled_key(hid, True)
                else:
                    self._bump("hid_unmapped")
            elif etype == q.kCGEventKeyUp:
                self._bump("tap_keys")
                if q.CGEventGetIntegerValueField(event, q.kCGKeyboardEventAutorepeat):
                    return
                vk = q.CGEventGetIntegerValueField(event, q.kCGKeyboardEventKeycode)
                hid = _mac_vk_to_hid(vk)
                if hid is not None:
                    self._bump("hid_mapped")
                    with self._lock:
                        self._pressed_keys.discard(hid)
                    engine.observe_local_key(hid, False)
                    if mode == "controlling":
                        engine.send_controlled_key(hid, False)
                else:
                    self._bump("hid_unmapped")
            elif etype == q.kCGEventFlagsChanged:
                self._forward_flags(event)
                if mode == "controlling":
                    vk = q.CGEventGetIntegerValueField(event, q.kCGKeyboardEventKeycode)
                    hid = _mac_vk_to_hid(vk)
                    if hid is not None:
                        bit = _VK_FLAG_BITS.get(int(vk))
                        if bit is not None:
                            engine.send_controlled_key(hid, bool(q.CGEventGetFlags(event) & bit))
            elif etype in (
                q.kCGEventMouseMoved,
                q.kCGEventLeftMouseDragged,
                q.kCGEventRightMouseDragged,
                q.kCGEventOtherMouseDragged,
            ):
                if mode == "controlling":
                    # The first motion event after disassociation can
                    # carry a large stale pre-entry delta; discard it.
                    with self._lock:
                        if self._ignore_next_motion:
                            self._ignore_next_motion = False
                            return
                dx = q.CGEventGetIntegerValueField(event, q.kCGMouseEventDeltaX)
                dy = q.CGEventGetIntegerValueField(event, q.kCGMouseEventDeltaY)
                pos = q.CGEventGetLocation(event)
                engine.observe_local_mouse(dx, dy, int(pos.x), int(pos.y))
                if mode == "controlling":
                    engine.send_controlled_mouse(dx, dy)
            elif etype in (
                q.kCGEventLeftMouseDown,
                q.kCGEventLeftMouseUp,
                q.kCGEventRightMouseDown,
                q.kCGEventRightMouseUp,
                q.kCGEventOtherMouseDown,
                q.kCGEventOtherMouseUp,
            ):
                button = _event_button(q, etype, event)
                down = etype in (
                    q.kCGEventLeftMouseDown,
                    q.kCGEventRightMouseDown,
                    q.kCGEventOtherMouseDown,
                )
                if mode == "controlling":
                    engine.send_controlled_button(button, down)
                else:
                    engine.observe_local_button(button, down)
            elif etype == q.kCGEventScrollWheel:
                dy = q.CGEventGetIntegerValueField(event, q.kCGScrollWheelEventDeltaAxis1)
                dx = q.CGEventGetIntegerValueField(event, q.kCGScrollWheelEventDeltaAxis2)
                if mode == "controlling":
                    engine.send_controlled_wheel(int(round(dy * 120)), int(round(dx * 120)))
                else:
                    engine.observe_local_wheel(int(round(dy * 120)), int(round(dx * 120)))
        except Exception as exc:
            self._note_exception(exc)

    def _note_exception(self, exc: Exception) -> None:
        """F6: counters + a single surfaced toast for the first failure."""
        self._bump("exceptions")
        with self._lock:
            first = self._first_exception is None
            if first:
                self._first_exception = f"{type(exc).__name__}: {exc}"
        engine = self.engine
        if engine is not None and first:
            try:
                engine.on_status(
                    f"KVM: input capture hit an error ({self._first_exception}) - "
                    "see diagnostics for details",
                    level="error",
                )
            except Exception:
                pass

    def _forward_flags(self, event) -> None:
        """FlagsChanged carries the keycode of the modifier that changed,
        so left/right variants (incl. AltGr) are identified exactly."""
        q = _q()
        self._bump("tap_keys")
        vk = q.CGEventGetIntegerValueField(event, q.kCGKeyboardEventKeycode)
        hid = _mac_vk_to_hid(vk)
        if hid is None:
            self._bump("hid_unmapped")
            return
        bit = _VK_FLAG_BITS.get(int(vk))
        if bit is None:
            self._bump("hid_unmapped")
            return
        self._bump("hid_mapped")
        self.engine.observe_local_key(hid, bool(q.CGEventGetFlags(event) & bit))

    # -- delegation ------------------------------------------------------------

    def _record_assoc(self, associate: bool, state: str) -> bool:
        """Call CGAssociateMouseAndMouseCursorPosition and record the outcome.

        Quartz returns no useful value, so success is only "did not raise".
        Every attempt is timestamped with a monotonic sequence number and the
        requesting state for the F6 diagnostics / handoff audit.
        """
        try:
            _q().CGAssociateMouseAndMouseCursorPosition(associate)
            ok = True
        except Exception:
            ok = False
        self._assoc_seq += 1
        rec = {
            "t": time.monotonic(),
            "seq": self._assoc_seq,
            "associate": bool(associate),
            "state": state,
            "ok": ok,
        }
        with self._lock:
            self._assoc_calls.append(rec)
        if ok:
            self._bump("assoc_true" if associate else "assoc_false")
        else:
            self._bump("assoc_errors")
        return ok

    def set_delegation(self, state: str) -> bool:
        """Apply the delegation, returning success.

        ``_mode`` flips only after the Quartz call succeeds: a failed
        CGAssociate... call must never leave the platform believing it is
        decoupled when it is not (F2) - that is the stuck-cursor symptom.

        Entering "controlling" is ordered (review F3): hide the cursor,
        park it, disassociate the hardware mouse, then mark the first
        post-entry motion event as discardable, and only then flip mode.
        Entering "remote" resets the software-cursor position so the next
        relative move is re-derived from the real cursor (handoff entry).
        """
        if state == "controlling":
            # 1. Hide and park the cursor so disassociated hardware deltas
            #    have nowhere to land. Re-applying while already controlling
            #    must not hide again (ShowCursor/HideCursor are refcounted).
            q = _q()
            with self._lock:
                already = self._mode == "controlling"
            if not already:
                try:
                    q.CGDisplayHideCursor(q.CGMainDisplayID())
                    with self._lock:
                        self._cursor_hidden = True
                except Exception:
                    pass
                try:
                    self.warp_cursor(*self._park_position())
                except Exception:
                    pass
            # 2. Decouple hardware mouse deltas from the cursor.
            if not self._record_assoc(False, state):
                # Failure must not leave the cursor hidden behind a lie.
                with self._lock:
                    hidden = self._cursor_hidden
                if hidden:
                    try:
                        self.show_cursor()
                    except Exception:
                        pass
                return False
            with self._lock:
                self._ignore_next_motion = True
                self._mode = state
            return True
        if state == "remote":
            # Decouples hardware mouse deltas from the on-screen cursor so
            # injected absolute moves aren't fought by the local trackpad's
            # own accumulator.
            if not self._record_assoc(False, state):
                return False
            with self._lock:
                self._mode = state
                self._soft_valid = False
            return True
        if state == "local":
            if not self._record_assoc(True, state):
                return False
            with self._lock:
                self._mode = state
            with self._lock:
                hidden = self._cursor_hidden
            if hidden:
                self.show_cursor()
                with self._lock:
                    self._cursor_hidden = False
            return True
        return False

    def _park_position(self) -> tuple[int, int]:
        """Center of the layout to park the cursor on controlling entry."""
        try:
            layout = self.screen_layout()
            return layout.left() + layout.width() // 2, layout.top() + layout.height() // 2
        except Exception:
            return self.cursor_position()

    def keyboard_health(self) -> str:
        """F7: "ok", "idle", "no_keys" or "stalled".

        Stalled = mouse events are still flowing through the tap but no
        key events have been seen for a while during a sharing session -
        the classic macOS Secure Input signature. No_keys = mouse events
        flow but zero key events have ever arrived (the user may simply
        not be typing; the engine applies a grace period). Idle = nothing
        at all (normal quiet Mac, no session activity).
        """
        if not _QUARTZ_OK:
            return "idle"
        with self._lock:
            last_any = self._last_any
            last_key = self._last_key
        now = time.monotonic()
        if not last_any or now - last_any > 5.0:
            return "idle"
        if last_key and now - last_key <= 2.0:
            return "ok"
        if not last_key:
            return "no_keys"
        return "stalled"

    def note_keyboard_stall(self) -> None:
        """First-stage recovery: restart the HID tap from scratch.

        Called once per stall episode by the engine watchdog. The event
        tap and its CFRunLoop live on their own thread, so restarting is
        just: stop the runloop, wait for the thread, spin up a new one.
        """
        with self._lock:
            rl = self._tap_runloop
            thread = self._tap_thread
        if rl is not None:
            try:
                CFRunLoopStop(rl)
            except Exception:
                pass
        if thread is not None and thread.is_alive():
            thread.join(timeout=2)
        self._bump("tap_restarts")
        with self._lock:
            self._tap_port = None
            self._tap_runloop = None
        with self._queue_cv:
            # Records captured by the dead tap are stale.
            while self._input_queue:
                self._release_event(self._input_queue.popleft()[2])
        if self._stop.is_set() or self.engine is None:
            return
        try:
            self._callback_ref = self._make_callback()
            self._tap_thread = threading.Thread(target=self._tap_main, name="kvm-tap", daemon=True)
            self._tap_thread.start()
        except Exception:
            pass

    # -- geometry ---------------------------------------------------------------

    def screen_layout(self) -> ScreenLayout:
        if NSScreen is None:
            raise MacPlatformError("AppKit unavailable")
        monitors = []
        for screen in NSScreen.screens():
            f = screen.frame()
            monitors.append(
                Monitor(
                    int(f.origin.x),
                    int(f.origin.y),
                    int(f.size.width),
                    int(f.size.height),
                    float(screen.backingScaleFactor()),
                )
            )
        return ScreenLayout(monitors, primary=0)

    def cursor_position(self) -> tuple[int, int]:
        q = _q()
        ev = q.CGEventCreate(None)
        loc = q.CGEventGetLocation(ev)
        return int(loc.x), int(loc.y)

    def warp_cursor(self, x: int, y: int) -> None:
        q = _q()
        q.CGWarpMouseCursorPosition((x, y))

    def hide_cursor(self) -> None:
        q = _q()
        q.CGDisplayHideCursor(q.CGMainDisplayID())
        with self._lock:
            self._cursor_hidden = True

    def show_cursor(self) -> None:
        q = _q()
        q.CGDisplayShowCursor(q.CGMainDisplayID())
        with self._lock:
            self._cursor_hidden = False

    # -- injection ---------------------------------------------------------------

    def inject_move_rel(self, dx: int, dy: int) -> None:
        """Relative remote motion via an application-maintained software
        cursor, clamped to the layout - never per-event warping (repeated
        warping interferes with tap deltas and event suppression). The
        real cursor is warped only for placement at handoff entry/return.
        """
        q = _q()
        with self._lock:
            if not self._soft_valid:
                # Handoff entry: derive the software position from the
                # real cursor exactly once.
                try:
                    sx, sy = self.cursor_position()
                except Exception:
                    sx, sy = 0, 0
                self._soft_x, self._soft_y = sx, sy
                self._soft_valid = True
            nx = self._soft_x + dx
            ny = self._soft_y + dy
            self._soft_x, self._soft_y = nx, ny
        try:
            layout = self.screen_layout()
            nx = min(max(nx, layout.left()), layout.right() - 1)
            ny = min(max(ny, layout.top()), layout.bottom() - 1)
            self._soft_x, self._soft_y = nx, ny
        except Exception:
            pass
        ev = q.CGEventCreateMouseEvent(None, q.kCGEventMouseMoved, (self._soft_x, self._soft_y), q.kCGMouseButtonLeft)
        q.CGEventSetIntegerValueField(ev, q.kCGEventSourceUserData, SENTINEL)
        # Session-tap posting is below our HID capture tap, so the injected
        # event reaches the target app without being mistaken for local
        # input; the sentinel is the safety net either way.
        q.CGEventPost(q.kCGSessionEventTap, ev)
        self._report_edge(self._soft_x, self._soft_y)

    def inject_move_abs(self, x: int, y: int) -> None:
        q = _q()
        with self._lock:
            self._soft_x, self._soft_y = x, y
            self._soft_valid = True
        ev = q.CGEventCreateMouseEvent(None, q.kCGEventMouseMoved, (x, y), q.kCGMouseButtonLeft)
        q.CGEventSetIntegerValueField(ev, q.kCGEventSourceUserData, SENTINEL)
        q.CGEventPost(q.kCGSessionEventTap, ev)
        self._report_edge(x, y)

    def _report_edge(self, x: int, y: int) -> None:
        """Seam detection at injection time: the controller drives our
        cursor with warps, so check the landing point for the return edge
        instead of polling."""
        if self._mode != "remote" or self.engine is None:
            return
        try:
            side = in_jump_zone(self.screen_layout(), x, y)
            if side is not None:
                self.engine.on_remote_edge(side, x, y)
        except Exception:
            pass

    def inject_button(self, button: int, down: bool) -> None:
        q = _q()
        if button == 0:
            etype = q.kCGEventLeftMouseDown if down else q.kCGEventLeftMouseUp
            field = 0
        elif button == 1:
            etype = q.kCGEventRightMouseDown if down else q.kCGEventRightMouseUp
            field = 1
        else:
            etype = q.kCGEventOtherMouseDown if down else q.kCGEventOtherMouseUp
            field = button
        pos = self.cursor_position()
        ev = q.CGEventCreateMouseEvent(None, etype, pos, field)
        q.CGEventSetIntegerValueField(ev, q.kCGEventSourceUserData, SENTINEL)
        q.CGEventPost(q.kCGSessionEventTap, ev)
        with self._lock:
            if down:
                self._injected_buttons.add(button)
            else:
                self._injected_buttons.discard(button)

    def inject_wheel(self, dy: int, dx: int) -> None:
        q = _q()
        ev = q.CGEventCreateScrollWheelEvent(None, q.kCGScrollEventUnitLine, 2, dy / 120.0, dx / 120.0)
        q.CGEventSetIntegerValueField(ev, q.kCGEventSourceUserData, SENTINEL)
        q.CGEventPost(q.kCGSessionEventTap, ev)

    def inject_key(self, hid: int, down: bool) -> None:
        q = _q()
        from .kvm_keymap import hid_to_mac_vk

        vk = hid_to_mac_vk(hid)
        if vk is None:
            return
        ev = q.CGEventCreateKeyboardEvent(None, vk, down)
        q.CGEventSetIntegerValueField(ev, q.kCGEventSourceUserData, SENTINEL)
        q.CGEventPost(q.kCGSessionEventTap, ev)
        with self._lock:
            if down:
                self._injected_keys.add(hid)
            else:
                self._injected_keys.discard(hid)

    def _release_all_locally(self) -> None:
        """Release everything this machine is holding: physical keys
        observed at the tap and keys/buttons this process injected.

        Called when the tap dies, on ownership changes, and on shutdown
        so no key/button can be left stuck on this Mac.
        """
        with self._lock:
            keys = sorted(self._pressed_keys)
            self._pressed_keys.clear()
            injected = sorted(self._injected_keys)
            self._injected_keys.clear()
            buttons = sorted(self._injected_buttons)
            self._injected_buttons.clear()
        for hid in keys:
            try:
                self.inject_key(hid, False)
            except Exception:
                pass
        for hid in injected:
            try:
                self.inject_key(hid, False)
            except Exception:
                pass
        for button in buttons:
            try:
                self.inject_button(button, False)
            except Exception:
                pass


# -- module helpers --------------------------------------------------------------

def _event_button(q, etype, event) -> int:
    if etype in (q.kCGEventLeftMouseDown, q.kCGEventLeftMouseUp):
        return 0
    if etype in (q.kCGEventRightMouseDown, q.kCGEventRightMouseUp):
        return 1
    return int(q.CGEventGetIntegerValueField(event, q.kCGMouseEventButtonNumber))


def _mac_vk_to_hid(vk: int):
    from .kvm_keymap import mac_vk_to_hid

    return mac_vk_to_hid(vk)


# macOS virtual keycode -> CGEvent flag bit (only for modifier keys).
_VK_FLAG_BITS = {
    0x38: 0x00020000,  # Left Shift    kCGEventFlagMaskShift
    0x3C: 0x00020000,  # Right Shift
    0x3B: 0x00040000,  # Left Control  kCGEventFlagMaskControl
    0x3E: 0x00040000,  # Right Control
    0x3A: 0x00080000,  # Left Option   kCGEventFlagMaskAlternate
    0x3D: 0x00080000,  # Right Option
    0x37: 0x00100000,  # Left Command  kCGEventFlagMaskCommand
    0x36: 0x00100000,  # Right Command
}


# -- spike CLI ---------------------------------------------------------------------

def main():
    """Standalone verification of capture/inject/filter/cursor on this Mac.

        python -m core.kvm_platform_mac --spike

    Prints permission state and the local layout, then for N seconds
    prints captured mouse deltas, buttons, wheel and keys. Two seconds in
    it injects a relative move, an absolute move and an "a" keystroke;
    the injected events must NOT appear in the capture output
    (self-filter). Finally it hides/shows the cursor and warps it to
    (600, 400).
    """
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--spike", action="store_true")
    parser.add_argument("--controller", action="store_true",
                        help="simulate controller mode: park the cursor, call "
                             "CGAssociate(False), print per-second diagnostics "
                             "while you physically move the mouse")
    parser.add_argument("--seconds", type=int, default=6)
    args = parser.parse_args()

    class _Engine:
        def on_status(self, msg):
            print(f"[status] {msg}", flush=True)

        def observe_local_mouse(self, dx, dy, x, y):
            print(f"  mouse rel=({dx},{dy}) abs=({x},{y})", flush=True)

        def observe_local_button(self, button, down):
            print(f"  button {button} {'down' if down else 'up'}", flush=True)

        def observe_local_wheel(self, dy, dx):
            print(f"  wheel dy={dy} dx={dx}", flush=True)

        def observe_local_key(self, hid, down):
            print(f"  key hid=0x{hid:02x} {'down' if down else 'up'}", flush=True)

        def send_controlled_mouse(self, dx, dy):
            print(f"  -> send mouse rel=({dx},{dy})", flush=True)

        def send_controlled_button(self, button, down):
            print(f"  -> send button {button} {'down' if down else 'up'}", flush=True)

        def send_controlled_wheel(self, dy, dx):
            print(f"  -> send wheel dy={dy} dx={dx}", flush=True)

        def send_controlled_key(self, hid, down):
            print(f"  -> send key hid=0x{hid:02x} {'down' if down else 'up'}", flush=True)

        def on_remote_edge(self, side, x, y):
            print(f"  edge {side} at ({x},{y})", flush=True)

    platform = MacInputPlatform()
    print(f"listen permission: {platform.permission_ok()}", flush=True)
    layout = platform.screen_layout()
    print(f"layout: {layout.to_monitors()}", flush=True)
    if args.controller:
        _controller_spike(args)
        return
    platform.start(_Engine())

    def print_diag():
        """Per-second diagnostics deltas: the Secure Input check is
        "type in a normal field, then a password field: tap_keys and
        hid_mapped must keep rising for the normal field and go quiet
        (while mouse still flows) for the secure one."""
        prev = None
        while True:
            time.sleep(1.0)
            try:
                d = platform.diagnostics()
            except Exception:
                continue
            keys = ("tap_keys", "hid_mapped", "hid_unmapped", "exceptions", "tap_disables", "tap_restarts")
            if prev is None:
                prev = d
                fe = f" first_exception={d.get('first_exception')!r}" if d.get("first_exception") else ""
                print(f"[diag] mode={d['mode']} " + " ".join(f"{k}={d.get(k, 0)}" for k in keys) + fe, flush=True)
                continue
            deltas = " ".join(f"{k}=+{d.get(k, 0) - prev.get(k, 0)}" for k in keys)
            line = f"[diag] mode={d['mode']} {deltas}"
            if d.get("exceptions", 0) > prev.get("exceptions", 0):
                line += f" first_exception={d.get('first_exception')!r}"
            print(line, flush=True)
            prev = d

    def inject():
        time.sleep(2)
        print("  [spike] injecting rel move, abs move, 'a' key", flush=True)
        platform.inject_move_rel(120, -60)
        platform.inject_move_abs(600, 400)
        platform.inject_key(0x04, True)
        platform.inject_key(0x04, False)
        time.sleep(1.5)
        print("  [spike] hiding cursor...", flush=True)
        platform.hide_cursor()
        time.sleep(1.0)
        print("  [spike] showing cursor + warp to (600,400)", flush=True)
        platform.show_cursor()
        platform.warp_cursor(600, 400)

    threading.Thread(target=inject, daemon=True).start()
    threading.Thread(target=print_diag, daemon=True).start()
    time.sleep(args.seconds)
    platform.stop()
    print("spike done", flush=True)


def _controller_spike(args) -> None:
    """Manual diagnostic for the "Mac controller cursor moves while
    controlling Windows" symptom:

        python -m core.kvm_platform_mac --controller 10

    Parks the cursor at the screen center, applies the "controlling"
    delegation (CGAssociateMouseAndMouseCursorPosition(False)) and prints
    per-second state while the operator physically moves the mouse.

    Expected on a healthy Mac: the cursor stays parked (physical movement
    is swallowed at the tap and only forwarded as rel deltas), mode stays
    "controlling", assoc_false == 1 and assoc_true == 0 until the exit
    restore.  Any re-association during the run shows up in assoc_calls.

    The diagnostics only prove Quartz did not raise; a cursor that still
    moves despite a clean record points at macOS/device/external software
    rather than this code path.
    """
    class _Engine:
        def on_status(self, msg):
            print(f"[status] {msg}", flush=True)

        def observe_local_mouse(self, dx, dy, x, y):
            print(f"  mouse rel=({dx},{dy}) abs=({x},{y})", flush=True)

        def observe_local_button(self, button, down):
            pass

        def observe_local_wheel(self, dy, dx):
            pass

        def observe_local_key(self, hid, down):
            pass

        def send_controlled_mouse(self, dx, dy):
            print(f"  -> send mouse rel=({dx},{dy})", flush=True)

        def send_controlled_button(self, button, down):
            pass

        def send_controlled_wheel(self, dy, dx):
            pass

        def send_controlled_key(self, hid, down):
            pass

        def on_remote_edge(self, side, x, y):
            pass

    platform = MacInputPlatform()
    layout = platform.screen_layout()
    cx, cy = layout.left() + layout.width() // 2, layout.top() + layout.height() // 2
    print(f"controller spike: park at ({cx},{cy}), delegation -> controlling", flush=True)
    platform.start(_Engine())
    platform.warp_cursor(cx, cy)
    platform.hide_cursor()
    ok = platform.set_delegation("controlling")
    print(f"set_delegation('controlling') -> {ok}", flush=True)

    prev = None
    start = time.monotonic()
    while time.monotonic() - start < args.seconds:
        time.sleep(1.0)
        try:
            d = platform.diagnostics()
        except Exception:
            continue
        pos = platform.cursor_position()
        keys = ("assoc_false", "assoc_true", "assoc_errors", "tap_keys")
        line = f"[diag] mode={d['mode']} cursor={pos} " + " ".join(f"{k}={d.get(k, 0)}" for k in keys)
        if prev is not None and d.get("assoc_calls"):
            new_calls = [c for c in d["assoc_calls"] if c["seq"] > prev.get("seq", 0)]
            if new_calls:
                line += f" NEW_ASSOC={new_calls}"
        print(line, flush=True)
        prev = {**d, "seq": d["assoc_calls"][-1]["seq"] if d["assoc_calls"] else 0}

    print("restoring local delegation...", flush=True)
    platform.set_delegation("local")
    platform.show_cursor()
    platform.stop()
    d = platform.diagnostics()
    print(f"final: mode={d['mode']} assoc_false={d['assoc_false']} "
          f"assoc_true={d['assoc_true']} assoc_errors={d['assoc_errors']} "
          f"calls={d['assoc_calls']}", flush=True)
    print("controller spike done", flush=True)


if __name__ == "__main__":
    main()
