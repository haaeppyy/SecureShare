"""Tray menu construction tests (regression for the 3-arg lambda bug).

pystray rejects action callables with more than two parameters; once a
peer was discovered, _build_menu raised ValueError and the menu froze at
its startup state. These tests pin _build_menu to never raise and to
reflect current state (peers, sync toggle).
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pystray  # noqa: E402

from tray.app import TrayApp  # noqa: E402

import pytest


class Peer:
    def __init__(self, name, fp, host="192.168.0.6", port=48620, service=None):
        self.name = name
        self.fingerprint = fp
        self.host = host
        self.port = port
        self.service = service or f"{name}-{fp[:8]}._secureshare._tcp.local."


class StubStore:
    def __init__(self):
        self.identity = {"name": "Tester"}
        self.sync_enabled = False
        self.peers = {
            "fp-paired": {
                "fingerprint": "fp-paired",
                "name": "PairedBox",
                "paired_date": "2026-08-10",
                "kvm_allowed": False,
                "kvm_side": "right",
            }
        }

    def is_paired(self, fp):
        return fp in self.peers

    def list_peers(self):
        return list(self.peers.values())

    def get_peer(self, fp):
        return self.peers.get(fp)

    def set_sync_enabled(self, value):
        self.sync_enabled = value

    def set_peer_kvm_allowed(self, fp, value):
        if fp in self.peers:
            self.peers[fp]["kvm_allowed"] = value

    def set_peer_kvm_side(self, fp, value):
        if fp in self.peers:
            self.peers[fp]["kvm_side"] = value


class StubKVM:
    def __init__(self):
        self.enabled = False
        self._links = {}
        self._controls = {}

    def set_enabled(self, value):
        self.enabled = value

    def link_status(self, fp):
        return self._links.get(fp, "offline")

    def control_state(self, fp):
        return self._controls.get(fp, "local")

    def control_label(self, fp):
        return self.control_state(fp)


class StubDiscovery:
    def __init__(self, peers):
        self._peers = peers

    def peers(self):
        return dict(self._peers)


def make_app(peers):
    app = TrayApp()
    app.node = type(
        "Node",
        (),
        {"store": StubStore(), "discovery": StubDiscovery(peers), "kvm": StubKVM()},
    )()
    # No Tk in tests: record popup openings instead of creating windows.
    app._pair_dialog_opens = []
    app._show_pair_dialog = app._pair_dialog_opens.append
    return app


def items_of(menu):
    return list(menu._items)


def find_text(menu, prefix):
    found = []
    for item in items_of(menu):
        if str(item.text).startswith(prefix):
            found.append(item)
        sub = item.submenu
        if sub is not None:
            found.extend(find_text(sub, prefix))
    return found


def test_build_menu_with_peers_does_not_raise():
    peers = {
        "fp-paired": Peer("PairedBox", "fp-paired"),
        "fp-new": Peer("NewBox", "fp-new"),
    }
    menu = make_app(peers)._build_menu()  # must not raise
    assert find_text(menu, "Pair with device")
    assert find_text(menu, "Send file to")
    assert not find_text(menu, "No devices found")


def test_build_menu_without_peers():
    menu = make_app({})._build_menu()
    assert find_text(menu, "No devices currently online")


def test_sync_item_reflects_store_state():
    app = make_app({})
    menu = app._build_menu()
    off = find_text(menu, "Clipboard sync:")[0]
    assert str(off.text).endswith("OFF")

    app.node.store.set_sync_enabled(True)
    menu = app._build_menu()
    on = find_text(menu, "Clipboard sync:")[0]
    assert str(on.text).endswith("ON")


def test_peer_submenu_items_are_clickable():
    """The per-peer actions must survive pystray's action validation."""
    peers = {
        "fp-paired": Peer("PairedBox", "fp-paired"),
        "fp-new": Peer("NewBox", "fp-new"),
    }
    app = make_app(peers)
    menu = app._build_menu()
    pair_items = find_text(menu, "NewBox")
    send_items = find_text(menu, "PairedBox")
    assert pair_items and send_items

    # All actions constructed without error; the menu is fully built.
    for item in pair_items:
        assert item._action is not None


class StubSession:
    def __init__(self, fp, name, pin="123456", role="responder", state="pending"):
        self.peer_fp = fp
        self.peer_name = name
        self.pin = pin
        self.role = role
        self.state = state
        self.error = None
        self.insession = True
        self.closed = False
        self.actions = []

    def accept(self):
        self.actions.append("accept")
        self.state = "awaiting_confirm"

    def confirm(self, ok):
        self.actions.append(("confirm", ok))

    def deny(self):
        self.actions.append("deny")
        self.state = "denied"

    def close(self):
        self.closed = True


def test_responder_session_shown_inline_in_menu():
    app = make_app({})
    app._handle_session(StubSession("fp-b", "Bob", pin="482915"))
    menu = app._build_menu()
    assert find_text(menu, "Pairing from Bob")
    assert find_text(menu, "PIN: 482915")
    assert find_text(menu, "Accept")
    assert find_text(menu, "No devices currently online")  # pairing section coexists with peers section


def test_initiator_session_shows_confirm():
    app = make_app({})
    app._handle_session(StubSession("fp-b", "Bob", pin="482915", role="initiator", state="awaiting_confirm"))
    menu = app._build_menu()
    assert find_text(menu, "Pairing with Bob")
    assert find_text(menu, "Confirm")
    assert find_text(menu, "Deny")


def test_duplicate_sessions_for_same_peer_collapse():
    app = make_app({})
    first = StubSession("fp-b", "Bob")
    second = StubSession("fp-b", "Bob", pin="000111")
    app._handle_session(first)
    app._handle_session(second)
    assert first.closed, "superseded session must be closed"
    menu = app._build_menu()
    assert len(find_text(menu, "Pairing from Bob")) == 1
    assert find_text(menu, "PIN: 000111")


def test_pending_sessions_pruned_when_done():
    app = make_app({})
    session = StubSession("fp-b", "Bob")
    app._handle_session(session)
    session.state = "done"
    menu = app._build_menu()
    assert not find_text(menu, "Pairing from Bob")


def test_session_action_dispatch():
    app = make_app({})
    session = StubSession("fp-b", "Bob")
    app._session_action(session, "accept")
    assert session.actions == ["accept"]
    app._session_action(session, "deny")
    assert session.actions == ["accept", "deny"]


# -- pairing popups ----------------------------------------------------------


class FakeWindow:
    def __init__(self):
        self.destroyed = False

    def destroy(self):
        self.destroyed = True


def test_handle_session_opens_pair_dialog():
    app = make_app({})
    session = StubSession("fp-b", "Bob", pin="482915")
    app._handle_session(session)
    assert app._pair_dialog_opens == [session], "popup must open for the request"
    assert app._sessions["fp-b"] is session


def test_pair_dialog_action_dispatches_and_closes():
    app = make_app({})
    session = StubSession("fp-b", "Bob")
    win = FakeWindow()
    app._pair_dialogs["fp-b"] = win
    app._pair_dialog_action(session, "accept")
    assert session.actions == ["accept"]
    assert win.destroyed, "dialog must close after the button action"

    app._pair_dialog_action(session, "deny")
    assert session.actions[-1] == "deny"

    confirm = StubSession("fp-c", "Cara", role="initiator", state="awaiting_confirm")
    app._pair_dialog_action(confirm, "confirm")
    assert confirm.actions == [("confirm", True)]


def test_prune_closes_pair_dialog():
    app = make_app({})
    session = StubSession("fp-b", "Bob")
    app._handle_session(session)
    win = FakeWindow()
    app._pair_dialogs["fp-b"] = win
    session.state = "done"
    app._prune_sessions()
    assert "fp-b" not in app._sessions
    assert "fp-b" not in app._pair_dialogs
    assert win.destroyed, "pruned session must close its popup"


def test_pair_dialog_reflects_pin_and_role():
    """The popup wiring (role-specific buttons) survives the stub."""
    app = make_app({})
    responder = StubSession("fp-b", "Bob", pin="123456")
    app._handle_session(responder)
    initiator = StubSession("fp-c", "Cara", pin="654321", role="initiator", state="awaiting_confirm")
    app._handle_session(initiator)
    assert [s.role for s in app._pair_dialog_opens] == ["responder", "initiator"]
    assert app._pair_dialog_opens[0].pin == "123456"
    assert app._pair_dialog_opens[1].pin == "654321"


def make_transfer_app():
    """TrayApp without a Tk window for tracker-level tests."""
    app = make_app({})
    app._ensure_transfer_window = lambda: None
    app._close_transfer_window = lambda: None
    return app


def test_transfer_tracker_start_progress_done():
    app = make_transfer_app()
    app._tx_start("send", "fp-b", "Bob", "photo.jpg", None)
    tid = "send:fp-b:photo.jpg"
    assert tid in app._transfers
    entry = app._transfers[tid]
    assert entry["direction"] == "send"
    assert entry["peer"] == "Bob"
    assert entry["received"] == 0
    assert entry["total"] is None

    app._tx_progress(tid, 5000, 10000)
    assert app._transfers[tid]["received"] == 5000
    assert app._transfers[tid]["total"] == 10000

    app._tx_done(tid)
    assert tid not in app._transfers


def test_transfer_tracker_dedupes_and_handles_recv():
    app = make_transfer_app()
    app._tx_start("recv", "fp-a", "Alice", "in.bin", 4242)
    app._tx_start("recv", "fp-a", "Alice", "in.bin", 9999)  # duplicate -> no-op
    entries = [t for t in app._transfers if t.startswith("recv:fp-a")]
    assert len(entries) == 1
    assert app._transfers[entries[0]]["total"] == 4242


def test_transfer_menu_section_shows_percentage():
    app = make_transfer_app()
    app._tx_start("send", "fp-b", "Bob", "photo.jpg", None)
    tid = "send:fp-b:photo.jpg"
    app._tx_progress(tid, 67, 100)
    menu = app._build_menu()
    assert find_text(menu, "Transfers")
    rows = find_text(menu, "\u2191 photo.jpg 67%")
    assert rows, "menu must show the active transfer with percentage"
    assert str(rows[0].text).endswith("[███████░░░]")


def test_transfer_menu_clears_after_done():
    app = make_transfer_app()
    app._tx_start("send", "fp-b", "Bob", "photo.jpg", 100)
    app._tx_progress("send:fp-b:photo.jpg", 100, 100)
    app._tx_done("send:fp-b:photo.jpg")
    menu = app._build_menu()
    assert not find_text(menu, "photo.jpg")


def test_post_progress_throttles():
    app = make_transfer_app()
    tid = "send:fp-b:photo.jpg"
    app._tx_start("send", "fp-b", "Bob", "photo.jpg", 100)
    app._queue = __import__("queue").Queue()
    app._post_progress(tid, 1000, 10000)
    app._post_progress(tid, 2000, 10000)  # too soon -> suppressed
    assert app._queue.qsize() == 1
    app._post_progress(tid, 10000, 10000)  # final frame always posted
    assert app._queue.qsize() == 2


def test_stale_transfers_pruned():
    app = make_transfer_app()
    app._tx_start("recv", "fp-a", "Alice", "stalled.bin", 1000)
    tid = "recv:fp-a:stalled.bin"
    app._transfers[tid]["last"] -= 60.0
    closed = []
    app._close_transfer_window = lambda: closed.append(1)
    app._prune_stale_transfers(__import__("time").monotonic())
    assert tid not in app._transfers
    assert closed, "window must close once the last transfer is gone"


# -- KVM menu section --------------------------------------------------------


def test_kvm_menu_reflects_engine_state():
    app = make_app({})
    menu = app._build_menu()
    sharing = find_text(menu, "Mouse & keyboard sharing: OFF")[0]
    assert not sharing._checked(sharing)
    assert "no device online" in str(sharing.text)

    app.node.kvm.enabled = True
    menu = app._build_menu()
    sharing = find_text(menu, "Mouse & keyboard sharing: ON")[0]
    assert sharing._checked(sharing)


def test_kvm_toggle_action_flips_engine():
    app = make_app({})
    menu = app._build_menu()
    enable = find_text(menu, "Mouse & keyboard sharing: OFF")[0]
    enable._action(None, enable)
    assert app.node.kvm.enabled is True
    menu = app._build_menu()
    disable = find_text(menu, "Mouse & keyboard sharing: ON")[0]
    disable._action(None, disable)
    assert app.node.kvm.enabled is False


def test_kvm_peer_menu_shows_consent_and_side():
    store = StubStore()
    store.peers["fp-paired"] = {
        "fingerprint": "fp-paired",
        "name": "PairedBox",
        "paired_date": "2026-08-10",
        "kvm_allowed": True,
        "kvm_side": "top",
    }
    app = make_app({})
    app.node.store = store
    menu = app._build_menu()
    consent = find_text(menu, "Allow this device to control Tester")
    assert consent and all(it._checked(it) for it in consent)
    tops = find_text(menu, "Top")
    assert tops, "side radio items must exist"
    assert all(it._checked(it) for it in tops)
    assert not any(it._checked(it) for it in find_text(menu, "Right"))
    assert not any(it._checked(it) for it in find_text(menu, "Left"))
    assert not any(it._checked(it) for it in find_text(menu, "Bottom"))


def test_kvm_side_action_updates_store():
    app = make_app({})
    menu = app._build_menu()
    top_item = find_text(menu, "Top")[0]
    top_item._action(None, top_item)
    assert app.node.store.peers["fp-paired"]["kvm_side"] == "top"
    assert app.node.store.peers["fp-paired"]["kvm_allowed"] is False


def test_kvm_consent_action_updates_store():
    app = make_app({})
    menu = app._build_menu()
    allow = find_text(menu, "Allow this device to control Tester")[0]
    allow._action(None, allow)
    assert app.node.store.peers["fp-paired"]["kvm_allowed"] is True
    menu = app._build_menu()
    deny = find_text(menu, "Allow this device to control Tester")[0]
    deny._action(None, deny)
    assert app.node.store.peers["fp-paired"]["kvm_allowed"] is False


def test_kvm_status_row_reflects_link_and_control():
    app = make_app({})
    app.node.kvm.enabled = True
    app.node.kvm._links["fp-paired"] = "ready"
    app.node.kvm._controls["fp-paired"] = "local"
    menu = app._build_menu()
    assert find_text(menu, "KVM status: ready")

    app.node.kvm._links["fp-paired"] = "connecting"
    menu = app._build_menu()
    assert find_text(menu, "KVM status: connecting")

    app.node.kvm._links["fp-paired"] = "ready"
    app.node.kvm._controls["fp-paired"] = "controlling"
    menu = app._build_menu()
    assert find_text(menu, "KVM status: controlling")

    app.node.kvm._controls["fp-paired"] = "remote"
    menu = app._build_menu()
    assert find_text(menu, "KVM status: controlled by peer")

    app.node.kvm.enabled = False
    menu = app._build_menu()
    assert find_text(menu, "KVM status: off")


def test_kvm_status_offline_without_links():
    app = make_app({})
    app.node.kvm.enabled = True
    menu = app._build_menu()
    assert find_text(menu, "KVM status: offline")


def test_kvm_side_labels_use_device_name():
    app = make_app({})
    menu = app._build_menu()
    assert find_text(menu, "Allow this device to control Tester")
    assert find_text(menu, "This device is on this side of Tester")


def test_share_files_aggregate_into_one_batch():
    app = make_app({})
    app._queue_share_files(["a", "b"])
    app._queue_share_files(["b", "c"])  # duplicates collapse
    assert app._share_pending == ["a", "b", "c"]
    app._share_flush_at = time.monotonic() - 1
    app._flush_share_picker()
    assert app._share_pending == []
    assert app._share_dialog_files == ["a", "b", "c"]


def test_share_batch_sends_all_files_to_chosen_peer():
    app = make_app({})
    sent = []
    app._send_to = lambda peer, path: sent.append((peer["name"], path))
    app._share_dialog_files = ["a", "b", "c"]
    app._send_share_batch({"fingerprint": "fp-paired", "name": "PairedBox"})
    assert sent == [("PairedBox", "a"), ("PairedBox", "b"), ("PairedBox", "c")]
    assert app._share_dialog_files == []


def test_pump_interval_is_adaptive():
    app = make_app({})
    assert app._pump_interval() == app.IDLE_PUMP_INTERVAL
    app._transfers = {"recv:a:b": {}}
    assert app._pump_interval() == app.BUSY_PUMP_INTERVAL
    app._transfers = {}
    app._pending_toasts = ["boom"]
    assert app._pump_interval() == app.BUSY_PUMP_INTERVAL
    app._pending_toasts = []
    app._toast_flush_at = time.monotonic() + 1
    assert app._pump_interval() == app.BUSY_PUMP_INTERVAL
    app._toast_flush_at = 0.0
    app._share_pending = ["/tmp/x"]
    assert app._pump_interval() == app.BUSY_PUMP_INTERVAL
    app._share_pending = []
    app._pair_dialogs = {"fp": object()}
    assert app._pump_interval() == app.BUSY_PUMP_INTERVAL
    app._pair_dialogs = {}
    assert app._pump_interval() == app.IDLE_PUMP_INTERVAL


def test_toast_drops_info_and_aggregates_errors():
    app = make_app({})
    notified = []
    app.icon = type("Icon", (), {"notify": lambda self, m, t: notified.append(m)})()
    app._toast("Clipboard sync: on")
    app._toast("KVM linked with peer")
    app._toast("peer controls this device")
    assert notified == []  # info/status messages never reach the user

    app._toast("send failed: boom", "error")
    app._toast("kvm error: kaboom", "error")
    assert notified == []  # aggregated until the window elapses

    app._toast_flush_at = time.monotonic() - 1
    app._flush_toasts()
    assert notified == ["send failed: boom; kvm error: kaboom"]

    # The same combination is not re-shown.
    app._toast("send failed: boom", "error")
    app._toast("kvm error: kaboom", "error")
    app._toast_flush_at = 0.0
    app._flush_toasts()
    assert len(notified) == 1


pytestmark = pytest.mark.unit
