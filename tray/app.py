"""SecureShare tray application.

Runs a pystray icon with tkinter dialogs. The design constraint is that
tkinter wants its root on the main thread while pystray can run detached,
so every UI action (menu click, pairing session, transfer completion) is
posted to a queue that the main thread drains inside its idle loop. The
Node itself lives on a background thread.

Layout of a busy node:
    main thread: tk root (hidden) + pystray Icon.run_detached()
    worker:      Node (discovery, transfer server, sync watchers)
"""

import argparse
import json
import os
import queue
import socket
import sys
import threading
import time
import urllib.parse
from functools import partial

import pystray
from PIL import Image, ImageDraw

from core.version import version_label

if not getattr(sys, "frozen", False):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from core.node import Node
    from core.transfer import default_download_dir
except RuntimeError as exc:
    print(f"SecureShare cannot start: {exc}", file=sys.stderr)
    sys.exit(1)

ICON_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icons", "tray.png")

SHARE_IPC_PORT = 48625
SHARE_IPC_MAX = 65536
SHARE_AGGREGATE_WINDOW = 1.5


def share_files_from_url(url: str) -> list[str]:
    """Parse secureshare://send?files=<newline-joined, percent-encoded paths>."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "secureshare" or parsed.netloc != "send":
        return []
    query = urllib.parse.parse_qs(parsed.query)
    raw = query.get("files", [""])[0]
    return [p for p in urllib.parse.unquote(raw).split("\n") if p]


def forward_share_request(files: list[str]) -> bool:
    """Hand the file list to the running primary instance; False when none
    is listening (the caller should start one and own the request)."""
    if not files:
        return True
    try:
        with socket.create_connection(("127.0.0.1", SHARE_IPC_PORT), timeout=1.5) as conn:
            conn.sendall(
                json.dumps({"action": "share", "files": files}).encode("utf-8")[
                    : SHARE_IPC_MAX
                ]
            )
            conn.settimeout(2.0)
            reply = conn.recv(16)
            return reply.strip() == b"ok"
    except OSError:
        return False


def default_icon():
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([8, 8, 56, 56], radius=14, fill=(41, 98, 255, 255))
    d.ellipse([22, 18, 42, 38], fill=(255, 255, 255, 255))
    d.polygon([(22, 38), (32, 52), (42, 38)], fill=(255, 255, 255, 255))
    return img


def load_icon():
    try:
        return Image.open(ICON_PATH)
    except OSError:
        return default_icon()


class TrayApp:
    def __init__(self, name=None, data_dir=None, download_dir=None, port=None, max_transfer_size=None, trusted_subnets=None, initial_share_files=None):
        self.name = name or None
        self.data_dir = data_dir
        self.download_dir = download_dir or default_download_dir()
        self.port = port
        self.max_transfer_size = max_transfer_size
        self.trusted_subnets = trusted_subnets
        self._initial_share_files = list(initial_share_files or [])
        self.node = None
        self.icon = None
        self.root = None
        self._queue = queue.Queue()
        self._sessions = {}
        self._session_ts = {}
        self._pair_dialogs = {}
        self._last_menu_refresh = 0.0
        self._menu_sig = None
        self._last_toast_text = None
        self._pending_toasts = []
        self._toast_flush_at = 0.0
        self._stopping = False
        self._transfers = {}
        self._last_tx_post = {}
        self._transfer_window = None
        self._transfer_rows = {}
        self._share_ipc = None
        self._share_pending = []
        self._share_flush_at = 0.0
        self._share_dialog = None
        self._share_dialog_files = []

    # -- lifecycle -----------------------------------------------------------

    def run(self):
        from core.transfer import DEFAULT_PORT

        self._start_share_ipc()
        self.node = Node(
            name=self.name,
            data_dir=self.data_dir,
            download_dir=self.download_dir,
            port=self.port or DEFAULT_PORT,
            max_transfer_size=self.max_transfer_size,
            trusted_subnets=self.trusted_subnets,
            on_status=lambda s, level="info": self.post(self._status_event, s, level),
            on_incoming_pair=lambda s: self.post(self._handle_session, s),
            on_transfer_start=lambda i: self.post(
                self._tx_start, "recv", i["fingerprint"], i["from"], i["name"], i["size"]
            ),
            on_transfer_progress=lambda i, r, t: self._post_progress(
                f"recv:{i['fingerprint']}:{i['name']}", r, t
            ),
            on_transfer_complete=lambda i: self.post(self._tx_recv_done, i),
            log=lambda m: self.post(self._log, m),
        )
        self.node.start()

        import tkinter as tk

        self.root = tk.Tk()
        self.root.withdraw()
        self.root.protocol("WM_DELETE_WINDOW", self._quit)

        from tray.logbook import LogBook

        self._logbook = LogBook(self.root, dump_diag=self._kvm_diagnostics)

        icon_options = {}
        if sys.platform == "darwin":
            # Integrate pystray into Tk's NSApplication: the Tk mainloop below
            # is what pumps AppKit events (pystray run_detached on macOS does
            # not run its own loop).
            try:
                from AppKit import NSApplication

                icon_options["darwin_nsapplication"] = NSApplication.sharedApplication()
            except Exception:
                pass

        self.icon = pystray.Icon(
            "SecureShare",
            load_icon(),
            "SecureShare",
            menu=self._build_menu(),
            **icon_options,
        )
        self.icon.run_detached()
        if self._initial_share_files:
            self._queue_share_files(self._initial_share_files)
            self._initial_share_files = []
        self._pump()

    def _quit(self):
        if self._stopping:
            return
        self._stopping = True
        try:
            self.icon.stop()
        except Exception:
            pass
        for session in list(self._sessions.values()):
            try:
                session.close()
            except Exception:
                pass
        for fp in list(self._pair_dialogs):
            self._close_pair_dialog(fp)
        try:
            self.node.stop()
        except Exception:
            pass
        self._close_transfer_window()
        ipc = self._share_ipc
        self._share_ipc = None
        if ipc is not None:
            try:
                ipc.close()
            except Exception:
                pass
        try:
            self.root.destroy()
        except Exception:
            pass

    # -- share IPC (loopback, single primary) --------------------------------

    def _start_share_ipc(self):
        """Bind the loopback share listener; if another instance already
        holds it, this instance stays a client (requests get forwarded)."""
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", SHARE_IPC_PORT))
            srv.listen(4)
            srv.settimeout(0.5)
            self._share_ipc = srv
            threading.Thread(target=self._share_ipc_loop, name="share-ipc", daemon=True).start()
        except OSError:
            self._share_ipc = None

    def _share_ipc_loop(self):
        while not self._stopping:
            try:
                conn, addr = self._share_ipc.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._handle_share_ipc, args=(conn, addr), daemon=True
            ).start()

    def _handle_share_ipc(self, conn, addr):
        try:
            if addr[0] != "127.0.0.1":
                return
            conn.settimeout(2.0)
            data = conn.recv(SHARE_IPC_MAX + 1)
            if not data or len(data) > SHARE_IPC_MAX:
                return
            req = json.loads(data.decode("utf-8"))
            if req.get("action") != "share":
                return
            files = [
                f
                for f in req.get("files", [])
                if isinstance(f, str) and os.path.isfile(f)
            ]
            if files:
                self.post(self._queue_share_files, files)
            conn.sendall(b"ok")
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _queue_share_files(self, files: list[str]):
        added = False
        for f in files:
            if f not in self._share_pending:
                self._share_pending.append(f)
                added = True
        if added:
            self._share_flush_at = time.monotonic() + SHARE_AGGREGATE_WINDOW

    def _flush_share_picker(self):
        if not self._share_pending or not self._share_flush_at:
            return
        if time.monotonic() < self._share_flush_at:
            return
        self._share_flush_at = 0.0
        self._show_share_dialog()

    def _close_share_dialog(self):
        win = self._share_dialog
        self._share_dialog = None
        self._share_dialog_files = []
        if win is not None:
            try:
                win.destroy()
            except Exception:
                pass

    def _show_share_dialog(self):
        """One picker for all pending files: pick a paired device, every file
        goes to it."""
        files = self._share_pending
        self._share_pending = []
        if not files:
            return
        if self._share_dialog is not None:
            try:
                if self._share_dialog.winfo_exists():
                    self._share_dialog_files.extend(files)
                    return
            except Exception:
                pass
        if self.root is None:
            # Headless (tests): record the batch; nothing to show.
            self._share_dialog_files = list(files)
            return
        import tkinter as tk

        self._prepare_dialog()
        win = tk.Toplevel(self.root)
        win.title("SecureShare - Send files")
        win.resizable(False, False)
        win.attributes("-topmost", True)
        win.protocol("WM_DELETE_WINDOW", self._close_share_dialog)
        self._share_dialog = win
        self._share_dialog_files = list(files)
        tk.Label(
            win,
            text=f"Send {len(files)} file(s) to:",
            font=("", 12, "bold"),
        ).pack(padx=28, pady=(16, 6))
        peers = sorted(
            self.node.store.list_peers(), key=lambda p: (p["name"] or "").lower()
        )
        if not peers:
            tk.Label(win, text="No paired devices yet", fg="#888").pack(pady=4)
        else:
            for peer in peers:
                tk.Button(
                    win,
                    text=peer["name"] or peer["fingerprint"][:8],
                    width=26,
                    command=lambda p=peer: self._send_share_batch(p),
                ).pack(pady=2)
        tk.Button(win, text="Cancel", width=12, command=self._close_share_dialog).pack(
            pady=(10, 14)
        )

    def _send_share_batch(self, peer):
        files = list(self._share_dialog_files)
        self._close_share_dialog()
        for path in files:
            self._send_to(peer, path)

    # -- main-thread queue pump ----------------------------------------------

    BUSY_PUMP_INTERVAL = 0.1
    IDLE_PUMP_INTERVAL = 1.0

    def _pump_interval(self) -> float:
        """Wake often while something needs the main thread (transfers,
        queued toasts, share picker, dialogs); otherwise once per second so
        an idle tray app costs almost no CPU."""
        if (
            self._transfers
            or self._pending_toasts
            or self._toast_flush_at
            or self._share_pending
            or self._share_flush_at
            or self._pair_dialogs
            or self._transfer_window is not None
            or self._share_dialog is not None
            or (getattr(self, "_logbook", None) is not None and self._logbook.open)
        ):
            return self.BUSY_PUMP_INTERVAL
        return self.IDLE_PUMP_INTERVAL

    def post(self, fn, *args):
        self._queue.put((fn, args))

    def _pump(self):
        while not self._stopping:
            try:
                fn, args = self._queue.get(timeout=self._pump_interval())
            except queue.Empty:
                self._refresh_menu_if_stale()
                if self.root:
                    self.root.update_idletasks()
                    self.root.update()
                self._flush_toasts()
                self._flush_share_picker()
                continue
            try:
                fn(*args)
            except Exception as exc:
                self._toast(f"error: {exc}", level="error")
            self._flush_toasts()
            self._flush_share_picker()
            if self.root:
                try:
                    self.root.update_idletasks()
                    self.root.update()
                except Exception:
                    break

    # -- UI helpers (main thread only) ---------------------------------------

    TOAST_WINDOW = 1.0
    TOAST_MAX_ITEMS = 4

    def _toast(self, message: str, level: str = "info"):
        """Notifications policy: only error-level messages reach the user;
        everything else (link state, takeover, toggles) is dropped. Errors
        arriving within the same short window are combined into ONE
        notification, flushed by the pump."""
        if level != "error":
            return
        if message not in self._pending_toasts:
            self._pending_toasts.append(message)
        if not self._toast_flush_at:
            self._toast_flush_at = time.monotonic() + self.TOAST_WINDOW

    def _flush_toasts(self):
        if not self._pending_toasts or not self._toast_flush_at:
            return
        if time.monotonic() < self._toast_flush_at:
            return
        messages = self._pending_toasts[: self.TOAST_MAX_ITEMS]
        if len(self._pending_toasts) > self.TOAST_MAX_ITEMS:
            messages.append(
                f"... and {len(self._pending_toasts) - self.TOAST_MAX_ITEMS} more"
            )
        self._pending_toasts.clear()
        self._toast_flush_at = 0.0
        text = "; ".join(messages)
        if text == self._last_toast_text:
            return
        self._last_toast_text = text
        try:
            self.icon.notify(text, "SecureShare")
        except Exception:
            pass

    def _log(self, message: str):
        self._toast(message)

    def _status_event(self, message: str, level: str = "info"):
        """Engine status stream: every level goes to the KVM log book (when
        open); toasts keep the existing error-only policy."""
        if getattr(self, "_logbook", None) is not None:
            self._logbook.append(message, level)
        self._toast(message, level)

    def _kvm_diagnostics(self) -> dict:
        return self.node.kvm.diagnostics()

    def _toggle_logbook(self, icon=None, item=None):
        logbook = getattr(self, "_logbook", None)
        if logbook is not None:
            self.post(logbook.toggle)

    def _refresh_menu_if_stale(self):
        now = time.monotonic()
        if now - self._last_menu_refresh < 2.0:
            return
        self._last_menu_refresh = now
        try:
            peers = self._safe_peers()
            self._prune_stale_transfers(now)
            sig = (
                len(peers),
                tuple((p.fingerprint, p.host, p.port) for p in peers),
                len([s for s in self._sessions.values() if self._session_actionable(s)]),
                self._sync_enabled(),
                self._kvm_enabled(),
                tuple(
                    (p["fingerprint"], p.get("kvm_allowed", False), p.get("kvm_side", "right"))
                    for p in self._kvm_peers()
                ),
                tuple(
                    (p["fingerprint"], self._peer_kvm_status(p["fingerprint"]))
                    for p in self._kvm_peers()
                ),
                tuple(
                    (tid, min(100, int(entry["received"] * 100 / (entry["total"] or 1))) // 5)
                    for tid, entry in sorted(self._transfers.items())
                ),
            )
        except Exception:
            return
        if sig == self._menu_sig:
            return
        self._menu_sig = sig
        try:
            self.icon.menu = self._build_menu()
            if os.environ.get("SECURESHARE_DEBUG"):
                print(
                    f"[menu] refreshed ok: peers={len(peers)} sync={self._sync_enabled()!r}",
                    flush=True,
                )
        except Exception:
            print("[menu] refresh FAILED", flush=True)
            if os.environ.get("SECURESHARE_DEBUG"):
                import traceback

                traceback.print_exc()

    # -- pairing -------------------------------------------------------------

    def _handle_session(self, session):
        if session.state == "denied" or session.error or not session.insession:
            self._toast(
                f"Pairing with {session.peer_name} failed: {session.error or 'denied'}",
                level="error",
            )
            return
        old = self._sessions.get(session.peer_fp)
        if old is not None and old is not session:
            try:
                old.close()
            except Exception:
                pass
        self._sessions[session.peer_fp] = session
        self._session_ts[session.peer_fp] = time.monotonic()
        self._show_pair_dialog(session)

    # -- pairing popups -------------------------------------------------------

    def _show_pair_dialog(self, session):
        """Pop up the pairing request / PIN confirmation window.

        Responder side shows Accept/Deny (the request to connect); the
        initiator side shows Confirm/Deny for the PIN match. Both sides
        must act: the responder Accepts, the initiator Confirms, and only
        then is trust stored.
        """
        if session.state in ("done", "denied") or session.error or not session.insession:
            return
        self._close_pair_dialog(session.peer_fp)
        import tkinter as tk

        self._prepare_dialog()
        win = tk.Toplevel(self.root)
        win.title("SecureShare - Pairing")
        win.resizable(False, False)
        win.attributes("-topmost", True)
        win.protocol("WM_DELETE_WINDOW", lambda: self._close_pair_dialog(session.peer_fp))
        if session.role == "initiator":
            title = f"Pairing with {session.peer_name}"
        else:
            title = f"Pairing from {session.peer_name}"
        tk.Label(win, text=title, font=("", 12, "bold")).pack(padx=28, pady=(16, 4))
        tk.Label(
            win,
            text=f"PIN: {session.pin}  -  check it matches on both screens",
            font=("", 11),
        ).pack(padx=28, pady=4)
        buttons = tk.Frame(win)
        buttons.pack(pady=(8, 16))
        if session.role == "initiator":
            tk.Button(
                buttons,
                text="Confirm",
                width=12,
                command=lambda: self._pair_dialog_action(session, "confirm"),
            ).pack(side="left", padx=6)
        else:
            tk.Button(
                buttons,
                text="Accept",
                width=12,
                command=lambda: self._pair_dialog_action(session, "accept"),
            ).pack(side="left", padx=6)
        tk.Button(
            buttons,
            text="Deny",
            width=12,
            command=lambda: self._pair_dialog_action(session, "deny"),
        ).pack(side="left", padx=6)
        self._pair_dialogs[session.peer_fp] = win

    def _pair_dialog_action(self, session, action):
        self._session_action(session, action)
        self._close_pair_dialog(session.peer_fp)
        if action == "deny":
            self._toast(f"Pairing with {session.peer_name} denied", level="error")

    def _close_pair_dialog(self, fingerprint):
        win = self._pair_dialogs.pop(fingerprint, None)
        if win is not None:
            try:
                win.destroy()
            except Exception:
                pass

    def _prune_sessions(self):
        now = time.monotonic()
        for fp, session in list(self._sessions.items()):
            if session.state in ("done", "denied") or session.error:
                del self._sessions[fp]
                self._session_ts.pop(fp, None)
                self._close_pair_dialog(fp)
            elif now - self._session_ts.get(fp, now) > 70.0:
                try:
                    session.close()
                except Exception:
                    pass
                del self._sessions[fp]
                self._session_ts.pop(fp, None)
                self._close_pair_dialog(fp)

    def _session_actionable(self, session):
        if session.error or not session.insession:
            return False
        if session.role == "initiator":
            return session.state == "awaiting_confirm"
        return session.state == "pending"

    def _session_action(self, session, action):
        try:
            if action == "accept":
                session.accept()
            elif action == "confirm":
                session.confirm(True)
            else:
                session.deny()
        except Exception as exc:
            self._toast(f"pairing error: {exc}", level="error")

    # -- transfers -----------------------------------------------------------

    TX_POST_INTERVAL = 0.2
    TX_STALE_AFTER = 30.0

    def _post_progress(self, tid, received, total):
        """Background-thread safe: throttles progress posts per transfer so
        the ~1 MiB chunk firehose does not flood the UI queue."""
        now = time.monotonic()
        last = self._last_tx_post.get(tid)
        if last is not None and now - last < self.TX_POST_INTERVAL and received < total:
            return
        self._last_tx_post[tid] = now
        self.post(self._tx_progress, tid, received, total)

    def _tx_start(self, direction, peer_fp, peer_name, name, total):
        tid = f"{direction}:{peer_fp}:{name}"
        if tid in self._transfers:
            return
        now = time.monotonic()
        self._transfers[tid] = {
            "direction": direction,
            "peer": peer_name,
            "name": name,
            "received": 0,
            "total": total,
            "started": now,
            "last": now,
        }
        self._ensure_transfer_window()
        self._rebuild_window_rows()

    def _tx_progress(self, tid, received, total):
        entry = self._transfers.get(tid)
        if entry is None:
            return
        if total is not None:
            entry["total"] = total
        entry["received"] = received
        entry["last"] = time.monotonic()
        if self._transfer_window is not None:
            try:
                if self._transfer_window.winfo_exists():
                    self._update_window_rows()
            except Exception:
                pass

    def _tx_done(self, tid):
        self._transfers.pop(tid, None)
        self._last_tx_post.pop(tid, None)
        if not self._transfers:
            self._close_transfer_window()

    def _tx_recv_done(self, info):
        self._tx_done(f"recv:{info['fingerprint']}:{info['name']}")

    def _prune_stale_transfers(self, now):
        for tid, entry in list(self._transfers.items()):
            if now - entry["last"] > self.TX_STALE_AFTER:
                del self._transfers[tid]
                self._last_tx_post.pop(tid, None)
        if not self._transfers:
            self._close_transfer_window()

    # -- transfer progress window -------------------------------------------

    def _ensure_transfer_window(self):
        if self._transfer_window is not None:
            try:
                if self._transfer_window.winfo_exists():
                    return
            except Exception:
                pass
        import tkinter as tk

        self._prepare_dialog()
        win = tk.Toplevel(self.root)
        win.title("SecureShare Transfers")
        win.attributes("-topmost", True)
        win.resizable(False, False)
        win.protocol("WM_DELETE_WINDOW", self._hide_transfer_window)
        self._transfer_window = win
        self._transfer_rows = {}
        self._rebuild_window_rows()

    def _hide_transfer_window(self):
        try:
            self._transfer_window.withdraw()
        except Exception:
            pass

    def _close_transfer_window(self):
        if self._transfer_window is not None:
            try:
                self._transfer_window.destroy()
            except Exception:
                pass
        self._transfer_window = None
        self._transfer_rows = {}

    def _rebuild_window_rows(self):
        win = self._transfer_window
        if win is None:
            return
        import tkinter as tk
        from tkinter import ttk

        for child in win.winfo_children():
            child.destroy()
        self._transfer_rows = {}
        for tid, entry in sorted(self._transfers.items()):
            frame = tk.Frame(win)
            frame.pack(fill="x", padx=10, pady=6)
            arrow = "↑" if entry["direction"] == "send" else "↓"
            tk.Label(frame, text=f"{arrow} {entry['name']}  ->  {entry['peer']}", anchor="w").pack(
                fill="x"
            )
            bar = ttk.Progressbar(frame, maximum=entry["total"] or 1, value=0)
            bar.pack(fill="x", pady=2)
            status = tk.Label(frame, text="", anchor="w")
            status.pack(fill="x")
            self._transfer_rows[tid] = {"bar": bar, "status": status}
        self._update_window_rows()

    def _update_window_rows(self):
        for tid, entry in sorted(self._transfers.items()):
            row = self._transfer_rows.get(tid)
            if row is None:
                self._rebuild_window_rows()
                return
            total = entry["total"]
            if not total:
                continue
            row["bar"].configure(maximum=total, value=entry["received"])
            pct = min(100.0, entry["received"] * 100.0 / total)
            elapsed = max(0.001, entry["last"] - entry["started"])
            rate = entry["received"] / elapsed
            rem = total - entry["received"]
            eta = rem / rate if rate > 0 else 0.0
            row["status"].configure(
                text=f"{pct:.0f}%  \u00b7  {rate / 1048576:.1f} MB/s  \u00b7  ETA {eta:.0f}s"
            )

    # -- menu ----------------------------------------------------------------

    def _build_menu(self):
        self._prune_sessions()
        items = [
            pystray.MenuItem(lambda item: f"Name: {self._node_name()}", None, enabled=False),
            pystray.MenuItem(lambda item: f"Status: {self._status()}", None, enabled=False),
            pystray.MenuItem(lambda item: f"Version: {version_label()}", None, enabled=False),
            pystray.Menu.SEPARATOR,
        ]
        transfer_items = self._transfer_items()
        if transfer_items:
            items.append(pystray.MenuItem("Transfers", None, enabled=False))
            items.extend(transfer_items)
            items.append(pystray.Menu.SEPARATOR)
        active = sorted(
            (s for s in self._sessions.values() if self._session_actionable(s)),
            key=lambda s: s.peer_name.lower(),
        )
        if active:
            for session in active:
                items.append(self._pairing_submenu(session))
            items.append(pystray.Menu.SEPARATOR)

        peers = self._safe_peers()

        if peers:
            items.append(self._pair_submenu(peers))
            items.append(self._send_submenu(peers))
            items.append(self._unpair_submenu())
        else:
            items.append(pystray.MenuItem("No devices currently online", None, enabled=False))

        items.append(pystray.Menu.SEPARATOR)
        items.append(
            pystray.MenuItem(
                lambda item: "Clipboard sync: ON" if self._sync_enabled() else "Clipboard sync: OFF",
                lambda icon, item: self.post(self._toggle_sync),
                checked=lambda item: self._sync_enabled(),
            )
        )
        # This is deliberately a direct menu switch. On macOS a submenu is
        # visually indistinguishable from a setting until it has been opened.
        items.append(
            pystray.MenuItem(
                lambda item: self._kvm_switch_label(),
                partial(self._toggle_kvm),
                checked=lambda item: self._kvm_enabled(),
            )
        )
        items.append(
            pystray.MenuItem("KVM log book…", partial(self._toggle_logbook))
        )
        items.append(self._kvm_setup_submenu())
        items.append(pystray.Menu.SEPARATOR)
        items.append(pystray.MenuItem("Open download folder", self._open_downloads))
        items.append(pystray.MenuItem("Quit", self._quit))
        return pystray.Menu(*items)

    def _pairing_submenu(self, session):
        if session.role == "initiator":
            label = f"Pairing with {session.peer_name}"
            confirm = pystray.MenuItem(
                "Confirm",
                lambda icon, item: self.post(self._session_action, session, "confirm"),
            )
        else:
            label = f"Pairing from {session.peer_name}"
            confirm = pystray.MenuItem(
                "Accept",
                lambda icon, item: self.post(self._session_action, session, "accept"),
            )
        return pystray.MenuItem(
            label,
            pystray.Menu(
                pystray.MenuItem(f"PIN: {session.pin}", None, enabled=False),
                confirm,
                pystray.MenuItem(
                    "Deny",
                    lambda icon, item: self.post(self._session_action, session, "deny"),
                ),
            ),
        )

    def _transfer_items(self):
        items = []
        for tid, entry in sorted(self._transfers.items()):
            total = entry["total"] or 1
            pct = min(100, int(entry["received"] * 100 / total))
            arrow = "↑" if entry["direction"] == "send" else "↓"
            filled = round(pct / 10)
            bar = "█" * filled + "░" * (10 - filled)
            items.append(
                pystray.MenuItem(
                    f"{arrow} {entry['name']} {pct}% [{bar}]",
                    None,
                    enabled=False,
                )
            )
        return items

    def _node_name(self):
        try:
            return self.node.store.identity["name"]
        except Exception:
            return "SecureShare"

    def _safe_peers(self):
        try:
            return sorted(
                self.node.discovery.peers().values(), key=lambda p: (p.name or "").lower()
            )
        except Exception:
            return []

    def _status(self):
        try:
            peers = len(self.node.discovery.peers())
            paired = len(self.node.store.list_peers())
            if peers == 0:
                return f"No devices online · {paired} paired saved"
            return f"{peers} device(s) online · {paired} paired saved"
        except Exception:
            return "starting..."

    def _sync_enabled(self):
        try:
            return bool(self.node.store.sync_enabled)
        except Exception:
            return False

    # -- keyboard & mouse sharing (KVM) --------------------------------------

    def _kvm_enabled(self):
        try:
            return bool(self.node.kvm.enabled)
        except Exception:
            return False

    def _kvm_switch_label(self):
        """Feature state, never a claim that a peer is connected."""
        try:
            online = len(self.node.discovery.peers())
        except Exception:
            online = 0
        state = "ON" if self._kvm_enabled() else "OFF"
        suffix = " · no device online" if online == 0 else ""
        return f"Mouse & keyboard sharing: {state}{suffix}"

    def _kvm_peers(self):
        try:
            return sorted(self.node.store.list_peers(), key=lambda p: (p["name"] or "").lower())
        except Exception:
            return []

    def _toggle_kvm(self, icon=None, item=None):
        try:
            before = self._kvm_enabled()
            self.node.kvm.set_enabled(not before)
            if os.environ.get("SECURESHARE_DEBUG"):
                print(
                    f"[menu] toggle kvm {before} -> {not before} "
                    f"(engine={self.node.kvm.enabled!r}, store={self.node.store.kvm_enabled!r})",
                    flush=True,
                )
        except Exception as exc:
            self._toast(f"kvm error: {exc}", level="error")

    def _toggle_kvm_allowed(self, fingerprint, icon=None, item=None):
        self._set_kvm_allowed(fingerprint, not self._peer_kvm_allowed(fingerprint))

    def _set_kvm_allowed(self, fingerprint, allowed, icon=None, item=None):
        try:
            self.node.store.set_peer_kvm_allowed(fingerprint, allowed)
        except Exception as exc:
            self._toast(f"kvm error: {exc}", level="error")

    def _set_kvm_side(self, fingerprint, side, icon=None, item=None):
        try:
            self.node.store.set_peer_kvm_side(fingerprint, side)
        except Exception as exc:
            self._toast(f"kvm error: {exc}", level="error")

    def _kvm_setup_submenu(self):
        peers = self._kvm_peers()
        if not peers:
            peers_label = [pystray.MenuItem("No paired devices", None, enabled=False)]
        else:
            peers_label = []
        peer_items = []
        for peer in peers:
            fp = peer["fingerprint"]
            status = self._peer_kvm_status(fp)
            side_items = []
            for label, value in (
                ("Left", "left"),
                ("Right", "right"),
                ("Top", "top"),
                ("Bottom", "bottom"),
            ):
                side_items.append(
                    pystray.MenuItem(
                        label,
                        partial(self._set_kvm_side, fp, value),
                        radio=True,
                        checked=partial(self._peer_kvm_side, fp, value),
                    )
                )
            peer_items.append(
                pystray.MenuItem(
                    peer["name"] or peer["fingerprint"][:8],
                    pystray.Menu(
                        pystray.MenuItem(
                            f"KVM status: {status}",
                            None,
                            enabled=False,
                        ),
                        pystray.Menu.SEPARATOR,
                        pystray.MenuItem(
                            f"Allow this device to control {self._node_name()}",
                            partial(self._toggle_kvm_allowed, fp),
                            checked=partial(self._peer_kvm_allowed, fp),
                        ),
                        pystray.MenuItem(
                            self._kvm_takeover_label(fp),
                            self._kvm_takeover_click(fp),
                            enabled=self._kvm_takeover_enabled(fp),
                        ),
                        pystray.Menu.SEPARATOR,
                        pystray.MenuItem(
                            f"This device is on this side of {self._node_name()}",
                            None,
                            enabled=False,
                        ),
                        *side_items,
                    ),
                )
            )
        return pystray.MenuItem(
            lambda item: f"Mouse & keyboard devices… ({len(peers)} paired)",
            pystray.Menu(
                pystray.MenuItem("Move across a selected screen edge to control it", None, enabled=False),
                *peers_label,
                *peer_items,
            ),
        )

    def _kvm_takeover_label(self, fp):
        """Menu-driven control toggle: one state-aware action per device."""
        status = self._peer_kvm_status(fp)

        def label(item=None):
            current = self._peer_kvm_status(fp)
            if current == "controlling" or current == "waiting for peer":
                return "Release control of this device…"
            if current == "controlled by peer":
                return "Give control back to this device"
            return "Take control of this device"
        return label

    def _kvm_takeover_enabled(self, fp):
        def enabled(item=None):
            status = self._peer_kvm_status(fp)
            if status in ("controlling", "waiting for peer", "controlled by peer"):
                return True
            return status == "ready"
        return enabled

    def _kvm_takeover_click(self, fp):
        def click(icon, item):
            status = self._peer_kvm_status(fp)
            if status == "controlling" or status == "waiting for peer":
                self.node.kvm.release_control(fp)
            elif status == "controlled by peer":
                self.node.kvm.release_control(fp)
            else:
                self.node.kvm.request_control(fp)
        return click

    def _peer_kvm_status(self, fp, item=None):
        """Per-peer KVM state. Link and control are separate on purpose."""
        try:
            link = self.node.kvm.link_status(fp)
            control = self.node.kvm.control_label(fp)
        except Exception:
            link = "offline"
            control = "local"
        if self._kvm_enabled() is False:
            return "off"
        if control == "controlling":
            return "controlling"
        if control == "waiting_active":
            return "waiting for peer"
        if control == "remote":
            return "controlled by peer"
        if control in ("requesting", "remote_preparing", "reverting"):
            return control.replace("_", " ")
        if link == "error":
            return "error"
        if link == "ready":
            return "ready"
        if link == "linked":
            return "linked"
        if link == "connecting":
            return "connecting"
        return "offline"

    def _peer_kvm_allowed(self, fp, item=None):
        try:
            return bool(self.node.store.get_peer(fp).get("kvm_allowed", False))
        except Exception:
            return False

    def _peer_kvm_not_allowed(self, fp, item=None):
        return not self._peer_kvm_allowed(fp)

    def _peer_kvm_side(self, fp, value, item=None):
        try:
            return self.node.store.get_peer(fp).get("kvm_side", "right") == value
        except Exception:
            return False

    def _toggle_sync(self):
        try:
            before = self._sync_enabled()
            self.node.sync.set_enabled(not before)
            if os.environ.get("SECURESHARE_DEBUG"):
                print(
                    f"[menu] toggle sync {before} -> {not before} "
                    f"(store={self.node.store.sync_enabled!r})",
                    flush=True,
                )
        except Exception as exc:
            import traceback

            traceback.print_exc()
            self._toast(f"sync error: {exc}", level="error")

    def _pair_submenu(self, peers):
        def make_item(peer):
            return pystray.MenuItem(
                peer.name or peer.fingerprint[:8],
                lambda icon, item: self.post(self._start_pairing, peer),
            )

        items = [
            make_item(p)
            for p in peers
            if not self.node.store.is_paired(p.fingerprint)
        ]
        if not items:
            items = [pystray.MenuItem("All devices paired", None, enabled=False)]
        return pystray.MenuItem("Pair with device", pystray.Menu(*items))

    def _send_submenu(self, peers):
        def make_item(peer):
            return pystray.MenuItem(
                peer.name or peer.fingerprint[:8],
                lambda icon, item: self.post(self._pick_and_send, peer),
            )

        items = [
            make_item(p) for p in peers if self.node.store.is_paired(p.fingerprint)
        ]
        if not items:
            items = [pystray.MenuItem("No paired devices", None, enabled=False)]
        return pystray.MenuItem("Send file to", pystray.Menu(*items))

    def _unpair_submenu(self):
        def make_item(peer):
            return pystray.MenuItem(
                f"{peer['name']} ({peer['fingerprint'][:8]})",
                lambda icon, item: self.post(self._unpair, peer["fingerprint"]),
            )

        items = [make_item(p) for p in self.node.store.list_peers()]
        if not items:
            items = [pystray.MenuItem("No paired devices", None, enabled=False)]
        return pystray.MenuItem("Unpair device", pystray.Menu(*items))

    def _open_downloads(self, icon=None, item=None):
        import subprocess

        try:
            if sys.platform == "darwin":
                subprocess.Popen(["open", self.download_dir])
            elif sys.platform == "win32":
                os.startfile(self.download_dir)
        except Exception as exc:
            self._toast(f"cannot open downloads: {exc}", level="error")

    # -- actions (main thread; heavy work offloaded to threads) --------------

    def _start_pairing(self, peer):
        def worker():
            try:
                # pair_with posts the session through on_session -> the UI
                # already handles it (menu entry); nothing more to do here.
                self.node.pair_with(peer.host, peer.port)
            except Exception as exc:
                self.post(self._toast, f"pairing failed: {exc}", "error")

        threading.Thread(target=worker, name="pair-init", daemon=True).start()

    def _prepare_dialog(self):
        """Put the hidden root on-screen so native dialogs (file picker,
        message boxes) never open clipped or off-screen."""
        try:
            w = self.root.winfo_screenwidth()
            h = self.root.winfo_screenheight()
            self.root.geometry(f"+{max(0, w // 2 - 250)}+{max(0, h // 4)}")
            self.root.update_idletasks()
        except Exception:
            pass

    def _pick_and_send(self, peer):
        from tkinter import filedialog

        self._prepare_dialog()
        path = filedialog.askopenfilename(
            parent=None if sys.platform == "darwin" else self.root,
            title=f"Send to {peer.name}",
        )
        if not path:
            return
        self._send_to(peer, path)

    def _send_to(self, peer, path):
        name = os.path.basename(path)
        tid = f"send:{peer.fingerprint}:{name}"

        def worker():
            self.post(
                self._tx_start,
                "send",
                peer.fingerprint,
                peer.name or peer.fingerprint[:8],
                name,
                None,
            )
            try:
                result = self.node.send_file(
                    peer.fingerprint, path, on_progress=self._post_progress_for(tid)
                )
                self.post(self._tx_done, tid)
            except Exception as exc:
                self.post(self._tx_done, tid)
                self.post(self._toast, f"send failed: {exc}", "error")

        threading.Thread(target=worker, name="send-file", daemon=True).start()

    def _post_progress_for(self, tid):
        def progress(sent, total):
            self._post_progress(tid, sent, total)

        return progress

    def _unpair(self, fingerprint: str):
        from tkinter import messagebox

        peer = self.node.store.get_peer(fingerprint)
        name = peer["name"] if peer else fingerprint[:8]
        self._prepare_dialog()
        if messagebox.askyesno("SecureShare", f"Unpair {name}?"):
            self.node.store.remove_peer(fingerprint)


def parse_share_argv(argv: list[str]) -> tuple[list[str], list[str]]:
    """Split raw argv into (options for argparse, share files).

    Handles the three launch shapes that carry files:
      - secureshare://send?files=...  (Share Extension URL scheme)
      - -sendFile <path> [-sendFile <path> ...]  (Finder Services)
      - plain paths                    (Windows right-click / Send to)
    macOS LaunchServices also passes a -psn_<n> serial, which is dropped.
    """
    rest = []
    files = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg.startswith("secureshare://"):
            files.extend(share_files_from_url(arg))
            i += 1
            continue
        if arg == "-sendFile" and i + 1 < len(argv):
            files.append(argv[i + 1])
            i += 2
            continue
        if arg.startswith("-psn_"):
            i += 1
            continue
        rest.append(arg)
        i += 1
    return rest, files


def main():
    rest, flag_files = parse_share_argv(sys.argv[1:])

    parser = argparse.ArgumentParser(description="SecureShare tray app")
    parser.add_argument("--name", help="device name shown to peers")
    parser.add_argument("--data-dir", help="where trust data is stored")
    parser.add_argument("--download-dir", help="where received files go")
    parser.add_argument("--port", type=int, help="transfer listener port")
    parser.add_argument(
        "--max-transfer-size",
        type=int,
        help="maximum accepted transfer size in bytes (default 10 GiB)",
    )
    parser.add_argument(
        "--trusted-subnets",
        help="comma-separated CIDRs allowed to connect (e.g. 192.168.1.0/24); "
        "default: any LAN peer",
    )
    parser.add_argument(
        "files",
        nargs="*",
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args(rest)

    share_files = []
    share_files.extend(flag_files)
    share_files.extend(args.files or [])
    share_files = [f for f in share_files if os.path.isfile(f)]

    if share_files:
        # A primary instance is already running: hand the files over and exit.
        if forward_share_request(share_files):
            return

    TrayApp(
        name=args.name,
        data_dir=args.data_dir,
        download_dir=args.download_dir,
        port=args.port,
        max_transfer_size=args.max_transfer_size,
        trusted_subnets=args.trusted_subnets,
        initial_share_files=share_files or None,
    ).run()


if __name__ == "__main__":
    main()
