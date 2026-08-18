"""Temporary KVM log book window (diagnostics aid; remove after use).

A plain Tk Toplevel on the app's main thread. The engine's ``on_status``
stream (every level) is appended here with a timestamp, plus an on-demand
engine/platform diagnostics dump. Bounded ring, autoscroll, Clear/Copy.
"""

import time
import tkinter as tk
from tkinter import font as tkfont

MAX_ENTRIES = 500


class LogBook:
    def __init__(self, root, dump_diag=None):
        self._root = root
        self._dump_diag = dump_diag  # callable() -> diagnostics dict
        self._window = None
        self._text = None
        self._count = 0

    @property
    def open(self) -> bool:
        return self._window is not None

    def toggle(self) -> None:
        if self._window is not None:
            self._window.destroy()
            self._window = None
            self._text = None
            return
        win = tk.Toplevel(self._root)
        win.title("SecureShare - KVM log book")
        win.geometry("620x400")
        win.protocol("WM_DELETE_WINDOW", self.toggle)
        mono = tkfont.nametofont("TkFixedFont")
        text = tk.Text(
            win,
            wrap="word",
            state="disabled",
            font=mono,
            background="#111111",
            foreground="#dddddd",
            insertbackground="#dddddd",
        )
        scroll = tk.Scrollbar(win, command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        text.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        buttons = tk.Frame(win)
        buttons.grid(row=1, column=0, columnspan=2, sticky="ew")
        for label, cmd in (
            ("Clear", self._clear),
            ("Copy", self._copy),
            ("Dump diagnostics", self._dump),
        ):
            tk.Button(buttons, text=label, command=cmd).pack(side="left", padx=4, pady=4)
        tk.Button(buttons, text="Close", command=self.toggle).pack(side="right", padx=4, pady=4)
        win.rowconfigure(0, weight=1)
        win.columnconfigure(0, weight=1)
        self._window = win
        self._text = text
        self.append("--- KVM log book opened ---", "info")

    def append(self, message: str, level: str = "info") -> None:
        if self._window is None or self._text is None:
            return
        stamp = time.strftime("%H:%M:%S")
        prefix = "[err] " if level == "error" else ""
        self._text.configure(state="normal")
        self._text.insert("end", f"{stamp} {prefix}{message}\n")
        self._count += 1
        while self._count > MAX_ENTRIES:
            self._text.delete("1.0", "2.0")
            self._count -= 1
        self._text.see("end")
        self._text.configure(state="disabled")

    def _clear(self) -> None:
        if self._text is None:
            return
        self._text.configure(state="normal")
        self._text.delete("1.0", "end")
        self._text.configure(state="disabled")
        self._count = 0

    def _copy(self) -> None:
        if self._text is None:
            return
        try:
            content = self._text.get("1.0", "end-1c")
            self._root.clipboard_clear()
            self._root.clipboard_append(content)
        except Exception:
            pass

    def _dump(self) -> None:
        if self._dump_diag is None:
            self.append("diagnostics unavailable", "error")
            return
        try:
            diag = self._dump_diag()
        except Exception as exc:
            self.append(f"diagnostics failed: {exc}", "error")
            return
        self.append("--- KVM diagnostics ---", "info")
        if not isinstance(diag, dict):
            self.append(repr(diag), "info")
            return
        for key in (
            "state",
            "handoffs",
            "blocked_edges",
            "denial_latch",
            "last_request",
            "last_revert",
            "request_log",
            "revert_log",
        ):
            value = diag.get(key)
            if value is not None:
                self.append(f"{key}: {value}", "info")
        platform = diag.get("platform")
        if isinstance(platform, dict):
            self.append("platform:", "info")
            for pkey in (
                "family",
                "mode",
                "assoc_false",
                "assoc_true",
                "assoc_errors",
                "assoc_calls",
                "hook_thread_alive",
                "ignore_warps",
                "first_exception",
            ):
                if pkey in platform:
                    self.append(f"  {pkey}: {platform[pkey]}", "info")
        self.append("--- end diagnostics ---", "info")