"""Cross-platform clipboard access.

Text is read/written via pyperclip everywhere. Images need OS-specific
APIs (pyperclip has no image support): win32clipboard on Windows,
NSPasteboard on macOS - see clipboard_win.py / clipboard_mac.py.

Platform modules are imported lazily so that neither OS is required to
have the other OS's dependencies installed.

File copies (drag-copy in Finder/Explorer) are detected so they are never
synced - file clipboard sync is explicitly out of scope.
"""

import sys

import pyperclip


class ClipboardSnapshot:
    __slots__ = ("text", "image_png", "file_copy")

    def __init__(self, text=None, image_png=None, file_copy=False):
        self.text = text
        self.image_png = image_png
        self.file_copy = file_copy

    def signature(self):
        parts = []
        if self.text is not None:
            parts.append(("t", hash(self.text)))
        if self.image_png is not None:
            parts.append(("i", hash(self.image_png)))
        return tuple(parts)


def read() -> ClipboardSnapshot:
    """Return the current clipboard content (text and/or image PNG)."""
    if sys.platform == "darwin":
        from . import clipboard_mac

        return clipboard_mac.read()
    if sys.platform == "win32":
        from . import clipboard_win

        return clipboard_win.read()
    text = _safe_paste()
    return ClipboardSnapshot(text=text if text else None)


def write(text: str | None = None, image_png: bytes | None = None) -> None:
    """Set the clipboard; both kinds may be set together."""
    if image_png is not None:
        if sys.platform == "darwin":
            from . import clipboard_mac

            clipboard_mac.write_image(image_png)
            return
        if sys.platform == "win32":
            from . import clipboard_win

            clipboard_win.write_image(image_png)
            return
    if text is not None:
        _safe_copy(text)


def _safe_paste() -> str:
    try:
        return pyperclip.paste()
    except Exception:
        return ""


def _safe_copy(text: str) -> None:
    try:
        pyperclip.copy(text)
    except Exception:
        pass