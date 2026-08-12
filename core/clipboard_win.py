"""Windows clipboard access via win32clipboard (image) + pyperclip (text).

Images are read as CF_DIB (device-independent bitmap) and normalized to
PNG; writing stores CF_DIB derived from a PNG. Explorer file copies
(CF_HDROP) are detected and excluded from sync.
"""

import io
import struct

from .clipboard import ClipboardSnapshot


def _dib_to_png(dib: bytes):
    try:
        from PIL import Image

        (bi_size,) = struct.unpack_from("<I", dib, 0)
        bmp = b"BM" + struct.pack("<IHHI", 14 + len(dib), 0, 0, 14 + bi_size) + dib
        img = Image.open(io.BytesIO(bmp))
        out = io.BytesIO()
        img.save(out, "PNG")
        return out.getvalue()
    except Exception:
        return None


def _png_to_dib(png_bytes: bytes) -> bytes:
    from PIL import Image

    img = Image.open(io.BytesIO(png_bytes))
    bmp = io.BytesIO()
    img.save(bmp, "BMP")
    return bmp.getvalue()[14:]  # strip BITMAPFILEHEADER, keep BITMAPINFO + pixels


def read() -> ClipboardSnapshot:
    try:
        import win32clipboard
        import win32con
    except Exception:
        try:
            import pyperclip

            return ClipboardSnapshot(text=pyperclip.paste() or None)
        except Exception:
            return ClipboardSnapshot()

    try:
        win32clipboard.OpenClipboard()
    except Exception:
        return ClipboardSnapshot()
    try:
        if win32clipboard.IsClipboardFormatAvailable(win32con.CF_HDROP):
            return ClipboardSnapshot(
                text=_text_from_clipboard(win32clipboard) or None, file_copy=True
            )
        image_png = None
        if win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_DIB):
            try:
                dib = win32clipboard.GetClipboardData(win32clipboard.CF_DIB)
            except Exception:
                dib = None
            if dib:
                image_png = _dib_to_png(bytes(dib))
        text = _text_from_clipboard(win32clipboard)
        return ClipboardSnapshot(text=text or None, image_png=image_png)
    finally:
        try:
            win32clipboard.CloseClipboard()
        except Exception:
            pass


def _text_from_clipboard(win32clipboard) -> str | None:
    try:
        if win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_UNICODETEXT):
            return win32clipboard.GetClipboardData(win32clipboard.CF_UNICODETEXT)
    except Exception:
        pass
    return None


def write_image(png_bytes: bytes) -> None:
    import win32clipboard

    try:
        dib = _png_to_dib(png_bytes)
    except Exception:
        return
    try:
        win32clipboard.OpenClipboard()
        try:
            win32clipboard.EmptyClipboard()
            win32clipboard.SetClipboardData(win32clipboard.CF_DIB, dib)
        finally:
            win32clipboard.CloseClipboard()
    except Exception:
        pass