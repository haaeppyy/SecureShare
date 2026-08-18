"""macOS clipboard access via AppKit.NSPasteboard (image) + pyperclip (text).

Screenshots are commonly TIFF on macOS; they are converted to PNG for
transport. Finder file copies (public.file-url) are detected and
excluded from sync.
"""

import io

from .clipboard import ClipboardSnapshot

FILE_URL = "public.file-url"
FILENAMES = "NSFilenamesPboardType"

_box = None
_box_error = None


def _appkit():
    global _box, _box_error
    if _box_error is not None:
        raise _box_error
    if _box is None:
        try:
            from AppKit import (
                NSPasteboard,
                NSPasteboardTypePNG,
                NSPasteboardTypeString,
                NSPasteboardTypeTIFF,
            )
            from Foundation import NSData

            _box = {
                "NSPasteboard": NSPasteboard,
                "PNG": NSPasteboardTypePNG,
                "TIFF": NSPasteboardTypeTIFF,
                "STRING": NSPasteboardTypeString,
                "NSData": NSData,
            }
        except Exception as exc:  # pragma: no cover - only on non-macOS
            _box_error = exc
            raise _box_error
    return _box


def _to_bytes(data):
    try:
        return bytes(data)
    except Exception:
        return None


def _tiff_to_png(tiff: bytes):
    try:
        from PIL import Image

        img = Image.open(io.BytesIO(tiff))
        out = io.BytesIO()
        img.save(out, "PNG")
        return out.getvalue()
    except Exception:
        return None


def _read_text(appkit):
    pb = appkit["NSPasteboard"].generalPasteboard()
    if appkit["STRING"] in pb.types():
        data = pb.dataForType_(appkit["STRING"])
        if data is not None:
            raw = _to_bytes(data)
            if isinstance(raw, bytes):
                try:
                    return raw.decode("utf-8")
                except Exception:
                    return raw.decode("latin-1", "replace")
    try:
        import pyperclip

        return pyperclip.paste() or None
    except Exception:
        return None


def change_count() -> int:
    """NSPasteboard change counter: a monotonic revision number whose
    comparison needs no content copy at all."""
    pb = _appkit()["NSPasteboard"].generalPasteboard()
    return int(pb.changeCount())


def read() -> ClipboardSnapshot:
    try:
        appkit = _appkit()
    except Exception:
        try:
            import pyperclip

            return ClipboardSnapshot(text=pyperclip.paste() or None)
        except Exception:
            return ClipboardSnapshot()

    pb = appkit["NSPasteboard"].generalPasteboard()
    types = list(pb.types())
    if FILE_URL in types or FILENAMES in types:
        return ClipboardSnapshot(text=_read_text(appkit), file_copy=True)

    image_png = None
    if appkit["PNG"] in types:
        data = pb.dataForType_(appkit["PNG"])
        if data is not None:
            image_png = _to_bytes(data)
    elif appkit["TIFF"] in types:
        data = pb.dataForType_(appkit["TIFF"])
        if data is not None:
            tiff = _to_bytes(data)
            if tiff is not None:
                image_png = _tiff_to_png(tiff)

    text = _read_text(appkit)
    return ClipboardSnapshot(text=text, image_png=image_png)


def write_image(png_bytes: bytes) -> None:
    appkit = _appkit()
    tiff_bytes = None
    try:
        from PIL import Image

        img = Image.open(io.BytesIO(png_bytes))
        tiff = io.BytesIO()
        img.save(tiff, "TIFF")
        tiff_bytes = tiff.getvalue()
    except Exception:
        tiff_bytes = None

    pb = appkit["NSPasteboard"].generalPasteboard()
    pb.clearContents()
    ns_png = appkit["NSData"].dataWithBytes_length_(png_bytes, len(png_bytes))
    pb.setData_forType_(ns_png, appkit["PNG"])
    if tiff_bytes is not None:
        ns_tiff = appkit["NSData"].dataWithBytes_length_(tiff_bytes, len(tiff_bytes))
        pb.setData_forType_(ns_tiff, appkit["TIFF"])