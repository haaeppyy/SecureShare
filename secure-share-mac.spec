# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for the macOS .app bundle.
#
# Build:  pyinstaller --clean --noconfirm secure-share-mac.spec
# Result: dist/SecureShare.app
#
# Notes:
#   - Runs as a menu-bar (status item) app; no dock icon by default, which
#     is what a tray utility should look like. To show a dock icon, remove
#     the LSUIElement key below.
#   - The app bundle must be built on macOS (tkinter, pyobjc and zeroconf
#     are all platform-bound).

import subprocess

from PyInstaller.utils.hooks import collect_submodules


def _build_tag():
    """Git short hash at build time (the tray shows Version: x.y.z (hash)
    so both devices can be verified on the same build)."""
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
        return out or "dev"
    except Exception:
        return "dev"


with open("core/_build_tag.py", "w", encoding="utf-8") as f:
    f.write(f"BUILD_TAG = {_build_tag()!r}\n")

from core import version  # noqa: E402

hiddenimports = [
    "keyring.backends",
    "keyring.backends.macOS",
    "pystray._darwin",
    "tkinter",
    "tkinter.filedialog",
    "tkinter.messagebox",
]

datas = [("tray/icons/tray.png", "tray/icons")]

a = Analysis(
    ["tray/app.py"],
    pathex=["."],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["PyQt5", "PyQt6", "PySide2", "PySide6", "gi", "pytest"],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    exclude_binaries=True,
    name="SecureShare",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="SecureShare",
)

app = BUNDLE(
    coll,
    name="SecureShare.app",
    icon="tray/icons/tray_256.png",
    bundle_identifier="com.secureshare.app",
    info_plist={
        "CFBundleShortVersionString": version.APP_VERSION,
        "CFBundleVersion": f"{version.APP_VERSION}.{version.BUILD_TAG}",
        "LSUIElement": True,
        "NSHighResolutionCapable": True,
        "NSMicrophoneUsageDescription": "",
        "LSMinimumSystemVersion": "11.0",
        "CFBundleURLTypes": [
            {
                "CFBundleURLName": "com.secureshare.app",
                "CFBundleURLSchemes": ["secureshare"],
            }
        ],
        "NSServices": [
            {
                "NSMenuItem": {"default": "Send to SecureShare"},
                "NSMessage": "sendFile",
                "NSSendTypes": ["public.data"],
                "NSServiceDescription": "Send a file to a paired SecureShare device",
            }
        ],
    },
)
