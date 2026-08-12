# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for Windows (one-file console-less exe).
#
# Build on Windows:  pyinstaller --clean --noconfirm secure-share-win.spec
# Result: dist/SecureShare.exe
#
# Notes:
#   - Must be built on Windows (pywin32, win32 tray backend).
#   - The tray icon is embedded via datas; pystray finds it relative to
#     the bundled path (see tray/app.py load_icon).

hiddenimports = [
    "keyring.backends",
    "keyring.backends.Windows",
    "pystray._win32",
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
    [],
    exclude_binaries=True,
    name="SecureShare",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    icon="tray/icons/tray_256.png",
)
