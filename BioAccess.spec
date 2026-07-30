# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path


project_root = Path.cwd()


a = Analysis(
    ["package_bioaccess.py"],
    pathex=[str(project_root), str(project_root / "vendorlibs")],
    binaries=[],
    datas=[
        (str(project_root / "biometric_app"), "biometric_app"),
        (str(project_root / "vendorlibs"), "vendorlibs"),
        (
            str(
                project_root
                / "tools"
                / "FutronicCaptureHelper"
                / "bin"
                / "Release"
                / "net8.0"
                / "win-x86"
                / "publish"
            ),
            "tools/FutronicCaptureHelper/bin/Release/net8.0/win-x86/publish",
        ),
        (str(project_root / "tools" / "dotnet-x86"), "tools/dotnet-x86"),
        (str(project_root / "data"), "data"),
    ],
    hiddenimports=[
        "pymysql",
        "cv2",
        "numpy",
        "cryptography",
        "PySide6.QtCore",
        "PySide6.QtGui",
        "PySide6.QtWidgets",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="BioAccess",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="BioAccess",
)
