# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the Monday Report Offline Edition (Windows-first).

Bundles the FastAPI backend, the licensing package, and the PREBUILT frontend
(dist/) into a one-folder application that runs without Internet, Node.js, a
separate Python, Docker, PostgreSQL, or Redis. The private signing key is never
part of this build; only a customer-facing PUBLIC key is added by the build
orchestrator AFTER PyInstaller runs.
"""
import os
from pathlib import Path

ROOT = Path(os.getcwd()).resolve()

block_cipher = None

a = Analysis(
    [str(ROOT / "packaging" / "offline_entry.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[(str(ROOT / "dist"), "dist")],
    hiddenimports=[
        "backend.app.main",
        "backend.app.offline_runtime",
        "backend.app.worker",
        "backend.app.licensing.offline_provider",
        "uvicorn.logging",
        "uvicorn.loops.auto",
        "uvicorn.protocols.http.auto",
        "uvicorn.protocols.websockets.auto",
        "uvicorn.lifespan.on",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Server-backend adapters are not part of the offline product.
        "psycopg",
        "redis",
        "tkinter",
        # Accidental transitive bundles: nothing in the offline runtime uses
        # these, and nltk's PyInstaller runtime hook crashes on machines
        # without a populated user profile.
        "nltk",
        "matplotlib",
        "numpy",
        "pandas",
        "scipy",
        "IPython",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="MondayReportOffline",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="MondayReportOffline",
)
