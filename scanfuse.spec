# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path

project_dir = Path(SPEC).resolve().parent
a = Analysis(
    [str(project_dir / 'scanfuse' / 'cli.py')],
    pathex=[str(project_dir)],
    binaries=[],
    datas=[(str(project_dir / 'scanfuse' / 'templates'), 'scanfuse/templates')],
    hiddenimports=['yaml', 'markdown.extensions.tables', 'markdown.extensions.fenced_code'],
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
    a.binaries,
    a.datas,
    [],
    name='scanfuse',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
