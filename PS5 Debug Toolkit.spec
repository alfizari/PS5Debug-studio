# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

datas = [('assets', 'assets')]
binaries = []
hiddenimports = ['aes_cbc', 'aob', 'app_paths', 'asmgen', 'bulk_items', 'cheats', 'cheats_editor_tab', 'cheats_play_tab', 'cheats_store', 'cheats_tab', 'cheat_export', 'cheat_export_dialog', 'cheat_formats', 'cheat_pack', 'cheat_recorder', 'cheat_tools', 'codecave', 'codecave_dialog', 'debugger_core', 'debugger_tab', 'disasm', 'disasm_view', 'disassembler_tab', 'func_logger', 'func_logger_window', 'hex_view', 'items', 'klog_tab', 'pointer_scan', 'pointer_scan_dialog', 'projects', 'ps5debug_client', 'scanner_tab', 'script_api', 'script_window', 'scrollable', 'theme', 'unwind', 'numpy']
tmp_ret = collect_all('capstone')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('keystone')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]


a = Analysis(
    ['gui.py'],
    pathex=['.'],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['shnext_decryptor', 'shnext_bridge', 'player', 'unicorn', 'matplotlib', 'pandas', 'scipy', 'PyQt5', 'PySide6', 'IPython'],
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
    name='PS5 Debug Toolkit',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['assets/icon.ico'],
)
