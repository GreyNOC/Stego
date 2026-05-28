# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['greynoc_stego_extractor_app.pyw'],
    pathex=[],
    binaries=[],
    datas=[
        ('assets/greynoc_app_icon.png', 'assets'),
        ('assets/greynoc_brand.png', 'assets'),
        ('assets/greynoc_globe_256.png', 'assets'),
    ],
    hiddenimports=[],
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
    name='GreyNOCStegoExtractor',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    icon='assets/greynoc_app.ico',
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
