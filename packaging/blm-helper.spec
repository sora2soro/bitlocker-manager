# PyInstaller spec for the BitLocker Manager Unlock Helper.
# Build (on Windows):  pyinstaller packaging\blm-helper.spec
# Output:              dist\blm-helper.exe   (a single self-contained file)
#
# The helper is pure standard-library Python, so there are no third-party
# hidden imports to chase. This produces one .exe that needs no Python on the
# target PC.

block_cipher = None

a = Analysis(
    ['..\\agent\\unlock-helper.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    name='blm-helper',
    console=False,         # windowless: no console pops up. Startup/errors go to
                           # %LOCALAPPDATA%\BLMHelper\helper.log instead.
    onefile=True,
    upx=False,
    icon=None,             # add 'blm.ico' here if you want a custom icon
)
