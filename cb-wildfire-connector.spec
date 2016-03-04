# -*- mode: python -*-
a = Analysis(['scripts/cb-wildfire-connector'],
             pathex=['.'],
             hiddenimports=['unicodedata'],
             hookspath=None,
             runtime_hooks=None)
pyz = PYZ(a.pure)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          exclude_binaries=True,
          name='cb-wildfire-connector',
          debug=False,
          strip=None,
          upx=True,
          console=True )
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=None,
               upx=True,
               name='cb-wildfire-connector')