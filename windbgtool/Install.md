# Installation
1. Install python 2.7 on the target system
2. Copy python27.dll to %SystemRoot%
3. Install pip
    wget https://bootstrap.pypa.io/get-pip.py
    python get-pip.py
    
4. Copy pykd.dll to Windbg Winext folder
    copy pykd.dll "%ProgramFiles%\Debugging Tools for Windows (x64)\winext"
    copy pykd.dll "%ProgramFiles%\Debugging Tools for Windows (x86)\winext"
    
5. Run following command to verify pykd
    0:000> .load pykd

6. Intall PyKD
    0:000> !pykd.install

7. Dependencies
    Copy Disasm    
        Copy pyvex to target folder ( Bin\Pyvex\x86 )
            pip install cffi
            pip install archinfo
    Copy Util   
    Copy WinDBG\*.py

# Path Issue
Copy ext dlls to C:\Python27\Lib\site-packages\pykd
    copy "%ProgramFiles%\Debugging Tools for Windows (x64)\Wow64" C:\Python27\Lib\site-packages\pykd
    copy "%ProgramFiles%\Debugging Tools for Windows (x64)\Wow64\exts" C:\Python27\Lib\site-packages\pykd
    copy "%ProgramFiles%\Debugging Tools for Windows (x86)\winext" C:\Python27\Lib\site-packages\pykd