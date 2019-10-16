# windbgtool

This is a WinDbg Toolbox package. This tool runs more complicated operations based upon PyKD package.

# Installation
### Python 3.x

* Install python 3.x on the target system from [python home page](http://python.org)

### PyKD

1. Install pip if it is not installed

```
wget https://bootstrap.pypa.io/get-pip.py
python get-pip.py
```
    
2. Copy pykd.dll to Windbg Winext folder

```
copy pykd.dll "%ProgramFiles%\Debugging Tools for Windows (x64)\winext"
copy pykd.dll "%ProgramFiles%\Debugging Tools for Windows (x86)\winext"
```
# Path Issue
Copy ext dlls to C:\Python27\Lib\site-packages\pykd

```
copy "%ProgramFiles%\Debugging Tools for Windows (x64)\Wow64" C:\Python27\Lib\site-packages\pykd
copy "%ProgramFiles%\Debugging Tools for Windows (x64)\Wow64\exts" C:\Python27\Lib\site-packages\pykd
copy "%ProgramFiles%\Debugging Tools for Windows (x86)\winext" C:\Python27\Lib\site-packages\pykd
```

3. Run following command to verify pykd
    0:000> .load pykd

4. Intall PyKD
    0:000> !pykd.install

### pyvex

```
pip install pyvex
pip install cffi
pip install archinfo
```

#### capstone

```
pip install capstone
```
