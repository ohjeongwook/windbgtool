# windbgtool

This is a WinDbg Toolbox package. This tool runs more complicated operations based upon PyKD package.

# Installation
### Python 3.x

* Install python 3.x on the target system from [python home page](http://python.org)

* Install pip if it is not installed

```
wget https://bootstrap.pypa.io/get-pip.py
python get-pip.py
```

* Install dependencies:

```
pip install pyvex
pip install cffi
pip install archinfo
pip install capstone
pip install pykd
```

### PyKD from WinDbg
   
2. Copy pykd.dll to Windbg Winext folder

```
copy pykd.dll "%ProgramFiles%\Debugging Tools for Windows (x64)\winext"
```

```
copy pykd.dll "%ProgramFiles%\Debugging Tools for Windows (x64)\Wow64\winext"
```

```
copy pykd.dll "%ProgramFiles%\Debugging Tools for Windows (x86)\winext"
```

# PyKD + WinDbg Integration

1. Locate Python installation folder.

```
%LOCALAPPDATA%\Programs\Python\Python37-32\python.exe
```

2. Locate pykd site-packages folder:

```
%LOCALAPPDATA%\Programs\Python\Python37-32\Lib\site-packages\pykd
```

Copy ext dlls to C:\Python27\Lib\site-packages\pykd

```
copy "%ProgramFiles%\Debugging Tools for Windows (x64)\winext" C:\Python27\Lib\site-packages\pykd
```

```
copy "%ProgramFiles%\Debugging Tools for Windows (x64)\Wow64\exts" %LOCALAPPDATA%\Programs\Python\Python37-32\Lib\site-packages\pykd
```


```
copy "%ProgramFiles%\Debugging Tools for Windows (x86)\winext" %LOCALAPPDATA%\Programs\Python\Python37-32\Lib\site-packages\pykd
```

3. Run following command to verify pykd
    0:000> .load pykd

4. Intall PyKD, if ".load pykd" command fails
    0:000> !pykd.install
