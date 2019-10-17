# windbgtool

This is a WinDbg Toolbox package. This tool runs more complicated operations based upon PyKD package.

# Installation
## Python 3.x

* Install python 3.x on the target system from [Python Releases for Windows](https://www.python.org/downloads/windows/)

* Install pip if it is not installed

```
wget https://bootstrap.pypa.io/get-pip.py
python get-pip.py
```

## Python Modules
* Install dependencies:

```
pip install pyvex
pip install archinfo
pip install capstone
pip install pykd
```

##
pip install cffi


## PyKD + WinDbg Integration

1. Locate Python installation folder.

```
%LOCALAPPDATA%\Programs\Python\Python37-32\python.exe
```

2. Locate pykd site-packages folder:

```
%LOCALAPPDATA%\Programs\Python\Python37-32\Lib\site-packages\pykd
```

3. Locate WinDbg extension folders

64 bit WinDbg Installation:
> "%ProgramFiles%\Debugging Tools for Windows (x64)\winext"

32 bit WinDbg in 64 bit WinDbg Installation:
> "%ProgramFiles%\Debugging Tools for Windows (x64)\Wow64\winext"

32 bit WinDbg Installation:
> "%ProgramFiles%\Debugging Tools for Windows (x86)\winext"

### PyKD from WinDbg

Install [pykd-ext](https://githomelab.ru/pykd/pykd-ext) to run [pykd](https://githomelab.ru/pykd/pykd) from WinDbg prompt.

1. Download [last version](https://githomelab.ru/pykd/pykd-ext/wikis/Downloads)   
2. Copy pykd.dll to Windbg winext folder

```
copy x64\pykd.dll "%ProgramFiles%\Debugging Tools for Windows (x64)\winext"
```

```
copy x86\pykd.dll "%ProgramFiles%\Debugging Tools for Windows (x64)\Wow64\winext"
```

```
copy x86\pykd.dll "%ProgramFiles%\Debugging Tools for Windows (x86)\winext"
```

3. Run following command to verify pykd

```
0:000> .load pykd
```

The following command will show the current Python interpreter in use.

```
0:005> !pykd.info

pykd bootstrapper version: 2.0.0.22

Installed python:

Version:        Status:     Image:
------------------------------------------------------------------------------
* 3.7 x86-32    Unloaded    C:\Users\tester\AppData\Local\Programs\Python\Python37-32\python37.dll
```

4. Intall PyKD, if ".load pykd" command fails

```
0:000> !pykd.install
```

### PyKD

Copy ext dlls to C:\Python27\Lib\site-packages\pykd

```
copy "%ProgramFiles%\Debugging Tools for Windows (x64)\winext" %LOCALAPPDATA%\Programs\Python\Python37\Lib\site-packages\pykd
```

```
copy "%ProgramFiles%\Debugging Tools for Windows (x64)\Wow64\exts" %LOCALAPPDATA%\Programs\Python\Python37-32\Lib\site-packages\pykd
```


```
copy "%ProgramFiles%\Debugging Tools for Windows (x86)\winext" %LOCALAPPDATA%\Programs\Python\Python37-32\Lib\site-packages\pykd
```

