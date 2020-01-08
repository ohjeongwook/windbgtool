# PyKD + WinDbg Integration Issue Fixes

* There are some compatibility issues with existing PyKD DLL distributions. This is how you can fix it.

1. Locate Python installation folder.

Ex)

```
%LOCALAPPDATA%\Programs\Python\Python37-32\python.exe
```

2. Locate pykd site-packages folder:

Ex)

```
%LOCALAPPDATA%\Programs\Python\Python37-32\Lib\site-packages\pykd
```

3. Locate WinDbg extension folders

* 64 bit WinDbg Installation:
   > "%ProgramFiles%\Debugging Tools for Windows (x64)\winext"

* 32 bit WinDbg in 64 bit WinDbg Installation:
   > "%ProgramFiles%\Debugging Tools for Windows (x64)\Wow64\winext"

* 32 bit WinDbg Installation:
   > "%ProgramFiles%\Debugging Tools for Windows (x86)\winext"

## PyKD from WinDbg

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

## PyKD

* Source folder:
64 bits:
"%ProgramFiles(x86)%\Windows Kits\10\Debuggers\x64"
"%ProgramFiles%\Windows Kits\10\Debuggers\x64"
"%ProgramFiles%\Debugging Tools for Windows (x64)"

32 bits:
"%ProgramFiles(x86)%\Windows Kits\10\Debuggers\x86"
"%ProgramFiles%\Debugging Tools for Windows (x64)\Wow64"

* Target folders:

64 bits:
C:\python27-x64\Lib\site-packages\pykd
%LOCALAPPDATA%\Programs\Python\Python37\Lib\site-packages\pykd

32 bits:
C:\Python27\Lib\site-packages\pykd
%LOCALAPPDATA%\Programs\Python\Python37-32\Lib\site-packages\pykd

* Files

```
dbgeng.dll
dbghelp.dll
DbgModel.dll
msdia140.dll 
srcsrv.dll
symsrv.dll
winext\*.dll
```
