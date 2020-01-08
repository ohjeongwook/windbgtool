# WinDbgTool

This is a WinDbg Toolbox package. This tool runs more complicated operations based upon PyKD package.

## Installation

1. Install [WinDbg](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/)

2. Run pip to install windbgtool from this repository:

```
pip install git+https://github.com/ohjeongwook/windbgtool --upgrade
```

3. PyKD has some issues with DLL package distribution.
   * Run following command to fix PyKD WinDbg dependencies on the target machine
   
```
python -m pykdfix.fix_windbg_files
```

