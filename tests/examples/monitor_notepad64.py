import os
import sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../..'))

import windbgtool.debugger
import windbgtool.monitor

if __name__ == '__main__':
    debugger = windbgtool.debugger.DbgEngine()
    debugger.run(executable_path = r'c:\windows\notepad.exe')
    debugger.set_symbol_path()
    debugger.enumerate_modules()
    debugger.load_symbols(['kernel32'])

    monitor_breakpoints = windbgtool.monitor.Breakpoints()
    api_list = [
        'kernel32!CreateFileA', 'kernel32!CreateFileW', 'KERNELBASE!CreateFileA', 'KERNELBASE!CreateFileW',
        'kernel32!WriteFile', 'KERNELBASE!WriteFile',
        "KERNELBASE!RegQueryValueExA", "KERNELBASE!RegQueryValueExW", "KERNELBASE!RegOpenKeyExA", "KERNELBASE!RegOpenKeyExW", "KERNELBASE!RegCreateKeyExA", 
        "KERNELBASE!RegCreateKeyExW", "KERNELBASE!RegGetValueA", "KERNELBASE!RegGetValueW", "KERNELBASE!RegCloseKey", "KERNELBASE!RegSetValueExW", "KERNELBASE!RegSetValueExA",
        "KERNELBASE!RegSetKeyValueA", "KERNELBASE!RegSetKeyValueW", "KERNELBASE!RegEnumKeyExA", "KERNELBASE!RegEnumKeyExW", "KERNELBASE!RegGetKeySecurity",
        "KERNELBASE!RegQueryInfoKeyA", "KERNELBASE!RegQueryInfoKeyW", "KERNELBASE!RegDeleteKeyValueW", "KERNELBASE!RegDeleteKeyValueA", "KERNELBASE!RegDeleteKeyExA",
        "KERNELBASE!RegDeleteKeyExW", "KERNELBASE!RegDeleteValueA", "KERNELBASE!RegDeleteValueW", "KERNELBASE!RegEnumValueA", "KERNELBASE!RegEnumValueW", "KERNELBASE!RegDeleteTreeA", "KERNELBASE!RegDeleteTreeW"
    ]

    for api in api_list:
        monitor_breakpoints.add(api)
    
    while True:
        debugger.go()

