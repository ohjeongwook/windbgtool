import os
import sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../..'))

import windbgtool.debugger
import windbgtool.monitor

if __name__ == '__main__':
    debugger = windbgtool.debugger.DbgEngine()
    debugger.run(executable_path = 'notepad.exe')
    debugger.set_symbol_path()
    debugger.enumerate_modules()
    debugger.load_symbols(['kernel32'])

    monitor_breakpoints = windbgtool.monitor.Breakpoints()
    monitor_breakpoints.add('kernel32!CreateFileA')
    monitor_breakpoints.add('kernel32!CreateFileW')
    monitor_breakpoints.add('kernelbase!CreateFileA')
    monitor_breakpoints.add('kernelbase!CreateFileW')
    monitor_breakpoints.add('kernel32!WriteFile')
    monitor_breakpoints.add('kernelbase!WriteFile')
    
    debugger.go()

