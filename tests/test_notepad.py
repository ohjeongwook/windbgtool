import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import windbgtool.debugger
import windbgtool.breakpoints

if __name__ == '__main__':
    dbg_engine = windbgtool.debugger.DbgEngine()
    dbg_engine.run(executable_path = 'notepad.exe')
    dbg_engine.set_symbol_path()
    dbg_engine.enumerate_modules()
    dbg_engine.load_symbols(['kernel32'])


    def handler():
        eip = dbg_engine.get_instruction_pointer()
        print('handler: %x' % eip)
        print(dbg_engine.run_command("dt _PEB"))
        print(dbg_engine.run_command("r"))
        print(dbg_engine.run_command("dqs fs:00"))

    breakpoint_operations = windbgtool.breakpoints.Operations(dbg_engine)
    breakpoint_operations.add_symbol_bp('kernel32', 'CreateFileA', [], handler = handler)
    breakpoint_operations.add_symbol_bp('kernel32', 'CreateFileW', [], handler = handler)

    dbg_engine.go()
