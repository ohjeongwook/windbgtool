import windbgtool.debugger
import windbgtool.breakpoints

if __name__ == '__main__':
    dbg_engine = windbgtool.debugger.DbgEngine()
    dbg_engine.run(executable_path = 'notepad.exe')
    dbg_engine.set_symbol_path()
    dbg_engine.enumerate_modules()
    dbg_engine.load_symbols(['kernel32'])

    breakpointsOperations = windbgtool.breakpoints.Operations(dbg_engine)
    breakpointsOperations.add_symbol_bp('kernel32', 'CreateFileA', [])
    breakpointsOperations.add_symbol_bp('kernel32', 'CreateFileW', [])

    dbg_engine.go()
