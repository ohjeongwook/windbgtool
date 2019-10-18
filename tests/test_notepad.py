import windbgtool.debugger
import windbgtool.breakpoints

if __name__ == '__main__':
    dbg_engine = windbgtool.debugger.DbgEngine()
    dbg_engine.Run(executable_path = 'notepad.exe')
    dbg_engine.SetSymbolPath()
    dbg_engine.EnumerateModules()
    dbg_engine.LoadSymbols(['kernel32'])

    breakpointsOperations = windbgtool.breakpoints.Operations(dbg_engine)
    breakpointsOperations.AddSymbolBP('kernel32', 'CreateFileA', [])
    breakpointsOperations.AddSymbolBP('kernel32', 'CreateFileW', [])

    dbg_engine.Go()
