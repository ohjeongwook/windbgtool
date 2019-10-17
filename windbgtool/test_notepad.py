import debugger

if __name__ == '__main__':
    dbg_engine = debugger.DbgEngine()
    dbg_engine.Run(executable_path = 'notepad.exe')
    dbg_engine.SetSymbolPath()
    dbg_engine.EnumerateModules()
    dbg_engine.LoadSymbols(['kernel32'])
    def breakpointHandler():
        print('breakpointHandler:')

    dbg_engine.AddSymbolBP('kernel32','CreateFileA',[])
    dbg_engine.AddSymbolBP('kernel32','CreateFileW',[])
    dbg_engine.Go()
