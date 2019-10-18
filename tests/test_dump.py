import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import windbgtool.debugger
import windbgtool.breakpoints

if __name__ == '__main__':
    import pprint

    dump_filename = sys.argv[1]

    dbg_engine = windbgtool.debugger.DbgEngine()

    #dbg_engine.SetLogLevel(debug = True)
    dbg_engine.LoadDump(dump_filename)
    dbg_engine.SetSymbolPath()
    dbg_engine.EnumerateModules()
    dbg_engine.LoadSymbols(['kernel32', 'ntdll'])

    for address in dbg_engine.GetAddressList():
        print(address['Comment'] + ': ' + hex(address['BaseAddr']))
