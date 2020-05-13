import os
import sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../..'))

import windbgtool.debugger
import windbgtool.breakpoints

if __name__ == '__main__':
    import pprint

    dump_filename = sys.argv[1]

    dbg_engine = windbgtool.debugger.DbgEngine()

    #dbg_engine.set_log_level(debug = True)
    dbg_engine.load_dump(dump_filename)
    dbg_engine.set_symbol_path()
    dbg_engine.enumerate_modules()
    dbg_engine.load_symbols(['kernel32', 'ntdll'])

    for address in dbg_engine.get_address_list():
        print('> BaseAddress: ' + hex(address['BaseAddr']) + ' Comments: ' + address['Comment'])
