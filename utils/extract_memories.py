import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

if __name__ == '__main__':
    import pprint
    import traceback
    import windbgtool.debugger
    import windbgtool.breakpoints

    dump_filename = sys.argv[1]

    debugger = windbgtool.debugger.DbgEngine()

    #debugger.set_log_level(debug = True)
    debugger.load_dump(dump_filename)
    debugger.set_symbol_path()
    debugger.enumerate_modules()
    # debugger.load_symbols(['kernel32', 'ntdll'])
    
    for address in debugger.get_address_list():
        if address['State'] in ('MEM_FREE', 'MEM_RESERVE') or address['Usage'] == 'Free':
            continue

        if address['Usage'] != 'Image':
            continue


        print('='*80)
        print("Address %.8x ~ %.8x (size: %.8x) - [%s] %s" % (
                                                            address['BaseAddr'], 
                                                            address['BaseAddr']+address['RgnSize'], 
                                                            address['RgnSize'], 
                                                            address['Usage'], 
                                                            address['Comment']
                                                        )
                                                    )
        print('')

        if debugger:
            dmp_filename = '%x.dmp' % (address['BaseAddr'])
            try:
                debugger.run_command(".writemem %s %x L?%x" % (dmp_filename, address['BaseAddr'], address['RgnSize']))
            except:
                printf("* Writemem failed")
                traceback.print_exc(file = sys.stdout)
