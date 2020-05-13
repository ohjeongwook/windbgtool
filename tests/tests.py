import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import pprint
import json

import windbgtool.debugger
import windbgtool.breakpoints

import unittest

class NotepadTests(unittest.TestCase):
    def setUp(self):
        dump_filename = r'test_files/notepad.dmp'
        self.dbg_engine = windbgtool.debugger.DbgEngine(use_command_mode = False)
        #dbg_engine.set_log_level(debug = True)        
        self.dbg_engine.load_dump(dump_filename)
        self.dbg_engine.set_symbol_path()

    def tearDown(self):
        pass

    def test_get_arch(self):
        assert(self.dbg_engine.get_arch() == 'AMD64', "get_arch changed")

    def test_get_bytes(self):
        resolved_address = self.dbg_engine.resolve_symbol('kernel32!CreateFileW')
        read_bytes = self.dbg_engine.get_bytes(resolved_address, 10)
        assert(read_bytes == b'\xff%zm\x05\x00\xcc\xcc\xcc\xcc', "test_get_bytes failed")

    def test_get_wide_string(self):
        wide_string = self.dbg_engine.get_wide_string(0x00007FF6A44DDD50)
        assert(wide_string == 'Security-SPP-GenuineLocalStatus', "test_get_wide_string failed")        

    def test_get_module_names(self):
        self.dbg_engine.use_command_mode = False
        get_module_names1 = self.dbg_engine.get_module_names()
        self.dbg_engine.use_command_mode = True
        get_module_names2 = self.dbg_engine.get_module_names()

        get_module_names1.sort()
        get_module_names2.sort()

        assert(get_module_names1 == get_module_names2, "test_get_module_list failed")

    def test_enumerate_module_symbols_in_command_mode(self):
        self.dbg_engine.use_command_mode = True
        self.dbg_engine.enumerate_modules()
        self.dbg_engine.load_symbols(['kernel32'])

        test_filename = 'test_enumerate_module_symbols.json'
        if not os.path.isfile(test_filename):
            with open(test_filename, 'w') as fd:
                json.dump(self.dbg_engine.address_to_symbols, fd, indent = 4)
            pprint.pprint(self.dbg_engine.address_to_symbols)

        with open(test_filename, 'r') as fd:
            orig_address_to_symbols = json.load(fd)
            assert(self.dbg_engine.address_to_symbols == orig_address_to_symbols, "kernel32_symbols changed")

    def test_enumerate_module_symbols(self):
        self.dbg_engine.use_command_mode = False
        self.dbg_engine.enumerate_modules()
        self.dbg_engine.load_symbols(module_name_patterns = ['kernel32'])

        test_filename = 'test_enumerate_module_symbols.json'
        if not os.path.isfile(test_filename):
            with open(test_filename, 'w') as fd:
                json.dump(self.dbg_engine.address_to_symbols, fd, indent = 4)
            pprint.pprint(self.dbg_engine.address_to_symbols)

        with open(test_filename, 'r') as fd:
            orig_address_to_symbols = json.load(fd)
            assert(self.dbg_engine.address_to_symbols == orig_address_to_symbols, "kernel32_symbols changed")

    def test_find_symbol(self):
        self.dbg_engine.enumerate_modules()
        self.dbg_engine.load_symbols(['kernel32'])

        test_filename = 'test_enumerate_module_symbols.json'
        if os.path.isfile(test_filename):
            with open(test_filename, 'r') as fd:
                kernel32_symbols = json.load(fd)

                for address, symbol in kernel32_symbols.items():
                    resolved_symbol = self.dbg_engine.find_symbol(int(address))
                    assert(resolved_symbol == symbol, "resolve_symbol failed: %s" % symbol)       

    def test_resolve_symbol_find_symbol(self):
        self.dbg_engine.use_command_mode = False
        self.dbg_engine.enumerate_modules()
        self.dbg_engine.unload_symbols('kernel32')

        test_filename = 'test_enumerate_module_symbols.json'
        if os.path.isfile(test_filename):
            with open(test_filename, 'r') as fd:
                kernel32_symbols = json.load(fd)

                i = 0
                for address, symbol in kernel32_symbols.items():
                    resolved_symbol = self.dbg_engine.find_symbol(int(address))
                    assert(resolved_symbol == symbol, "resolve_symbol failed: %s" % symbol)
                    i += 1

                    if i > 10:
                        break

    def xtest_resolve_symbol(self):
        self.dbg_engine.enumerate_modules()
        self.dbg_engine.load_symbols(['kernel32'])

        test_filename = 'test_enumerate_module_symbols.json'
        if os.path.isfile(test_filename):
            with open(test_filename, 'r') as fd:
                kernel32_symbols = json.load(fd)

                for address, symbol in kernel32_symbols.items():
                    resolved_address = self.dbg_engine.resolve_symbol('kernel32!' + symbol)
                    assert(resolved_address == address, "test_resolve_symbol failed: %s" % symbol)           

    def test_enumerate_modules(self):
        module_list = self.dbg_engine.enumerate_modules()

        test_filename = 'test_enumerate_modules.json'
        if not os.path.isfile(test_filename):
            with open(test_filename, 'w') as fd:
                json.dump(module_list, fd, indent = 4)

            pprint.pprint(module_list)

        with open(test_filename, 'r') as fd:
            orig_module_list = json.load(fd)
            assert(module_list == orig_module_list, "module_list changed")

    def test_get_address_list(self):
        self.dbg_engine.enumerate_modules()
        self.dbg_engine.load_symbols(['kernel32', 'ntdll'])
        address_list = self.dbg_engine.get_address_list()

        test_filename = 'test_get_address_list.json'
        if not os.path.isfile(test_filename):
            with open(test_filename, 'w') as fd:
                json.dump(address_list, fd, indent = 4)

            for address in self.dbg_engine.get_address_list():
                print('> BaseAddress: ' + hex(address['BaseAddr']) + ' Comments: ' + address['Comment'])

        with open(test_filename, 'r') as fd:
            orig_address_list = json.load(fd)
            assert(address_list == orig_address_list, "address_list changed")

if __name__ == "__main__":
    unittest.main()
