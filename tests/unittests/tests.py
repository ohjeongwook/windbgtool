import os
import sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../..'))

import pprint
import json

import windbgtool.debugger
import windbgtool.breakpoints

import unittest

class tests(unittest.TestCase):
    def setUp(self):
        dump_filename = r'../test_files/notepad.dmp'
        self.dbg_engine = windbgtool.debugger.DbgEngine(use_command_mode = False)
        self.dbg_engine.load_dump(dump_filename)
        self.dbg_engine.set_symbol_path()

        self.test_load_symbols_filename = 'test_load_symbols.json'
        self.test_enumerate_modules_filename = 'test_enumerate_modules.json'
        self.test_get_address_list_filename = 'test_get_address_list.json'

    def tearDown(self):
        pass

    def test_get_arch(self):
        assert str(self.dbg_engine.get_arch()) == 'AMD64', 'get_arch(): %s' % self.dbg_engine.get_arch()

    def test_resolve_symbol(self):
        symbols_and_address_pairs = (
            ('kernel32.dll!CreateFileW', 0x7ffb22bdf7b0), 
            ('kernel32!CreateFileW', 0x7ffb259e1d30),
            ('CreateFileW', 0x7ffb22bdf7b0),
        )

        for (symbol, address) in symbols_and_address_pairs:
            resolved_address = self.dbg_engine.resolve_symbol(symbol)
            assert(address == resolved_address)

    def test_get_bytes(self):
        resolved_address = self.dbg_engine.resolve_symbol('kernel32!CreateFileW')
        read_bytes = self.dbg_engine.get_bytes(resolved_address, 10)
        assert(read_bytes == b'\xff%zm\x05\x00\xcc\xcc\xcc\xcc')

    def test_get_wide_string(self):
        wide_string = self.dbg_engine.get_wide_string(0x00007FF6A44DDD50)
        assert(wide_string == 'Security-SPP-GenuineLocalStatus')

    def test_get_module_names(self):
        self.dbg_engine.use_command_mode = False
        get_module_names1 = self.dbg_engine.get_module_names()
        self.dbg_engine.use_command_mode = True
        get_module_names2 = self.dbg_engine.get_module_names()

        get_module_names1.sort()
        get_module_names2.sort()

        assert(get_module_names1 == get_module_names2)

    def load_address_to_symbol_file(self, filename):
        address_to_symbols = {}
        with open(filename, 'r') as fd:
            for (address, symbol) in json.load(fd).items():
                address_to_symbols[int(address)] = symbol
        return address_to_symbols

    def test_load_symbols_in_command_mode(self):
        self.dbg_engine.use_command_mode = True
        self.dbg_engine.enumerate_modules()
        self.dbg_engine.reset_symbols()
        self.dbg_engine.load_symbols(['kernel32'])

        test_filename = 'test_load_symbols_in_command_mode.json'
        if not os.path.isfile(test_filename):
            with open(test_filename, 'w') as fd:
                json.dump(self.dbg_engine.address_to_symbols, fd, indent = 4)

        orig_address_to_symbols = self.load_address_to_symbol_file(test_filename)
        for (address, symbol) in self.dbg_engine.address_to_symbols.items():
            assert orig_address_to_symbols[address] == symbol, '%s vs %s' % (self.dbg_engine.address_to_symbols[address], symbol)

    def test_load_symbols(self):
        self.dbg_engine.use_command_mode = False
        self.dbg_engine.enumerate_modules()
        self.dbg_engine.reset_symbols()
        self.dbg_engine.load_symbols(module_name_patterns = ['kernel32'])

        if not os.path.isfile(self.test_load_symbols_filename):
            with open(self.test_load_symbols_filename, 'w') as fd:
                json.dump(self.dbg_engine.address_to_symbols, fd, indent = 4)

        orig_address_to_symbols =self.load_address_to_symbol_file(self.test_load_symbols_filename)

        for (addres, symbol) in orig_address_to_symbols.items():
            assert self.dbg_engine.address_to_symbols[addres] == symbol

    def test_find_symbol_in_command_mode(self):
        self.dbg_engine.use_command_mode = True
        self.dbg_engine.enumerate_modules()
        self.dbg_engine.reset_symbols()
        self.dbg_engine.load_symbols(['kernel32'])

        orig_address_to_symbols =self.load_address_to_symbol_file('test_load_symbols_in_command_mode.json')
        for address, symbol in orig_address_to_symbols.items():
            resolved_symbol = self.dbg_engine.find_symbol(address)
            assert resolved_symbol == symbol, 'Symbol mismatch: resolved_symbol: %s == symbol: %s' % (resolved_symbol, symbol)

    def test_find_symbol(self):
        self.dbg_engine.use_command_mode = False
        self.dbg_engine.enumerate_modules()
        self.dbg_engine.unload_symbols('kernel32')

        if os.path.isfile(self.test_load_symbols_filename):
            with open(self.test_load_symbols_filename, 'r') as fd:
                kernel32_symbols = json.load(fd)

                i = 0
                for address, symbol in kernel32_symbols.items():
                    resolved_symbol = self.dbg_engine.find_symbol(int(address))
                    assert(resolved_symbol == symbol)
                    i += 1

                    if i > 10:
                        break

    def xtest_resolve_symbol(self):
        self.dbg_engine.enumerate_modules()
        self.dbg_engine.reset_symbols()
        self.dbg_engine.load_symbols(['kernel32'])

        if os.path.isfile(self.test_load_symbols_filename):
            with open(self.test_load_symbols_filename, 'r') as fd:
                kernel32_symbols = json.load(fd)

                for address, symbol in kernel32_symbols.items():
                    resolved_address = self.dbg_engine.resolve_symbol('kernel32!' + symbol)
                    assert(resolved_address == address)

    def compare_module_list(self, orig_module_list, module_list):
        module_names = list(module_list.keys())
        module_names.sort()

        orig_module_names = list(orig_module_list.keys())
        orig_module_names.sort()

        assert module_names == orig_module_names

        for module_name in module_names:
            assert module_list[module_name] == orig_module_list[module_name], pprint.pformat(module_list[module_name]) + pprint.pformat(orig_module_list[module_name])

    def test_enumerate_modules(self):
        self.dbg_engine.use_command_mode = False
        module_list = self.dbg_engine.enumerate_modules()

        if not os.path.isfile(self.test_enumerate_modules_filename):
            with open(self.test_enumerate_modules_filename, 'w') as fd:
                json.dump(module_list, fd, indent = 4)

        with open(self.test_enumerate_modules_filename, 'r') as fd:
            orig_module_list = json.load(fd)
            self.compare_module_list(orig_module_list, module_list)

    def test_enumerate_modules_in_command_mode(self):
        self.dbg_engine.use_command_mode = True
        module_list = self.dbg_engine.enumerate_modules()

        with open(self.test_enumerate_modules_filename, 'r') as fd:
            orig_module_list = json.load(fd)
            self.compare_module_list(orig_module_list, module_list)            

    def test_get_address_list(self):
        self.dbg_engine.use_command_mode = False
        self.dbg_engine.enumerate_modules()
        self.dbg_engine.reset_symbols()
        self.dbg_engine.load_symbols(['kernel32', 'ntdll'])
        address_list = self.dbg_engine.get_address_list()

        if not os.path.isfile(self.test_get_address_list_filename):
            with open(self.test_get_address_list_filename, 'w') as fd:
                json.dump(address_list, fd, indent = 4)

        with open(self.test_get_address_list_filename, 'r') as fd:
            orig_address_list = json.load(fd)

            for i in range(0, len(address_list), 1):
                assert(address_list[i]['BaseAddr'] == orig_address_list[i]['BaseAddr'])
                assert(address_list[i]['EndAddr'] == orig_address_list[i]['EndAddr'])
                assert(address_list[i]['RgnSize'] == orig_address_list[i]['RgnSize'])
                assert(address_list[i]['Type'] == orig_address_list[i]['Type'])
                assert(address_list[i]['State'] == orig_address_list[i]['State'])
                assert(address_list[i]['Protect'] == orig_address_list[i]['Protect'])
                assert(address_list[i]['Usage'] == orig_address_list[i]['Usage'])

if __name__ == "__main__":
    unittest.main()

