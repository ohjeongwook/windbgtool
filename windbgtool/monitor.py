import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import re
import time
import json
import pprint
import logging
import base64

import pykd
import windbgtool.debugger

class Dumper:
    def __init__(self, def_filename = 'windef.json'):
        self.windef = {}
        if not os.path.isfile(def_filename):
            def_filename = os.path.join(os.path.dirname(os.path.realpath(__file__)), def_filename)

        if os.path.isfile(def_filename):
            with open(def_filename, 'r') as fd:
                self.windef = json.load(fd)

        self.debugger = windbgtool.debugger.DbgEngine()
        self.arch = self.debugger.get_arch()

    def get_arguments(self, count):
        arguments = []
        if self.arch == 'AMD64':
            arguments.append(pykd.reg('rcx'))
            count -= 1

            if count > 0:
                arguments.append(pykd.reg('rdx'))
                count -= 1

            if count > 0:
                arguments.append(pykd.reg('r8'))
                count -= 1

            if count > 0:
                arguments.append(pykd.reg('r9'))
                count -= 1

            if count > 0:
                rsp = pykd.reg('rsp')
                arguments += pykd.loadQWords(int(rsp + 8), count)
        else:
            pass

        return arguments

    def dump_stack(self, length):
        if self.arch == 'AMD64':
            print(pykd.dbgCommand("dqs rsp L%d" % (length)))
        else:
            print(pykd.dbgCommand("dqs esp L%d" % (length)))

    def dump_arguments(self, function_def):
        index = 0
        arguments = self.get_arguments(len(function_def['arg_types']))
        for arg_type in function_def['arg_types']:
            name = function_def['arg_names'][index][1]
            print(arg_type + ' ' + name)
            argument = arguments[index]
            if arg_type == 'c_wchar_p':                
                print('\t' + self.debugger.get_wide_string(argument))
            else:
                print('\t' + hex(argument))
            index += 1

    def dump_function(self, function_name):
        if function_name in self.windef['functions']:
            function_def = self.windef['functions'][function_name]
            print('# %s' % function_name)
            self.dump_arguments(function_def)

class Breakpoints:
    def __init__(self, def_filename = 'windef.json'):
        self.debugger = windbgtool.debugger.DbgEngine()
        self.breakpoints_map = {}       
        self.return_breakpoints_map = {}
        self.dumper = Dumper(def_filename)

    def handle_breakpoint(self):
        address = self.debugger.get_instruction_pointer()
        if address in self.breakpoints_map:
            print('address: %x' % address)
            pprint.pprint(self.breakpoints_map[address])

            symbol = self.breakpoints_map[address]['symbol']
            function_name = symbol.split('!')[-1]
            self.dumper.dump_function(function_name)
        else:
            print(self.debugger.find_symbol(address))
        print('')

    def __add_breakpoint(self, address):
        if not address in self.breakpoints_map:
            self.breakpoints_map[address] = {}
        self.breakpoints_map[address]['bp'] = pykd.setBp(address, self.handle_breakpoint)

    def __del__(self):
        self.clear()

    def clear(self):
        for (addr, bp) in self.breakpoints_map.items():
            bp.remove()
            del self.breakpoints_map[addr]
            
    def add(self, symbol, handler = None):
        address = self.debugger.resolve_symbol(symbol)       
        if address > 0:
            self.__add_breakpoint(address)
            self.breakpoints_map[address]['symbol'] = symbol
