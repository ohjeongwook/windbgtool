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

class Logger:
    def __init__(self, windows_api_filename = 'windows_api.json'):
        self.windows_api = {}
        if not os.path.isfile(windows_api_filename):
            windows_api_filename = os.path.join(os.path.dirname(os.path.realpath(__file__)), windows_api_filename)

        print('Loading ' + windows_api_filename)
        if os.path.isfile(windows_api_filename):
            self.load_windows_api_defs(windows_api_filename)

        self.debugger = windbgtool.debugger.DbgEngine()

    def load_windows_api_defs(self, filename):
        with open(filename, 'r') as fd:
            self.windows_api = json.load(fd)

        self.functions = {}
        for funcdef in self.windows_api['funcdefs']:
            if 'name' in funcdef['type']:
                name = funcdef['type']['name']
                self.functions[name] = funcdef

    def find_function(self, name):
        if name in self.functions:
            return self.functions[name]

    def get_arguments(self, count):
        arguments = []
        if self.debugger.get_arch() == 'AMD64':
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
            esp = pykd.reg('esp')
            arguments += pykd.loadDWords(int(esp + 4), count)

        return arguments

    def dump_stack(self, length):
        if self.debugger.get_arch() == 'AMD64':
            print(pykd.dbgCommand("dqs rsp L%d" % (length)))
        else:
            print(pykd.dbgCommand("dqs esp L%d" % (length)))

    def log_arguments(self, function_def):
        index = 0
        argument_values = self.get_arguments(len(function_def['arguments']))
        for argument in function_def['arguments']:
            if 'name' in argument:
                print('name: ' + argument['name'])

            argument_value = argument_values[index]
            print('\t' + hex(argument_value))

            if argument['type'] in ('LPCWSTR', 'LPWSTR'):
                if argument_value != 0:
                    try:
                        print('\t' + self.debugger.get_wide_string(argument_value))
                    except:
                        print('\tException to read memory')

            elif argument['type'] in ('LPCSTR', 'LPSTR'):
                if argument_value != 0:
                    try:
                        print('\t' + self.debugger.get_string(argument_value))
                    except:
                        print('\tException to read memory')
                
            index += 1

    def log_function(self, symbol):
        if symbol.find('!') > 0:
            function_name = symbol.split('!')[1]
        else:
            function_name = symbol

        if function_name.endswith('Stub'):
            function_name = function_name[0:-4]

        function_def = self.find_function(function_name)
        print('# %s' % function_name)

        if function_def is not None:
            self.log_arguments(function_def)


class ModuleLoadHandler(pykd.eventHandler):
    def __init__(self, modload_handler):
        pykd.eventHandler.__init__(self)
        self.modload_handler = modload_handler

    def onLoadModule(self, base_address, name):
        #print("onLoadModule: %s at 0x%x" % (name, base_address))
        self.modload_handler(name, base_address)
        return pykd.executionStatus.Break

class Breakpoints:
    def __init__(self, def_filename = 'windows_api.json'):
        self.debugger = windbgtool.debugger.DbgEngine()
        self.breakpoints_map = {}
        self.return_breakpoints_map = {}
        self.unresolved_symbols = []

        self.logger = Logger(def_filename)
        self.modload_handler = ModuleLoadHandler(self.modload_handler)

    def handle_breakpoint(self):
        address = self.debugger.get_instruction_pointer()
        if address in self.breakpoints_map:
            print('address: %x' % address)

            symbol = self.breakpoints_map[address]['symbol']
            function_name = symbol.split('!')[-1]
            self.logger.log_function(function_name)
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
            print('Setting breakpoint for %s (%x)' % (symbol, address))
            self.__add_breakpoint(address)
            self.breakpoints_map[address]['symbol'] = symbol
            return True
        else:
            if not symbol in self.unresolved_symbols:
                self.unresolved_symbols.append(symbol)
            print('Can\'t resolve %s' % (symbol))
            return False

    def modload_handler(self, module_name, base_address):
        print('modload_handler: %s' % module_name)
        for symbol in self.unresolved_symbols:
            if symbol.lower().startswith(module_name.lower()):
                self.add(symbol)

if __name__ == '__main__':
    logger = Logger()
    create_process_a_def = logger.find_function('CreateProcessA')
    pprint.pprint(create_process_a_def)

    create_process_a_def = logger.find_function('CreateProcessW')
    pprint.pprint(create_process_a_def)    