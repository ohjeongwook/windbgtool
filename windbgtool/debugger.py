import os
import sys
sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import re
import time
import json
import pprint
import logging
import base64

import pykd

import windbgtool.util
import windbgtool.log

class Singleton(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]

class DbgEngine(object, metaclass=Singleton):
    def __init__(self, use_command_mode = False):
        self.use_command_mode = use_command_mode
        self.module_list = {}
        self.address_to_symbols = {}
        self.symbol_to_address = {}
        self.arch = ''
        self.windbg_log_parser = windbgtool.log.Parser()
       
    def load_dump(self, dump_filename):
        pykd.loadDump(dump_filename)

    def close_dump(self):
        pykd.closeDump()

    def run(self, executable_path):
        pykd.startProcess(executable_path)

    def run_command(self, cmd):
        ret = pykd.dbgCommand(cmd)
        if ret == None:
            ret = ""

        return ret

    def get_arch(self):
        if not self.arch:
            self.arch = str(pykd.getCPUMode())
            return self.arch
        return self.arch

    def set_symbol_path(self, symbol_path = 'srv*https://msdl.microsoft.com/download/symbols', reload = True):
        output = self.run_command(".sympath+ %s" % symbol_path)
        if reload:
            output += self.run_command(".reload")
        return output

    def load_symbols(self, module_name_patterns = []):
        if self.use_command_mode:
            for module_name in self.module_list.keys():
                found = False
                if len(module_name_patterns) == 0:
                    found = True

                for module_name_pattern in module_name_patterns:
                    if self.__match_name(module_name, module_name_pattern):
                        found = True

                if not found:
                    continue

                for (address, symbol) in self.get_addresses("%s!*" % module_name).items():
                    self.address_to_symbols[address] = symbol
        else:
            for module in pykd.getModulesList():
                name = module.name()
                found = False

                if len(module_name_patterns) == 0:
                    found = True

                for module_name_pattern in module_name_patterns:
                    if self.__match_name(name, module_name_pattern):
                        found = True

                if not found:
                    continue

                for symbol, address in module.enumSymbols():
                    full_symbol = module.name() + "!" + symbol
                    self.address_to_symbols[address] = full_symbol
       
        self.symbol_to_address = {}
        for (address, symbol) in self.address_to_symbols.items():
            self.symbol_to_address[symbol] = address

    def load_address_symbol(self, address):
        address_info = self.get_address_info(address)
        if address_info and 'Module Name' in address_info:
            self.load_symbols([address_info['Module Name'],])

    def unload_symbols(self, module): 
        if module in self.address_to_symbols:
            del self.address_to_symbols[module]

    def reset_symbols(self):
        self.address_to_symbols = {}
        self.symbol_to_address = {}

    def find_symbol(self, address):
        name = ''
        if not address in self.address_to_symbols:
            self.load_address_symbol(address)

        if address in self.address_to_symbols:
            name = self.address_to_symbols[address]
        else:
            if self.use_command_mode:
                try:
                    output = pykd.dbgCommand("u %x L1" % address)
                except:
                    output = ''

                if output:
                    output_lines = output.splitlines()
                    if len(output_lines) >= 0 and output_lines[0].endswith(':'):
                        name = output_lines[0]
            else:
                name = pykd.findSymbol(address)

        return name

    def resolve_symbol(self, symbol):
        offset = 0
        if symbol.find('+') >= 0:
            addr_toks = addr_str.split("+")
            if len(addr_toks)>1:
                symbol = addr_toks[0]
                offset = windbgtool.util.convert_to_int(addr_toks[1], 16)               

        if symbol in self.symbol_to_address:
            return self.symbol_to_address[symbol] + offset

        if symbol.find("!") >= 0:
            (module_name, function_name) = symbol.split('!', 1)
            if module_name.find(".") >= 0:
                module_name = module_name.split('.')[0]
            self.load_symbols([module_name,])

        if symbol in self.symbol_to_address:
            return self.symbol_to_address[symbol] + offset

        try:
            return pykd.getOffset(symbol) + offset
        except:
            return 0

    def __match_name(self, name, pattern):
        if name.lower().find(pattern.lower()) >= 0:
            return True
        return False

    def get_address_info(self, address):
        return self.windbg_log_parser.parse_address_details(self.run_command("!address %x" % address))

    def get_address_list(self):
        return self.windbg_log_parser.parse_address(self.run_command("!address"))

    def get_address_details(self, type):
        results = []
        for addr_info in self.get_address_list():
            if 'Protect' in addr_info:
               if type == 'NonImageRW' and \
                  addr_info['Protect'] == 'PAGE_READWRITE' and \
                  addr_info['Type'] != 'MEM_IMAGE':

                cmd = 'dqs %x L%x' % (addr_info['BaseAddr'], addr_info['RgnSize']/8)
                results.append(pykd.dbgCommand(cmd))

        return results

    def get_module_names(self):
        if self.use_command_mode:
            module_list = self.run_command("lm1m").splitlines()
        else:
            module_list = []
            for module in pykd.getModulesList():
                module_list.append(module.name())

        return module_list

    def enumerate_modules(self):
        self.module_list = {}

        if self.use_command_mode:
            for line in self.run_command("lmf").splitlines()[1:]:
                toks = line.split()[0:4]
                if len(toks) >= 4:
                    (start, end, name, full_path) = (windbgtool.util.convert_to_int(toks[0]), windbgtool.util.convert_to_int(toks[1]), toks[2], toks[3])           
                    logging.debug('Module: %x - %x (%s - %s)', start, end, name, full_path)
                    self.module_list[name] = {'Base': start, 'End': end, 'Path': full_path, 'Name': name}
                else:
                    logging.info('Broken lm line: %s', ''.join(toks))
        else:
            for module in pykd.getModulesList():
                name = module.name()
                self.module_list[name] = {
                                'Base': module.begin(), 
                                'End': module.begin() + module.size(),
                                'Path': module.image(),
                                'Name': name
                            }

        return self.module_list

    def add_module(self, module):
        lines = self.run_command("lmfm %s" % module).splitlines()

        if len(lines)<3:
            logging.info('Resolving %s information failed:', module)
            logging.info('\n'.join(lines))
        else:
            line = lines[2]
            toks = line.split()[0:4]
            (start, end, name, full_path) = (windbgtool.util.convert_to_int(toks[0]), windbgtool.util.convert_to_int(toks[1]), toks[2], toks[3])
        
            logging.debug('Module: %x - %x (%s - %s)', start, end, name, full_path)
            self.module_list[name] = {'Base': start, 'End': end, 'Path': full_path, 'Name': name}

    def get_addresses(self, name):
        return self.windbg_log_parser.parse_x(self.run_command("x %s" % name))        

    def resolve_module_name(self, module_name_pattern):
        for name in self.module_list.keys():
            if self.__match_name(name, module_name_pattern):
                return name
        return ''
        
    def get_module_base(self, module_name_pattern):
        for name in self.module_list.keys():
            if self.__match_name(name, module_name_pattern):
                return self.module_list[name]['Base']
        return ''
        
    def get_module_range(self, module_name_pattern):
        for name in self.module_list.keys():
            if self.__match_name(name, module_name_pattern):
                return (self.module_list[name]['Base'], self.module_list[name]['End'])
        return (0, 0)

    def get_module_name_from_base(self, base):
        for (module_name, module_info) in self.module_list.items():
            if module_info['Base'] == base:
                return module_name
        return ''

    def get_module_name(self, address):
        for (module_name, module_info) in self.module_list.items():
            if module_info['Base'] <= address and address <= module_info['End']:
                return module_name
        return ''        

    def get_instruction_pointer(self):
        if self.get_arch() == 'AMD64':
            return pykd.reg("rip")
        else:
            return pykd.reg("rip")

        return 0

    def get_stack_pointer(self):
        if self.get_arch() == 'AMD64':
            return pykd.reg("rsp")
        else:
            return pykd.reg("esp")

        return 0

    def get_eax(self):
        if self.get_arch() == 'AMD64':
            return pykd.reg("rax")
        else:
            return pykd.reg("eax")

        return 0

    def get_return_address(self):
        sp = self.get_stack_pointer()        
        
        try:
            if self.get_arch() == 'AMD64':
                return pykd.loadQWords(sp, 1)[0]
            else:
                return pykd.loadDWords(esp, 1)[0]
        except:
            logging.info('Accessing memory %x failed', sp)

        return 0

    def get_return_module_name(self):
        (sp, return_address) = self.get_return_address()
        for (module, (start, end, full_path)) in self.module_list.items():
            (start, end, full_path) = self.module_list[module]
            if return_address >= start and return_address <= end:
                return module

        return ''

    def get_module_info(self, module):
        return self.windbg_log_parser.parse_lmvm(self.run_command("lmvm "+module))        
            
    def get_bytes(self, address, length):
        num_arr = pykd.loadBytes(address, length)
        return bytearray(num_arr)
        
    def get_string(self, addr):
        bytes = ''
        found_null = False
        while 1:
            for b in pykd.loadBytes(addr, 0x10):
                if b == 0x0:
                    found_null = True
                    break
                bytes += chr(b)
                
            if found_null:
                break
            addr += 0x10
        return bytes

    def get_wide_string(self, addr):
        return pykd.loadWStr(addr)

    def get_entry_point_address(self):
        return windbgtool.util.convert_to_int(pykd.dbgCommand("r $exentry").split('=')[1], 0x10)

    def get_current_thread_context(self):
        thread = pykd.dbgCommand('.thread')
        print(thread)
        return windbgtool.util.convert_to_int(pykd.dbgCommand('.thread').split()[-1], 0x10)

    def get_disassembly_line(self, ip, length = 1):
        try:
            return self.run_command('u %x L%x' % (ip, length))
        except:
            return ''

    def gu(self):
        pykd.dbgCommand("gu")

    def go(self):
        pykd.go()
