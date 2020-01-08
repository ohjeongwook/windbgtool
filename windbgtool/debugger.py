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
import windbgtool.breakpoints

class DbgEngine:
    MSDLSymPath = 'srv*https://msdl.microsoft.com/download/symbols'

    def __init__(self):
        self.Logger = logging.getLogger(__name__)
        out_hdlr = logging.StreamHandler(sys.stdout)
        out_hdlr.setLevel(logging.INFO)
        self.Logger.addHandler(out_hdlr)
        self.Logger.setLevel(logging.INFO)

        self.Modules = {}
        self.SymbolMap = {}
        self.SymbolToAddress = {}

        self.WindbgLogParser = windbgtool.log.Parser()

    def __del__(self):
        self.close_dump()
        
    def set_log_level(self, debug = True):
        if debug:
            out_hdlr = logging.StreamHandler(sys.stdout)
            out_hdlr.setLevel(logging.DEBUG)
            self.Logger.addHandler(out_hdlr)
            self.Logger.setLevel(logging.DEBUG)
        else:
            out_hdlr = logging.StreamHandler(sys.stdout)
            out_hdlr.setLevel(logging.INFO)
            self.Logger.addHandler(out_hdlr)
            self.Logger.setLevel(logging.INFO)
       
    def load_dump(self, dump_filename):
        pykd.loadDump(dump_filename)

    def close_dump(self):
        pykd.closeDump()

    def run(self, executable_path):
        pykd.startProcess(executable_path)

    def run_command(self, cmd):
        self.Logger.debug('> run_command: [%s]', cmd)

        ret = pykd.dbgCommand(cmd)
        if ret == None:
            ret = ""

        self.Logger.debug('> run_command Result: [%s]', ret)
        return ret

    def get_machine(self):
        ret = self.run_command(".effmach")
        return ret.split(': ')[1].split(' ')

    def set_symbol_path(self):
        output = self.run_command(".sympath %s" % self.MSDLSymPath)
        output += self.run_command(".reload")

        return output

    def load_symbols(self, modules = []):
        self.SymbolMap = self.enumerate_module_symbols(modules)
       
        self.Logger.debug('* SymbolMap:')
        for (k, v) in self.SymbolMap.items():
            self.Logger.debug('\t%x: %s' % (k, v))

        self.SymbolToAddress = {}
        for (k, v) in self.SymbolMap.items():
            self.SymbolToAddress[v] = k

    def resolve_symbol(self, address):
        if address in self.SymbolMap:
            name = self.SymbolMap[address]
        else:
            try:
                output = pykd.dbgCommand("u %x L1" % address)
            except:
                output = ''

            name = ''
            if output:
                output_lines = output.splitlines()
                if len(output_lines) >= 0 and output_lines[0].endswith(':'):
                    name = output_lines[0][0:-1]                

        return name

    def get_symbol_address(self, symbol):
        if symbol in self.SymbolToAddress:
            return self.SymbolToAddress[symbol]
        return 0

    def match_name(self, name, pattern):
        if name.lower().find(pattern.lower()) >= 0:
            return True
        return False

    def get_address_info(self, address):
        return self.WindbgLogParser.parse_address_details(self.run_command("!address %x" % address))

    def get_address_list(self):
        return self.WindbgLogParser.parse_address(self.run_command("!address"))

    def get_address_details(self, type):
        results = []
        for addr_info in self.get_address_list():
            if 'Protect' in addr_info:
               if type == 'NonImageRW' and \
                  addr['Protect'] == 'PAGE_READWRITE' and \
                  addr['Type'] != 'MEM_IMAGE':

                cmd = 'dqs %x L%x' % (addr['BaseAddr'], addr['RgnSize']/8)
                results.append(dbgCommand(cmd))

        return results
                
    def get_module_list(self):
        return self.run_command("lm1m").splitlines()

    def enumerate_modules(self):
        self.Modules = {}
        for line in self.run_command("lmf").splitlines()[1:]:
            toks = line.split()[0:4]
            
            if len(toks) >= 4:
                (start, end, module, full_path) = (windbgtool.util.convert_to_int(toks[0]), windbgtool.util.convert_to_int(toks[1]), toks[2], toks[3])
            
                self.Logger.debug('Module: %x - %x (%s - %s)', start, end, module, full_path)
                self.Modules[module] = (start, end, full_path)
            else:
                self.Logger.info('Broken lm line: %s', ''.join(toks))

    def add_module(self, module):
        lines = self.run_command("lmfm %s" % module).splitlines()

        if len(lines)<3:
            self.Logger.info('Resolving %s information failed:', module)
            self.Logger.info('\n'.join(lines))
        else:
            line = lines[2]
            toks = line.split()[0:4]
            (start, end, module, full_path) = (windbgtool.util.convert_to_int(toks[0]), windbgtool.util.convert_to_int(toks[1]), toks[2], toks[3])
        
            self.Logger.debug('Module: %x - %x (%s - %s)', start, end, module, full_path)
            self.Modules[module] = (start, end, full_path)

    def get_addresses(self, name):
        return self.WindbgLogParser.parse_x(self.run_command("x %s" % name))        

    def enumerate_module_symbols(self, module_name_patterns = []):
        map = {}
        for name in self.Modules.keys():
            found = False
            if len(module_name_patterns) == 0:
                found = True

            for module_name_pattern in module_name_patterns:
                if self.match_name(name, module_name_pattern):
                    found = True

            if not found:
                continue

            for (k, v) in self.get_addresses("%s!*" % name).items():
                map[k] = v
        return map

    def resolve_module_name(self, module_name_pattern):
        for name in self.Modules.keys():
            if self.match_name(name, module_name_pattern):
                return name
        return ''
        
    def get_module_base(self, module_name_pattern):
        for name in self.Modules.keys():
            if self.match_name(name, module_name_pattern):
                return self.Modules[name][0]
        return ''
        
    def get_module_range(self, module_name_pattern):
        for name in self.Modules.keys():
            if self.match_name(name, module_name_pattern):
                return self.Modules[name][0:2]
        return (0, 0)

    def get_module_name_from_base(self, base):
        for (k, v) in self.Modules.items():
            if v[0] == base:
                return k
        return ''

    def get_instruction_pointer(self):
        try:
            return pykd.reg("rip")
        except:    
            return pykd.reg("eip")

        return 0

    def get_stack_pointer(self):
        try:
            return pykd.reg("rsp")
        except:    
            return pykd.reg("esp")

        return 0

    def get_return_address(self):
        try:
            rsp = pykd.reg("rsp")
            try:
                return pykd.loadQWords(rsp, 1)[0]
            except:
                self.Logger.info('Accessing memory %x failed', rsp)
            
        except:    
            esp = pykd.reg("esp")
            try:
                return pykd.loadDWords(esp, 1)[0]
            except:
                self.Logger.info('Accessing memory %x failed', esp)

        return 0

    def get_return_module_name(self):
        (sp, return_address) = self.get_return_address()
        for (module, (start, end, full_path)) in self.Modules.items():
            (start, end, full_path) = self.Modules[module]
            if return_address >= start and return_address <= end:
                return module

        return ''

    def get_module_info(self, module):
        return self.WindbgLogParser.parse_lmvm(self.run_command("lmvm "+module))        

    def resolve_address(self, addr_str):
        addr_toks = addr_str.split("+")
        
        if len(addr_toks)>1:
            addr_str = addr_toks[0]
            offset = windbgtool.util.convert_to_int(addr_toks[1], 16)
        else:
            offset = 0

        res = self.run_command("x "+addr_str)
        
        res_lines = res.splitlines()
        if len(res_lines)>0:
            return windbgtool.util.convert_to_int(res_lines[-1].split()[0])+offset
        else:
            [module, symbol] = addr_str.split("!")
            for line in self.run_command("x %s!" % (module)).splitlines():
                toks = line.split(' ', 1)
                if len(toks)>1:
                    xaddress = toks[0]
                    xaddress_str = toks[1]
                    
                    if xaddress_str == addr_str:
                        return windbgtool.util.convert_to_int(xaddress)+offset

            return 0+offset

    def show_stack(self):
        print('* Stack----')
        for dword in pykd.loadDWords(pykd.reg("esp"), 5):
            print('%x' % dword)
            
    def get_bytes(self, address, length):
        bytes = pykd.loadBytes(address, length)

        byte_str = ''
        for byte in bytes:
            byte_str += chr(byte)
        return byte_str
        
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
        bytes = ''
        found_null = False
        while 1:
            tmp_bytes = pykd.loadBytes(addr, 0x10)
            for i in range(0, len(tmp_bytes), 2):
                if tmp_bytes[i] == 0x0 and tmp_bytes[i+1] == 0x0:
                    found_null = True
                    break
                bytes += chr(tmp_bytes[i])+chr(tmp_bytes[i+1])
                
            if found_null:
                break
            addr += 0x10
        return bytes

    def get_entry_point_address(self):
        return int(pykd.dbgCommand("r $exentry").split('=')[1], 0x10)

    def get_current_thread_context(self):
        return int(pykd.dbgCommand('.thread').split()[-1], 0x10)

    def go(self):
        pykd.go()
