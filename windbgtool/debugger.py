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

import util.common
import windbgtool.log
import windbgtool.breakpoints

class DbgEngine:
    SymPath = 'srv*https://msdl.microsoft.com/download/symbols'

    def __init__(self):
        self.Logger = logging.getLogger(__name__)
        out_hdlr = logging.StreamHandler(sys.stdout)
        out_hdlr.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
        out_hdlr.setLevel(logging.INFO)
        self.Logger.addHandler(out_hdlr)
        self.Logger.setLevel(logging.INFO)

        self.Modules = {}
        self.SymbolMap = {}
        self.SymbolToAddress = {}

        self.WindbgLogParser = windbgtool.log.Parser()

    def LoadDump(self, dump_filename):
        pykd.loadDump(dump_filename)

    def Run(self, executable_path):
        pykd.startProcess(executable_path)

    def RunCmd(self, cmd):
        self.Logger.info('* RunCmd: %s', cmd)

        ret = pykd.dbgCommand(cmd)
        if ret == None:
            ret = ""

        self.Logger.info('\tResult: %s', ret)
        return ret

    def GetMachine(self):
        ret = self.RunCmd(".effmach")
        return ret.split(': ')[1].split(' ')

    def SetSymbolPath(self):
        output = ''
        output = self.RunCmd(".sympath %s" % self.SymPath)
        output += self.RunCmd(".reload")

        return output

    def LoadSymbols(self, modules = []):
        self.SymbolMap = self.EnumerateModuleSymbols(modules)
       
        self.Logger.info('* SymbolMap:')
        for (k, v) in self.SymbolMap.items():
            self.Logger.info('\t%x: %s' % (k, v))

        self.SymbolToAddress = {}
        for (k, v) in self.SymbolMap.items():
            self.SymbolToAddress[v] = k

    def ResolveSymbol(self, address):
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

    def GetSymbolAddress(self, symbol):
        if symbol in self.SymbolToAddress:
            return self.SymbolToAddress[symbol]
        return 0

    def MatchName(self, name, pattern):
        if name.lower().find(pattern.lower()) >= 0:
            return True
        return False

    def GetAddressList(self, debug = 0):
        return self.WindbgLogParser.ParseAddress(self.RunCmd("!address"))

    def GetAddressDetails(self, type):
        results = []
        for addr_info in self.GetAddressList():
            if 'Protect' in addr_info:
               if type == 'NonImageRW' and \
                  addr['Protect'] == 'PAGE_READWRITE' and \
                  addr['Type'] != 'MEM_IMAGE':

                cmd = 'dqs %x L%x' % (addr['BaseAddr'], addr['RgnSize']/8)
                results.append(dbgCommand(cmd))

        return results
                
    def GetModuleList(self):
        return self.RunCmd("lm1m").splitlines()

    def EnumerateModules(self):
        self.Modules = {}
        for line in self.RunCmd("lmf").splitlines()[1:]:
            toks = line.split()[0:4]
            
            if len(toks) >= 4:
                (start, end, module, full_path) = (util.common.Int(toks[0]), util.common.Int(toks[1]), toks[2], toks[3])
            
                self.Logger.info('Adding %x - %x (%s - %s)', start, end, module, full_path)
                self.Modules[module] = (start, end, full_path)
            else:
                self.Logger.info('Broken lm line: %s', ''.join(toks))

    def AddModule(self, module):
        lines = self.RunCmd("lmfm %s" % module).splitlines()

        if len(lines)<3:
            self.Logger.info('Resolving %s information failed:', module)
            self.Logger.info('\n'.join(lines))
        else:
            line = lines[2]
            toks = line.split()[0:4]
            (start, end, module, full_path) = (util.common.Int(toks[0]), util.common.Int(toks[1]), toks[2], toks[3])
        
            self.Logger.info('Adding %x - %x (%s - %s)', start, end, module, full_path)
            self.Modules[module] = (start, end, full_path)

    def GetAddresses(self, name):
        return self.WindbgLogParser.ParseX(self.RunCmd("x %s" % name))        

    def EnumerateModuleSymbols(self, module_name_patterns = []):
        map = {}
        for name in self.Modules.keys():
            found = False
            if len(module_name_patterns) == 0:
                found = True

            for module_name_pattern in module_name_patterns:
                if self.MatchName(name, module_name_pattern):
                    found = True

            if not found:
                continue

            for (k, v) in self.GetAddresses("%s!*" % name).items():
                map[k] = v
        return map

    def ResolveModuleName(self, module_name_pattern):
        for name in self.Modules.keys():
            if self.MatchName(name, module_name_pattern):
                return name
        return ''
        
    def GetModuleBase(self, module_name_pattern):
        for name in self.Modules.keys():
            if self.MatchName(name, module_name_pattern):
                return self.Modules[name][0]
        return ''
        
    def GetModuleRange(self, module_name_pattern):
        for name in self.Modules.keys():
            if self.MatchName(name, module_name_pattern):
                return self.Modules[name][0:2]
        return (0, 0)

    def GetModuleNameFromBase(self, base):
        for (k, v) in self.Modules.items():
            if v[0] == base:
                return k
        return ''

    def GetEIP(self):
        try:
            return pykd.reg("rip")
        except:    
            return pykd.reg("eip")

        return 0

    def GetESP(self):
        try:
            return pykd.reg("rsp")
        except:    
            return pykd.reg("esp")

        return 0

    def GetReturnAddress(self):
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

    def GetReturnModuleName(self):
        (sp, return_address) = self.GetReturnAddress()
        for (module, (start, end, full_path)) in self.Modules.items():
            (start, end, full_path) = self.Modules[module]
            if return_address >= start and return_address <= end:
                return module

        return ''

    def GetModuleInfo(self, module):
        return self.WindbgLogParser.ParseLMVM(self.RunCmd("lmvm "+module))        

    def ResolveAddress(self, addr_str):
        addr_toks = addr_str.split("+")
        
        if len(addr_toks)>1:
            addr_str = addr_toks[0]
            offset = util.common.Int(addr_toks[1], 16)
        else:
            offset = 0

        res = self.RunCmd("x "+addr_str)
        
        res_lines = res.splitlines()
        if len(res_lines)>0:
            return util.common.Int(res_lines[-1].split()[0])+offset
        else:
            [module, symbol] = addr_str.split("!")
            for line in self.RunCmd("x %s!" % (module)).splitlines():
                toks = line.split(' ', 1)
                if len(toks)>1:
                    xaddress = toks[0]
                    xaddress_str = toks[1]
                    
                    if xaddress_str == addr_str:
                        return util.common.Int(xaddress)+offset

            return 0+offset

    def ShowStack(self):
        print('* Stack----')
        for dword in pykd.loadDWords(pykd.reg("esp"), 5):
            print('%x' % dword)
            
    def GetBytes(self, address, length):
        bytes = pykd.loadBytes(address, length)

        byte_str = ''
        for byte in bytes:
            byte_str += chr(byte)
        return byte_str
        
    def GetString(self, addr):
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

    def GetWString(self, addr):
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

    def GetEntryPoint(self):
        return int(pykd.dbgCommand("r $exentry").split('=')[1], 0x10)

    def GetThreadContext(self):
        return int(pykd.dbgCommand('.thread').split()[-1], 0x10)

    def Go(self):
        pykd.go()
