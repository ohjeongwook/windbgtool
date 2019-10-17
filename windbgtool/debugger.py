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
import log
import breakpoints

class DbgEngine:
    SymPath = 'srv*https://msdl.microsoft.com/download/symbols'

    def __init__(self):
        self.logger = logging.getLogger(__name__)

        out_hdlr = logging.StreamHandler(sys.stdout)
        out_hdlr.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
        out_hdlr.setLevel(logging.INFO)
        self.logger.addHandler(out_hdlr)
        self.logger.setLevel(logging.INFO)

        self.Modules = {}
        self.SymbolMap = {}
        self.SymbolToAddress = {}
        self.BreakpointsMap = {}
        self.RecordsDB = None

        self.WindbgLogParser = log.Parser()
        self.AddressToBreakPoints = {}

    def LoadDump(self, dump_filename):
        pykd.loadDump(dump_file)

    def Run(self, executable_path):
        pykd.startProcess(executable_path)

    def RunCmd(self,cmd):
        self.logger.info('* RunCmd: %s', cmd)

        ret = pykd.dbgCommand(cmd)
        if ret == None:
            ret = ""

        self.logger.info('\tResult: %s', ret)
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
       
        self.logger.info('* SymbolMap:')
        for (k,v) in self.SymbolMap.items():
            self.logger.info('\t%x: %s' % (k,v))

        self.SymbolToAddress = {}
        for (k,v) in self.SymbolMap.items():
            self.SymbolToAddress[v] = k

    def ResolveSymbol(self,address):
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

    def GetSymbolAddress(self,symbol):
        if symbol in self.SymbolToAddress:
            return self.SymbolToAddress[symbol]
        return 0

    def MatchName(self,name,pattern):
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
                (start,end,module,full_path) = (util.common.Int(toks[0]), util.common.Int(toks[1]), toks[2], toks[3])
            
                self.logger.info('Adding %x - %x (%s - %s)',start,end,module,full_path)
                self.Modules[module] = (start,end,full_path)
            else:
                self.logger.info('Broken lm line: %s', ''.join(toks))

    def AddModule(self,module):
        lines = self.RunCmd("lmfm %s" % module).splitlines()

        if len(lines)<3:
            self.logger.info('Resolving %s information failed:', module)
            self.logger.info('\n'.join(lines))
        else:
            line = lines[2]
            toks = line.split()[0:4]
            (start,end,module,full_path) = (util.common.Int(toks[0]), util.common.Int(toks[1]), toks[2], toks[3])
        
            self.logger.info('Adding %x - %x (%s - %s)',start,end,module,full_path)
            self.Modules[module] = (start, end, full_path)

    def GetAddresses(self,name):
        return self.WindbgLogParser.ParseX(self.RunCmd("x %s" % name))        

    def EnumerateModuleSymbols(self,module_name_patterns = []):
        map = {}
        for name in self.Modules.keys():
            found = False
            if len(module_name_patterns) == 0:
                found = True

            for module_name_pattern in module_name_patterns:
                if self.MatchName(name,module_name_pattern):
                    found = True

            if not found:
                continue

            for (k,v) in self.GetAddresses("%s!*" % name).items():
                map[k] = v
        return map

    def ResolveModuleName(self,module_name_pattern):
        for name in self.Modules.keys():
            if self.MatchName(name,module_name_pattern):
                return name
        return ''
        
    def GetModuleBase(self,module_name_pattern):
        for name in self.Modules.keys():
            if self.MatchName(name,module_name_pattern):
                return self.Modules[name][0]
        return ''
        
    def GetModuleRange(self,module_name_pattern):
        for name in self.Modules.keys():
            if self.MatchName(name,module_name_pattern):
                return self.Modules[name][0:2]
        return (0,0)

    def GetModuleNameFromBase(self,base):
        for (k,v) in self.Modules.items():
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
                return loadQWords(rsp,1)[0]
            except:
                self.logger.info('Accessing memory %x failed',rsp)
            
        except:    
            esp = pykd.reg("esp")
            try:
                return loadDWords(esp,1)[0]
            except:
                self.logger.info('Accessing memory %x failed',esp)

        return 0

    def GetReturnModuleName(self):
        (sp, return_address) = self.GetReturnAddress()
        for (module,(start,end,full_path)) in self.Modules.items():
            (start,end,full_path) = self.Modules[module]
            if return_address >= start and return_address <= end:
                return module

        return ''

    def GetModuleInfo(self,module):
        return self.WindbgLogParser.ParseLMVM(self.RunCmd("lmvm "+module))        

    def ResolveAddress(self,addr_str):
        addr_toks = addr_str.split("+")
        
        if len(addr_toks)>1:
            addr_str = addr_toks[0]
            offset = util.common.Int(addr_toks[1],16)
        else:
            offset = 0

        res = self.RunCmd("x "+addr_str)
        
        res_lines = res.splitlines()
        if len(res_lines)>0:
            return util.common.Int(res_lines[-1].split()[0])+offset
        else:
            [module,symbol] = addr_str.split("!")
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
        for dword in loadDWords(pykd.reg("esp"),5):
            print('%x' % dword)
            
    def GetBytes(self,address,length):
        bytes = pykd.loadBytes(address,length)

        byte_str = ''
        for byte in bytes:
            byte_str += chr(byte)
        return byte_str
        
    def GetString(self,addr):
        bytes = ''
        found_null = False
        while 1:
            for b in pykd.loadBytes(addr,0x10):
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
            tmp_bytes = pykd.loadBytes(addr,0x10)
            for i in range(0,len(tmp_bytes),2):
                if tmp_bytes[i] == 0x0 and tmp_bytes[i+1] == 0x0:
                    found_null = True
                    break
                bytes += chr(tmp_bytes[i])+chr(tmp_bytes[i+1])
                
            if found_null:
                break
            addr += 0x10
        return bytes

    def GetEntryPoint(self):
        return int(pykd.dbgCommand("r $exentry").split(' = ')[1],0x10)

    """ Breakpoint """   
    
    def SetBp(self,addr,handler):
        if addr in self.AddressToBreakPoints:
            self.AddressToBreakPoints[addr].remove()
            del self.AddressToBreakPoints[addr]

        bp = pykd.setBp(int(addr), handler)
        self.AddressToBreakPoints[addr] = bp
        return bp

    def ClearBP(self):
        for (addr,bp) in self.AddressToBreakPoints.items():
            bp.remove()
            del self.AddressToBreakPoints[addr]

    def AddModuleBP(self,module_name,module_bps,handler):
        module_base = self.GetModuleBase(module_name)
        self.logger.info('AddModuleBP: %s (%x)',module_name,module_base)
        
        addresses = []
        for (rva,dump_targets) in module_bps.items():
            address = module_base+rva
            self.logger.info('\tSet bp: %x (%x+%x)) %s',address,module_base,rva,str(dump_targets))

            self.SetBp(address,handler)
            addresses.append(address)
            self.BreakpointsMap[address] = {
                                    'Type': 'Module', 
                                    'Module': module_name, 
                                    'RVA': rva,
                                    'Symbol': '',
                                    'DumpTargets': dump_targets
                                }
            
        return addresses
            
    def AddSymbolBP(self, module_name, symbol, dump_targets, handler = None):
        if not handler:
            handler = self.HandleBreakpoint

        symbol_str = module_name+'!'+symbol
        address = self.ResolveAddress(symbol_str)
        
        if address>0:
            bp = self.SetBp(address, handler)
            
            self.logger.info("Setting breakpoint %s (%.8x) - %d\n", symbol_str, address, bp.getId())
            self.BreakpointsMap[address] = {
                                    'Type': 'Symbol',
                                    'Module': module_name,
                                    'RVA': 0,
                                    'Symbol': symbol,
                                    'DumpTargets': dump_targets
                                }

    def LoadBreakPoints(self, breakpoint_db, record_db = ''):
        self.BreakPointsDB = breakpoints.DB(breakpoint_db)
        self.BreakPointsDB.Load()
        self.RecordsDB = breakpoints.Record(record_db)
        self.BreakpointsMap = {}
        for (module, rules) in self.BreakPointsDB.AddressBreakpoints.items():
            for (address, dump_targets) in rules.items():
                bp = self.SetBp(address,self.HandleBreakpoint)
                
                self.logger.info('Setting breakpoint on %s (%.8x) - %d' % (
                                                module,
                                                address,
                                                bp.getId()
                                            )
                                        )

                self.BreakpointsMap[address] = {
                                    'Type': 'Address',
                                    'Module': module,
                                    'RVA': 0,
                                    'Symbol': '',
                                    'DumpTargets': dump_targets
                                }
            
        for (module_name, module_bps) in self.BreakPointsDB.ModuleBreakpoints.items():
            self.AddModuleBP(module_name, module_bps, self.HandleBreakpoint)

        for (module_name, module_bps) in self.BreakPointsDB.SymbolBreakpoints.items():
            for (symbol, dump_targets) in module_bps.items():
                self.AddSymbolBP(module_name,symbol,dump_targets,self.HandleBreakpoint)
                
        self.ReturnBreakpointsMap = {}

    def DumpModuleParams(self, bp_type, module_base, dump_targets):
        dump_outputs = []
        if bp_type == 'Function':
            dump_targets_values = pykd.loadDWords(pykd.reg("esp")+4,len(dump_targets))
            arg_i = 0
            for (arg_type, dump_target_name) in dump_targets:
                dump_output = ''
                if arg_type == "LPCWSTR":
                    dump_output = self.RunCmd("du %.8x" % dump_targets_values[arg_i])
                    
                elif arg_type == "DWORD" or "HANDLE":
                    dump_output = "%.8x" % dump_targets_values[arg_i]
                    
                else:
                    dump_output = "%.8x" % dump_targets_values[arg_i]

                dump_output_item = {}
                dump_output_item['DumpTargetName'] = dump_target_name
                dump_output_item['ArgPosition'] = i
                dump_output_item['DumpOutput'] = dump_output
                dump_outputs.append(dump_output_item)

                self.loggger.debug("%s (%s):\n%s" % (dump_target_name,arg_type,dump_output))
                arg_i += 1

        elif bp_type == 'Instruction':
            for dump_target in dump_targets:
                arg_type = dump_target['Type']
                data_type = dump_target['DataType']

                dump_target_name = ''
                dump_output = ''
                if arg_type == "Register":
                    dump_target_name = dump_target['Value']
                    dump_output = "%.8x" % pykd.reg(str(dump_target_name))

                elif arg_type == "Memory" or arg_type == "Displacement" or arg_type == "Phrase":
                    memory_str = dump_target['Base']
                    if dump_target['Index']:
                        memory_str += '+%s*%x' % (dump_target['Index'],dump_target['Scale'])
                        
                    if arg_type == "Memory":
                        memory_str += '+%x' % (module_base+dump_target['Address'])
                    elif arg_type == "Displacement":
                        memory_str += '+%x' % dump_target['Offset']

                    dump_target_name = memory_str
                    
                    if data_type == 'Byte':
                        d_cmd = 'db'
                        d_length = 10
                    elif data_type == 'Word':
                        d_cmd = 'dw'
                        d_length = 10
                    elif data_type == 'DWORD':
                        d_cmd = 'dd'
                        d_length = 10

                    dump_output = self.RunCmd("%s %s L%x" % (d_cmd,memory_str,d_length))

                if dump_target_name:
                    dump_output_item = {}
                    dump_output_item['DumpTargetName'] = dump_target_name
                    dump_output_item['Position'] = dump_target['Position']
                    dump_output_item['DumpOutput'] = dump_output
                    dump_outputs.append(dump_output_item)

                    if dump_output.find('\n'):
                        self.loggger.debug("%s (%s):" % (dump_target_name,arg_type))
                        for line in dump_output.splitlines():
                            self.loggger.debug("\t%s" % (line))
                    else:
                        self.loggger.debug("%s (%s): %s" % (dump_target_name,arg_type,dump_output))
        return dump_outputs

    def DumpOperand(self,operand):
        operand_type = operand['Type']
        value = ''
        pointer = 0
        if operand_type == 'Displacement':
            base = pykd.reg(operand['Base'])
            if operand['Index']:
                index = pykd.reg(operand['Index'])
            else:
                index = 0
            offset = operand['Offset']
            if offset:
                if operand['Offset'] & 0x80000000:
                    offset = (0x100000000-offset)*-1

            pointer = base+index+offset

        elif operand_type == 'Register':
            value = pykd.reg(operand['Value'])
        elif operand_type == 'Memory':
            pointer = operand['Value']
        elif operand_type == 'Near':
            pass
        else:
            pass
            
        if pointer>0:
            (value,)= pykd.loadDWords(pointer,1)

        return value

    def GetCallParameters(self, count, is_syscall = False):
        if is_syscall:
            bits = 64 #TODO: support 32 bit
            parameter_values = pykd.loadQWords(pykd.reg("r10"),len(parameter_definition))
        else:
            parameters = []
            try:
                bits = 64
                parameters = []
                
                if count>0:
                    parameters.append(pykd.reg("rcx"))
                    if count>1:
                        parameters.append(pykd.reg("rdx"))
                        if count>2:
                            parameters.append(pykd.reg("r8"))
                            if count>3:
                                parameters.append(pykd.reg("r9"))
                                if count>4:
                                    try:
                                        rsp = pykd.reg("rsp")
                                        parameters+= pykd.loadQWords(rsp+8,count-4)
                                    except:
                                        self.logger.info('Accessing memory %x failed',rsp+8)

            except:
                bits = 32
                esp = pykd.reg("esp")        
                try:                
                    parameters = pykd.loadDWords(esp+4,count)
                except:
                    self.logger.info('Accessing memory %x failed', esp)

        return (bits,parameters)
        
    def DumpParameters(self,parameter_definition,is_syscall = False):
        (bits,parameter_values) = self.GetCallParameters(len(parameter_definition),is_syscall)

        parameter_map = {}
        for index in range(0, len(parameter_definition), 1):
            parameter = parameter_definition[index]            
            parameter_map[parameter['Name']] = parameter_values[index]

        results = []
        for index in range(0,len(parameter_definition),1):
            result = {}
            parameter = parameter_definition[index]
            
            result['Parameter'] = parameter
            parameter_value = parameter_values[index]
            result['Value'] = parameter_value

            if 'Dump' in parameter:
                if parameter['Dump']['Type'] == 'Bytes':
                    if parameter['Dump']['Length']['Type'] == 'Parameter':
                        parameter_length = parameter_map[parameter['Dump']['Length']['Value']]
                    elif parameter['Dump']['Length']['Type'] == 'Value':
                        parameter_length = parameter['Dump']['Length']['Value']
                    else:
                        parameter_length = 0x100

                    try:
                        bytes = self.GetBytes(parameter_value,parameter_length)
                        result['Bytes'] = base64.b64encode(bytes)
                    except:
                        pass

            elif parameter['Type'] == 'LPCSTR':
                string_val = self.GetString(parameter_value)
                result['String'] = string_val

            elif parameter['Type'] in ('LPWSTR', 'LPCWSTR'):
                wstring_val = self.GetWString(parameter_value)
                result['WString'] = wstring_val
                
            elif parameter['Pointer'] or parameter['Type'].startswith('LP'):
                try:
                    bytes = self.GetBytes(parameter_value,0x20)
                    result['Bytes'] = base64.b64encode(bytes)
                except:
                    pass

            results.append(result)
        return (parameter_map, results)

    def GetThreadContext(self):
        return int(pykd.dbgCommand('.thread').split()[-1],0x10)
        
    def HandleBreakpoint(self):
        eip = self.GetEIP()

        if eip in self.BreakpointsMap:
            record = {'Address': eip}
            record['Type'] = 'Enter'
            record['Module'] = self.BreakpointsMap[eip]['Module']
            record['RVA'] = self.BreakpointsMap[eip]['RVA']
            record['Symbol'] = self.BreakpointsMap[eip]['Symbol']
            record['ThreadContext'] = self.GetThreadContext()
            esp = self.GetESP()
            record['StackPointer'] = esp
            record['DumpTargets'] = []

            if record['Symbol']:
                self.logger.info('> %s!%s (+%.8x) (%.8x)' % (
                                                record['Module'],
                                                record['Symbol'],
                                                record['RVA'],
                                                record['Address']
                                            )
                                        )

            for dump_target in self.BreakpointsMap[eip]['DumpTargets']:
                if dump_target['Type'] == 'Operand':
                    dump_result = {}
                    dump_result['Operand'] = self.DumpOperand(dump_target['Value'])
                    
                    if dump_target['DataType'] == 'Pointer':
                        try:
                            bytes = self.GetBytes(parameter_values[index],0x100)
                            dump_result['Bytes'] = base64.b64encode(bytes)
                        except:
                            pass

                elif dump_target['Type'] == 'Parameters':
                    (parameter_map, dump_result) = self.DumpParameters(dump_target['Value'])
                    
                elif dump_target['Type'] == 'ReturnParameters' and len(dump_target['Value'])>0:
                    return_address = self.GetReturnAddress()
                    for (parameter_name,dump_instruction) in dump_target['Value'].items():                    
                        if dump_instruction['Length']['Type'] == 'Parameter':
                            parameter_length = parameter_map[dump_instruction['Length']['Value']]
                        else:
                            parameter_length = 0

                        self.ReturnBreakpointsMap[return_address] = {
                                                        'Type': 'ReturnParameter',
                                                        'EIP': eip,
                                                        'DumpInstruction': dump_instruction,
                                                        'Pointer': parameter_map[parameter_name],
                                                        'Length': parameter_length
                                                    }

                    bp = self.SetBp(return_address,self.HandleReturnBreakpoint)
                    self.logger.info('\tSet Return BP on %.8x - %d' % (return_address, bp.getId()))

                elif dump_target['Type'] == 'Function':
                    dump_result = []
                    for (arg_name, arg_offset) in dump_target['Args']:
                        arg_addr = esp+arg_offset
                        (arg_value,)= pykd.loadDWords(arg_addr,1)
                        try:
                            bytes = self.GetBytes(arg_value,0x100)
                            base64_bytes = base64.b64encode(bytes)
                        except:
                            base64_bytes = ''

                        dump_result.append({'Name': arg_name, 'Value': arg_value, 'Bytes': base64_bytes})

                else:
                    dump_result = []

                record['DumpTargets'].append({'Target': dump_target, 'Value': dump_result})

            if self.RecordsDB:
                self.RecordsDB.WriteRecord(record)
            else:
                self.logger.info(pprint.pformat(record))
        else:
            self.logger.info('> BP @%.8x' % eip)

    def HandleReturnBreakpoint(self):
        eip = self.GetEIP()
        if eip in self.ReturnBreakpointsMap:
            return_bp_info = self.ReturnBreakpointsMap[eip]

            try:
                bytes = self.GetBytes(return_bp_info['Pointer'],return_bp_info['Length'])
            except:
                bytes = ''

            original_eip = return_bp_info['EIP']
            record = {'Address': original_eip}
            record['Type'] = 'Return'
            record['Module'] = self.BreakpointsMap[original_eip]['Module']
            record['RVA'] = self.BreakpointsMap[original_eip]['RVA']
            record['Symbol'] = self.BreakpointsMap[original_eip]['Symbol']
            record['ThreadContext'] = self.GetThreadContext()
            record['StackPointer'] = self.GetESP()
            record['DumpTargets'] = [{
                                    'Target': return_bp_info,
                                    'Value': base64.b64encode(bytes)
                                   }
                                  ]
                                  
            if record['Symbol']:
                self.logger.info('> %s!%s (+%.8x) (%.8x) Return' % (
                                                record['Module'],
                                                record['Symbol'],
                                                record['RVA'],
                                                record['Address']
                                            )
                                        )

            if self.RecordsDB:
                self.RecordsDB.WriteRecord(record)
            else:
                self.logger.info(pprint.pformat(record))

    def Go(self):
        pykd.go()
