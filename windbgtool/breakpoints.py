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
import windbgtool.util
import windbgtool.breakpoints_storage
        
class Operations:
    def __init__(self, debugger):
        self.Logger = logging.getLogger(__name__)
        out_hdlr = logging.StreamHandler(sys.stdout)
        out_hdlr.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
        out_hdlr.setLevel(logging.INFO)
        self.Logger.addHandler(out_hdlr)
        self.Logger.setLevel(logging.INFO)

        self.Debugger = debugger
        self.AddressToBreakPoints = {}
        self.BreakpointsMap = {}
        self.RecordsDB = None
        
    def set_bp(self, addr, handler):
        if addr in self.AddressToBreakPoints:
            self.AddressToBreakPoints[addr].remove()
            del self.AddressToBreakPoints[addr]

        bp = pykd.setBp(int(addr), handler)
        self.AddressToBreakPoints[addr] = bp
        return bp

    def clear_bp(self):
        for (addr, bp) in self.AddressToBreakPoints.items():
            bp.remove()
            del self.AddressToBreakPoints[addr]

    def add_module_bp(self, module_name, module_bps, handler):
        module_base = self.Debugger.get_module_base(module_name)
        self.Logger.info('add_module_bp: %s (%x)', module_name, module_base)
        
        addresses = []
        for (rva, dump_targets) in module_bps.items():
            address = module_base+rva
            self.Logger.info('\tSet bp: %x (%x+%x)) %s', address, module_base, rva, str(dump_targets))

            self.set_bp(address, handler)
            addresses.append(address)
            self.BreakpointsMap[address] = {
                                    'Type': 'Module', 
                                    'Module': module_name, 
                                    'RVA': rva, 
                                    'Symbol': '', 
                                    'DumpTargets': dump_targets
                                }
            
        return addresses
            
    def add_symbol_bp(self, module_name, symbol, dump_targets, handler = None):
        if not handler:
            handler = self.handle_breakpoint

        symbol_str = module_name+'!'+symbol
        address = self.Debugger.resolve_address(symbol_str)
        
        if address>0:
            bp = self.set_bp(address, handler)
            
            self.Logger.info("Setting breakpoint %s (%.8x) - %d\n", symbol_str, address, bp.getId())
            self.BreakpointsMap[address] = {
                                    'Type': 'Symbol', 
                                    'Module': module_name, 
                                    'RVA': 0, 
                                    'Symbol': symbol, 
                                    'DumpTargets': dump_targets
                                }

    def load_breakpoints(self, breakpoint_db, record_db = ''):
        self.BreakPointsDB = windbgtool.breakpoints_storage.Storage(breakpoint_db)
        self.BreakPointsDB.load()
        self.RecordsDB = windbgtool.breakpoints_storage.Record(record_db)
        self.BreakpointsMap = {}

        for (module, rules) in self.BreakPointsDB.AddressBreakpoints.items():
            for (address, dump_targets) in rules.items():
                bp = self.set_bp(address, self.handle_breakpoint)
                
                self.Logger.info('Setting breakpoint on %s (%.8x) - %d' % (
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
            self.add_module_bp(module_name, module_bps, self.handle_breakpoint)

        for (module_name, module_bps) in self.BreakPointsDB.SymbolBreakpoints.items():
            for (symbol, dump_targets) in module_bps.items():
                self.add_symbol_bp(module_name, symbol, dump_targets, self.handle_breakpoint)
                
        self.ReturnBreakpointsMap = {}

    def dump_module_parameters(self, bp_type, module_base, dump_targets):
        dump_outputs = []
        if bp_type == 'Function':
            dump_targets_values = pykd.loadDWords(pykd.reg("esp")+4, len(dump_targets))
            arg_i = 0
            for (arg_type, dump_target_name) in dump_targets:
                dump_output = ''
                if arg_type == "LPCWSTR":
                    dump_output = self.Debugger.run_command("du %.8x" % dump_targets_values[arg_i])
                    
                elif arg_type == "DWORD" or "HANDLE":
                    dump_output = "%.8x" % dump_targets_values[arg_i]
                    
                else:
                    dump_output = "%.8x" % dump_targets_values[arg_i]

                dump_output_item = {}
                dump_output_item['DumpTargetName'] = dump_target_name
                dump_output_item['ArgPosition'] = i
                dump_output_item['DumpOutput'] = dump_output
                dump_outputs.append(dump_output_item)

                self.loggger.debug("%s (%s):\n%s" % (dump_target_name, arg_type, dump_output))
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
                        memory_str += '+%s*%x' % (dump_target['Index'], dump_target['Scale'])
                        
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

                    dump_output = self.Debugger.run_command("%s %s L%x" % (d_cmd, memory_str, d_length))

                if dump_target_name:
                    dump_output_item = {}
                    dump_output_item['DumpTargetName'] = dump_target_name
                    dump_output_item['Position'] = dump_target['Position']
                    dump_output_item['DumpOutput'] = dump_output
                    dump_outputs.append(dump_output_item)

                    if dump_output.find('\n'):
                        self.loggger.debug("%s (%s):" % (dump_target_name, arg_type))
                        for line in dump_output.splitlines():
                            self.loggger.debug("\t%s" % (line))
                    else:
                        self.loggger.debug("%s (%s): %s" % (dump_target_name, arg_type, dump_output))

        return dump_outputs

    def dump_operand(self, operand):
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
            (value, )= pykd.loadDWords(pointer, 1)

        return value

    def get_call_parameters(self, count, is_syscall = False):
        if is_syscall:
            bits = 64 #TODO: support 32 bit
            parameter_values = pykd.loadQWords(pykd.reg("r10"), len(parameter_definition))
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
                                        parameters+= pykd.loadQWords(rsp+8, count-4)
                                    except:
                                        self.Logger.info('Accessing memory %x failed', rsp+8)

            except:
                bits = 32
                esp = pykd.reg("esp")        
                try:                
                    parameters = pykd.loadDWords(esp+4, count)
                except:
                    self.Logger.info('Accessing memory %x failed', esp)

        return (bits, parameters)
        
    def dump_parameters(self, parameter_definition, is_syscall = False):
        (bits, parameter_values) = self.Debugger.get_call_parameters(len(parameter_definition), is_syscall)

        parameter_map = {}
        for index in range(0, len(parameter_definition), 1):
            parameter = parameter_definition[index]            
            parameter_map[parameter['Name']] = parameter_values[index]

        results = []
        for index in range(0, len(parameter_definition), 1):
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
                        bytes = self.Debugger.get_bytes(parameter_value, parameter_length)
                        result['Bytes'] = base64.b64encode(bytes)
                    except:
                        pass

            elif parameter['Type'] == 'LPCSTR':
                string_val = self.Debugger.get_string(parameter_value)
                result['String'] = string_val

            elif parameter['Type'] in ('LPWSTR', 'LPCWSTR'):
                wstring_val = self.Debugger.get_wide_string(parameter_value)
                result['WString'] = wstring_val
                
            elif parameter['Pointer'] or parameter['Type'].startswith('LP'):
                try:
                    bytes = self.Debugger.get_bytes(parameter_value, 0x20)
                    result['Bytes'] = base64.b64encode(bytes)
                except:
                    pass

            results.append(result)
        return (parameter_map, results)

    def handle_breakpoint(self):
        eip = self.Debugger.get_instruction_pointer()

        if eip in self.BreakpointsMap:
            record = {'Address': eip}
            record['Type'] = 'Enter'
            record['Module'] = self.BreakpointsMap[eip]['Module']
            record['RVA'] = self.BreakpointsMap[eip]['RVA']
            record['Symbol'] = self.BreakpointsMap[eip]['Symbol']
            record['ThreadContext'] = self.Debugger.get_current_thread_context()
            esp = self.Debugger.get_stack_pointer()
            record['StackPointer'] = esp
            record['DumpTargets'] = []

            if record['Symbol']:
                self.Logger.info('> %s!%s (+%.8x) (%.8x)' % (
                                                record['Module'], 
                                                record['Symbol'], 
                                                record['RVA'], 
                                                record['Address']
                                            )
                                        )

            for dump_target in self.BreakpointsMap[eip]['DumpTargets']:
                if dump_target['Type'] == 'Operand':
                    dump_result = {}
                    dump_result['Operand'] = self.dump_operand(dump_target['Value'])
                    
                    if dump_target['DataType'] == 'Pointer':
                        try:
                            bytes = self.Debugger.get_bytes(parameter_values[index], 0x100)
                            dump_result['Bytes'] = base64.b64encode(bytes)
                        except:
                            pass

                elif dump_target['Type'] == 'Parameters':
                    (parameter_map, dump_result) = self.dump_parameters(dump_target['Value'])
                    
                elif dump_target['Type'] == 'ReturnParameters' and len(dump_target['Value'])>0:
                    return_address = self.Debugger.get_return_address()
                    for (parameter_name, dump_instruction) in dump_target['Value'].items():                    
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

                    bp = self.set_bp(return_address, self.handle_return_breakpoint)
                    self.Logger.info('\tSet Return BP on %.8x - %d' % (return_address, bp.getId()))

                elif dump_target['Type'] == 'Function':
                    dump_result = []
                    for (arg_name, arg_offset) in dump_target['Args']:
                        arg_addr = esp+arg_offset
                        (arg_value, )= pykd.loadDWords(arg_addr, 1)
                        try:
                            bytes = self.Debugger.get_bytes(arg_value, 0x100)
                            base64_bytes = base64.b64encode(bytes)
                        except:
                            base64_bytes = ''

                        dump_result.append({'Name': arg_name, 'Value': arg_value, 'Bytes': base64_bytes})

                else:
                    dump_result = []

                record['DumpTargets'].append({'Target': dump_target, 'Value': dump_result})

            if self.RecordsDB:
                self.RecordsDB.write_record(record)
            else:
                self.Logger.info(pprint.pformat(record))
        else:
            self.Logger.info('> BP @%.8x' % eip)

    def handle_return_breakpoint(self):
        eip = self.Debugger.get_instruction_pointer()
        if eip in self.ReturnBreakpointsMap:
            return_bp_info = self.ReturnBreakpointsMap[eip]

            try:
                bytes = self.Debugger.get_bytes(return_bp_info['Pointer'], return_bp_info['Length'])
            except:
                bytes = ''

            original_eip = return_bp_info['EIP']
            record = {'Address': original_eip}
            record['Type'] = 'Return'
            record['Module'] = self.BreakpointsMap[original_eip]['Module']
            record['RVA'] = self.BreakpointsMap[original_eip]['RVA']
            record['Symbol'] = self.BreakpointsMap[original_eip]['Symbol']
            record['ThreadContext'] = self.Debugger.get_current_thread_context()
            record['StackPointer'] = self.Debugger.get_stack_pointer()
            record['DumpTargets'] = [{
                                    'Target': return_bp_info, 
                                    'Value': base64.b64encode(bytes)
                                   }
                                  ]
                                  
            if record['Symbol']:
                self.Logger.info('> %s!%s (+%.8x) (%.8x) Return' % (
                                                record['Module'], 
                                                record['Symbol'], 
                                                record['RVA'], 
                                                record['Address']
                                            )
                                        )

            if self.RecordsDB:
                self.RecordsDB.write_record(record)
            else:
                self.Logger.info(pprint.pformat(record))



