import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import re
import pprint
import logging

import windbgtool.util

class Parser:
    cmd_pattern = re.compile("^[0-9]:[0-9][0-9][0-9]> (.*)")
    instruction_line_pattern = re.compile("(^[0-9a-fA-F]{8}) ([0-9a-fA-F]+)[ ]+([a-zA-Z]+)[ ]*(.*)")
    instruction64_line_pattern = re.compile("(^[0-9a-fA-F]{8}`[0-9a-fA-F]{8}) ([0-9a-fA-F]+)[ ]+([a-zA-Z]+)[ ]*(.*)")
    register_line_pattern = re.compile("[a-zA-Z0-9 ]* = [0-9a-fA-F]+")
    pointer_dump_pattern = re.compile("(.*) ([a-z]s:[0-9a-fA-F]{8}.*$)")
    pointer64_dump_pattern = re.compile("(.*) ([a-z]s:[0-9a-fA-F]{8}`[0-9a-fA-F]{8}.*$)")
    jump_line_pattern = re.compile("(.*) (\(.*\)) \[br = [0-9]+\]")
    jump_line_pattern2 = re.compile("([^ ]+)[ ]+\[br = [0-9]+\]")
    addresses_pattern_str = '^[\+]*[ ]+'
    addresses_pattern_str += '([0-9a-fA-F`]+)[ ]+' * 3
    #addresses_pattern_str += '([^ ]+)[ ]+' * 4
    addresses_pattern_str += '(.*)'
    addresses_pattern = re.compile(addresses_pattern_str)
    
    x_patterns = []
    x_patterns.append(re.compile('([a-fA-F0-9`]+)[ \t]+([^ \t]+)[ \t]*\(.*\)'))
    x_patterns.append(re.compile('([a-fA-F0-9`]+)[ \t]+([^ \t]+)[ \t]* = [ \t]*(.*)'))
    x_patterns.append(re.compile('([a-fA-F0-9`]+)[ \t]+(.+)[ \t]+\(.*\)'))
    current_location_pattern = re.compile('^([a-zA-Z0-9]+)!([a-zA-Z0-9_:]+)\+(0x[a-fA-F0-9]+):')
    current_location_with_source_pattern = re.compile('^([a-zA-Z0-9]+)!([a-zA-Z0-9_:]+)\+(0x[a-fA-F0-9]+) \[.*\]:')
    current_location_short_pattern = re.compile('^([a-zA-Z0-9]+)!([a-zA-Z0-9_:]+):')
    current_location_short_with_source_pattern = re.compile('^([a-zA-Z0-9]+)!([a-zA-Z0-9_:]+) \[.*\]:')
    lm_line = re.compile('^([0-9a-fA-F`]+)[ ]+([0-9a-fA-F`]+)[ ]+([^ \t]+)[ ]+\(([a-zA-Z ]+)\)[ ]*(.*)') #

    def __init__(self, filename = '', use_vex = False):
        self.logger = logging.getLogger(__name__)       
        self.command_results = []
        self.run_log_output_lines = []

        if filename:
            fd = open(filename, 'r')
            self.Data = fd.read()
            fd.close()
            self.parse_cmd_lines()
            self.parse_run_log_output()

    def parse_cmd_lines(self):
        seq = 0

        self.command_results = []
        cmd_line = ''
        cmd_output_lines = []
        for line in self.Data.splitlines():
            cmd_line_match = self.cmd_pattern.match(line)
            if cmd_line_match != None:
                parsed_cmd_lines = self.parse_cmd_output_lines(cmd_line, cmd_output_lines)
                self.command_results.append((seq, cmd_line, parsed_cmd_lines, cmd_output_lines))

                seq += 1
                cmd_line = cmd_line_match.group(1)
                cmd_output_lines = []
            else:
                cmd_output_lines.append(line)

        parsed_cmd_lines = self.parse_cmd_output_lines(cmd_line, cmd_output_lines)
        self.command_results.append((seq, cmd_line, parsed_cmd_lines, cmd_output_lines))

    def parse_cmd_output_lines(self, cmd, result_lines):
        cmd_toks = cmd.split()
        if len(cmd_toks) == 0:
            return

        parsed_results = []
        if cmd_toks[0] == 'g' or cmd_toks[0] == 't' or cmd_toks[0] == 'p' or cmd_toks[0] == 'pr' or cmd_toks[0] == 'u':
            parsed_results = self.parse_instruction_lines(result_lines)
        elif cmd_toks[0].startswith("lm"):
            parsed_results = self.parse_lm(result_lines)
            pprint.pprint(parsed_results)
        elif cmd_toks[0] == 'k':
            pass #TODO: put comments where any call stack matches

        return parsed_results

    def parse_register_line(self, line):
        registers = {}
        m = self.register_line_pattern.match(line)
        if m != None:
            for reg_line in line.split():
                toks = reg_line.split('=')                
                
                if len(toks) == 1:
                    registers[toks[0]] = 1
                elif len(toks) == 2:
                    registers[toks[0]] = windbgtool.util.convert_to_int(toks[1])
        return registers

    def parse_lm(self, result_lines):
        parsed_results = []
        for line in result_lines:
            m = self.lm_line.match(line)
            if m != None:
                parsed_results.append({
                    'Start': m.group(1), 
                    'End': m.group(2), 
                    'Module Name': m.group(3), 
                    'Symbol Status': m.group(4), 
                    'Symbol Path': m.group(5)
                })
        return parsed_results
        
    def parse_instruction_lines(self, result_lines):
        parsed_results = []
        registers = {}
        current_location = []
        for line in result_lines:
            m = self.instruction64_line_pattern.match(line)
            if m != None:
                parsed_results.append(
                    {
                        'Address': windbgtool.util.convert_to_int(m.group(1)), 
                        'Bytes': windbgtool.util.hex_string_to_bytes(m.group(2)), 
                        'Op': m.group(3), 
                        'Operands': self.parse_operand_line(m.group(4)), 
                        'Registers': registers, 
                        'Location': current_location
                    }
                )
                registers = {}
                current_location = []
                continue

            m = self.instruction_line_pattern.match(line)
            if m != None:
                parsed_results.append(
                    {
                        'Address': windbgtool.util.convert_to_int(m.group(1)), 
                        'Bytes': windbgtool.util.hex_string_to_bytes(m.group(2)), 
                        'Op': m.group(3), 
                        'Operands': self.parse_operand_line(m.group(4)), 
                        'Registers': registers, 
                        'Location': current_location
                    }
                )
                registers = {}
                current_location = []
                continue
                
            registers = self.parse_register_line(line)
            if len(registers)>0:
                continue

            m = self.current_location_pattern.match(line)
            if m != None:
                current_location = ((m.group(1), m.group(2), windbgtool.util.convert_to_int(m.group(3))))
                continue

            m = self.current_location_with_source_pattern.match(line)
            if m != None:
                current_location = ((m.group(1), m.group(2), windbgtool.util.convert_to_int(m.group(3))))
                continue

            m = self.current_location_short_pattern.match(line)
            if m != None:
                current_location = ((m.group(1), m.group(2), 0))
                continue

            m = self.current_location_short_with_source_pattern.match(line)
            if m != None:
                current_location = ((m.group(1), m.group(2), 0))
                continue
            
        return parsed_results
        
    def parse_t(self, data):
        return self.parse_instruction_lines(data.splitlines())
        
    def parse_operand_line(self, operand_line):
        operand = operand_line
        pointer_line = ''
        m = self.pointer64_dump_pattern.match(operand_line)
        if m != None:
            operand = m.group(1)
            pointer_line = m.group(2)
        else:
            m = self.pointer_dump_pattern.match(operand_line)
            if m != None:
                operand = m.group(1)
                pointer_line = m.group(2)
            else:
                m = self.jump_line_pattern.match(operand_line)
                if m != None:
                    operand = m.group(1)
                else:
                    m = self.jump_line_pattern2.match(operand_line)
                    if m != None:
                        operand = m.group(1)            

        operands = operand.split(', ')    
        return (operands, pointer_line)

    def parse_x(self, data):
        map = {}
        for line in data.splitlines():
            try:
                name = ''
                for pattern in self.x_patterns:
                    m = pattern.match(line)
                    if m:
                        address = windbgtool.util.convert_to_int(m.group(1), 0x10)
                        name = m.group(2)
                        map[address] = name
                        break

                if name == '':
                    self.logger.debug('parse_x: none matched line - %s' % line)
            except:
                pass
        return map

    def parse_lmvm(self, data):
        info = {}
        for line in data.splitlines():
            toks = re.split(":[ ]+", re.sub("^[ ]+", "", line))
            
            if len(toks) == 2:
                info[toks[0]] = toks[1]
        return info
        
    def parse_address(self, data, debug = 0):
        lines = data.splitlines()
        address_list = []
        for line in lines:
            mem_info = {}
            m = self.addresses_pattern.match(line)
            if m:
                mem_states = ('MEM_COMMIT', 'MEM_FREE', 'MEM_RESERVE')
                toks = re.split('[ ]+', m.groups()[3], maxsplit = 5)

                mem_type = ''
                mem_state = ''
                protect = ''
                i = 0
                for tok in toks:
                    if tok in mem_states:
                        mem_state = tok
                    elif tok.startswith('MEM_'):
                        mem_type = tok
                    elif tok.startswith('PAGE_'):
                        protect = tok
                    else:
                        usage = tok
                        break
                    i += 1

                
                comment = ' '.join(toks[i+1:])
                mem_info = {
                    'BaseAddr': windbgtool.util.convert_to_int(m.groups()[0]), 
                    'EndAddr': windbgtool.util.convert_to_int(m.groups()[1]), 
                    'RgnSize': windbgtool.util.convert_to_int(m.groups()[2]), 
                    'Type': mem_type, 
                    'State': mem_state, 
                    'Protect': protect, 
                    'Usage': usage, 
                    'Comment': comment
                }

            if len(mem_info)>0:
                if debug>0:
                    pprint.pprint(mem_info)
                    print('')
                address_list.append(mem_info)
            else:
                if debug>0:
                    print(line)

        return address_list

    def parse_address_details(self, data, debug = 0):
        name_convert_map = {
            'Module name': 'Module Name'
        }

        lines = data.splitlines()
        address_details = {}
        for line in lines:
            pattern = re.compile("([A-Za-z ]+):[ \t]+([^ \t]+)(.*)")

            m = pattern.match(line)
            if m:
                groups = m.groups()
                value = groups[1].replace('`','')

                name = groups[0]
                if name in name_convert_map:
                    name = name_convert_map[name]
                address_details[name] = value
            else:
                pass
        return address_details

    def dump(self, level = 0):
        for (seq, cmd_line, parsed_results, result_lines) in self.command_results:
            print('* %.4d: %s' % (seq , cmd_line))
            
            if parsed_results != None:
                for parsed_result in parsed_results:
                    if not 'Address' in parsed_result:
                        continue
                    addr = parsed_result['Address']
                    op = parsed_result['Op']
                    operands = parsed_result['Operands'][0]
                    bytes = parsed_result['Bytes']

                    print('>> Disasm: %.8x %s %s' % (addr, op, ', '.join(operands)))
                    print('\t', windbgtool.util.bytes_to_hex_string(bytes))
                    print('')
                print('')
                
            if level>0:
                pprint.pprint(result_lines)
                print('')
                

    def skip_spaces(self, line):
        m = re.search('^[ \t]+', line)        
        if m:
            line = line[m.end():]
        return line

    # 76b89910 55              push    ebp
    def parse_disassembly_line(self, line):
        parsed_disasm_line = {'Line':line}
        # Address
        m = re.search('^([0-9a-fA-F]+)[ \t]+', line)
        
        if m == None or m.end() == 0:
            return None

        parsed_disasm_line['Address'] = convert_to_int(m.group(1), 16)
        line = line[m.end():]

        # Hex bytes
        insn_bytes = ''
        while 1:
            m = re.search('^([0-9a-fA-F][0-9a-fA-F])', line)
            
            if not m:
                break

            insn_bytes += chr(int(line[:m.end()], 0x10))
            line = line[m.end():]

        parsed_disasm_line['Bytes'] = insn_bytes
        line = self.skip_spaces(line)
            
        m = re.search('^[^ \t]+', line)
        if m:
            op = line[:m.end()]
            if op.endswith(':') or op.endswith(';'):
                return

            parsed_disasm_line['Op'] = op
            line = line[m.end():]

        line = self.skip_spaces(line)
        operands = []
        for operand in re.split(', [ \t]*', line):
            operand = operand.strip()
            operands.append(operand)
        parsed_disasm_line['Operands'] = operands
        
        return parsed_disasm_line

    def parse_run_log_output(self):
        bp_point = {}
        self.run_log_output_lines = []
        for line in self.Data.splitlines():
            # * :003123ec call eax
            m = re.match('^\* ([^:]*):([a-fA-F0-9]+) (.*)', line)
            if m:
                self.run_log_output_lines.append(bp_point)
                bp_point = {}
                bp_point['Function'] = m.group(1)
                bp_point['Address'] = windbgtool.util.convert_to_int(m.group(2), 16)            
                bp_point['Disasm Line'] = m.group(3)
                continue
                    
            # kernel32!LocalAlloc:
            m = re.match('^([^!]+)!(.*):$', line)
            if m:
                (module, func_name) = (m.group(1), m.group(2))
                bp_point['Target Module'] = module
                bp_point['Target Function'] = func_name
                continue
                
            # 0029ea58  00000040
            m = re.match('^([0-9a-fA-F]{8})  ([0-9a-fA-F]{8})', line)
            if m:
                (address, value) = (windbgtool.util.convert_to_int(m.group(1), 16), windbgtool.util.convert_to_int(m.group(2), 16))
                if not bp_point.has_key('Memory'):
                    bp_point['Memory'] = []
                bp_point['Memory'].append((address, value))
                continue
                
            parsed_disasm_line = self.parse_disassembly_line(line)
            
            if parsed_disasm_line != None:
                if not bp_point.has_key('DisasmLines'):
                    bp_point['DisasmLines'] = []
                bp_point['DisasmLines'].append(parsed_disasm_line)
                continue

        self.run_log_output_lines.append(bp_point)

    def parse_run_log_output_lines(self):
        echo_cmd_maps = {}
        for line in self.Data.splitlines():
            (bp_cmd, addr, cmd) = line.split(' ', 2)
            cmds = cmd.split(';')
            echo_cmd_maps.setdefault(cmds[0], []).append((bp_cmd, addr, cmd))

        keys = echo_cmd_maps.keys()
        keys.sort()
        for key in keys:
            for (bp_cmd, addr, cmd) in echo_cmd_maps[key]:
                print(bp_cmd, addr, cmd)
                print('%s %.16X %s' % (bp_cmd, windbgtool.util.convert_to_int(addr, 16)+(new_addr-orig_addr), cmd))
                
    def dump_run_log_output(self):
        for log_output in self.run_log_output_lines:
            if not log_output.has_key('Address'):
                continue

            address = log_output['Address']
            
            lines = []
            
            function = ''
            if log_output.has_key('Target Module'):
                function += log_output['Target Module']
            if log_output.has_key('Target Function'):
                function += '!' + log_output['Target Function']
            lines.append(function)
                
            for disasm_line in log_output['DisasmLines']:
                lines.append(disasm_line['Line'])

            print('%.8x: ' % address)
            prefix = '\t'
            for line in lines:
                print(prefix+line)

if __name__ == '__main__':
    import sys
    import os
    from optparse import OptionParser, Option

    parser = OptionParser(usage = "usage: %prog [options] args")    
    parser.add_option("-a", "--address_list", dest = "address_list", type = "string", default = "", metavar = "ADDRESS_LIST", help = "Set address list filename")
    parser.add_option("-r", "--run_log", dest = "run_log", type = "string", default = "", metavar = "RUN_LOG", help = "Parser run log file")

    (options, args) = parser.parse_args(sys.argv)

    use_vex = True
    if options.address_list:
        fd = open(options.address_list, 'r')
        data = fd.read()
        fd.close()
        log_parser = Parser(use_vex = use_vex)
        pprint.pprint(log_parser.parse_address(data))
    elif options.run_log:
        parser = Parser(options.run_log)
        parser.dump_run_log_output()
    else:
        filename = args[1]
        log_parser = Parser(filename, use_vex = use_vex)
        log_parser.dump()
