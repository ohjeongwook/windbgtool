import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import re
import pprint
import logging
import util.common

try:
    import vex.windbg
except:
    pass

class Parser:
    CmdPattern = re.compile("^[0-9]:[0-9][0-9][0-9]> (.*)")
    InstructionLinePattern = re.compile("(^[0-9a-fA-F]{8}) ([0-9a-fA-F]+)[ ]+([a-zA-Z]+)[ ]*(.*)")
    Instruction64LinePattern = re.compile("(^[0-9a-fA-F]{8}`[0-9a-fA-F]{8}) ([0-9a-fA-F]+)[ ]+([a-zA-Z]+)[ ]*(.*)")
    RegisterLinePattern = re.compile("[a-zA-Z0-9 ]* = [0-9a-fA-F]+")
    PointerDumpPattern = re.compile("(.*) ([a-z]s:[0-9a-fA-F]{8}.*$)")
    Pointer64DumpPattern = re.compile("(.*) ([a-z]s:[0-9a-fA-F]{8}`[0-9a-fA-F]{8}.*$)")
    JmpLinePattern = re.compile("(.*) (\(.*\)) \[br = [0-9]+\]")
    JmpLinePattern2 = re.compile("([^ ]+)[ ]+\[br = [0-9]+\]")
    AddressesPattern = re.compile('^[\+]*[ ]+([0-9a-fA-F`]+)[ ]+([0-9a-fA-F`]+)[ ]+([0-9a-fA-F`]+)[ ]+([^ ]+)[ ]+([^ ]+)[ ]+([^ ]+)[ ]+([^ ]+)[ ]+(.*)')
    Addresses2Pattern = re.compile('^[\+]*[ ]+([0-9a-fA-F`]+)[ ]+([0-9a-fA-F`]+)[ ]+([0-9a-fA-F`]+)[ ]+([^ ]+)[ ]+([^ ]+)[ ]+([^ ]+)[ ]+(.*)')
    
    XPatterns = []
    XPatterns.append(re.compile('([a-fA-F0-9`]+)[ \t]+([^ \t]+)[ \t]*\(.*\)'))
    XPatterns.append(re.compile('([a-fA-F0-9`]+)[ \t]+([^ \t]+)[ \t]* = [ \t]*(.*)'))
    XPatterns.append(re.compile('([a-fA-F0-9`]+)[ \t]+(.+)[ \t]+\(.*\)'))
    CurrentLocationPattern = re.compile('^([a-zA-Z0-9]+)!([a-zA-Z0-9_:]+)\+(0x[a-fA-F0-9]+):')
    CurrentLocationWithSourcePattern = re.compile('^([a-zA-Z0-9]+)!([a-zA-Z0-9_:]+)\+(0x[a-fA-F0-9]+) \[.*\]:')
    CurrentLocationShortPattern = re.compile('^([a-zA-Z0-9]+)!([a-zA-Z0-9_:]+):')
    CurrentLocationShortWithSourcePattern = re.compile('^([a-zA-Z0-9]+)!([a-zA-Z0-9_:]+) \[.*\]:')
    LMLine = re.compile('^([0-9a-fA-F`]+)[ ]+([0-9a-fA-F`]+)[ ]+([^ \t]+)[ ]+\(([a-zA-Z ]+)\)[ ]*(.*)') #

    def __init__(self,filename = '',use_vex = False):
        self.logger = logging.getLogger(__name__)
        if "vex.windbg" not in sys.modules:
            self.UseVex = False
        self.UseVex = use_vex
        
        self.CmdResults = []
        self.RunLogOutputLines = []

        if filename:
            fd = open(filename,'r')
            self.Data = fd.read()
            fd.close()
            self.ParseCmdLines()
            self.ParseRunLogOutput()

    def ParseCmdLines(self):
        seq = 0

        self.CmdResults = []
        cmd_line = ''
        cmd_output_lines = []
        for line in self.Data.splitlines():
            cmd_line_match = self.CmdPattern.match(line)
            if cmd_line_match!=None:
                parsed_cmd_lines = self.ParseCmdOutputLines(cmd_line,cmd_output_lines)
                self.CmdResults.append((seq,cmd_line, parsed_cmd_lines, cmd_output_lines))

                seq+=1
                cmd_line = cmd_line_match.group(1)
                cmd_output_lines = []
            else:
                cmd_output_lines.append(line)

        parsed_cmd_lines = self.ParseCmdOutputLines(cmd_line,cmd_output_lines)
        self.CmdResults.append((seq,cmd_line, parsed_cmd_lines, cmd_output_lines))

    def ParseCmdOutputLines(self,cmd,result_lines):
        cmd_toks = cmd.split()
        if len(cmd_toks) == 0:
            return

        parsed_results = []
        if cmd_toks[0] == 'g' or cmd_toks[0] == 't' or cmd_toks[0] == 'p' or cmd_toks[0] == 'pr' or cmd_toks[0] == 'u':
            parsed_results = self.ParseInstructionLines(result_lines)
        elif cmd_toks[0].startswith("lm"):
            parsed_results = self.ParseLM(result_lines)
            pprint.pprint(parsed_results)
        elif cmd_toks[0] == 'k':
            pass #TODO: put comments where any call stack matches

        return parsed_results

    def ParseRegisterLine(self,line):
        registers = {}
        m = self.RegisterLinePattern.match(line)
        if m!=None:
            for reg_line in line.split():
                toks = reg_line.split(' = ')                
                
                if len(toks) == 1:
                    registers[toks[0]] = 1
                elif len(toks) == 2:
                    registers[toks[0]] = util.common.Int(toks[1])
        return registers

    def ParseLM(self,result_lines):
        parsed_results = []
        for line in result_lines:
            m = self.LMLine.match(line)
            if m!=None:
                parsed_results.append({
                    'Start': m.group(1),
                    'End': m.group(2),
                    'Module Name': m.group(3),
                    'Symbol Status': m.group(4),
                    'Symbol Path': m.group(5)
                })
        return parsed_results
        
    def ParseInstructionLines(self,result_lines):
        parsed_results = []
        registers = {}
        current_location = []
        for line in result_lines:
            m = self.Instruction64LinePattern.match(line)
            if m!=None:
                parsed_results.append(
                    {
                        'Address': util.common.Int(m.group(1)), 
                        'Bytes': util.common.HexStrToBytes(m.group(2)),
                        'Op': m.group(3),
                        'Operands': self.ParseOperandLine(m.group(4)), 
                        'Registers': registers, 
                        'Location': current_location
                    }
                )
                registers = {}
                current_location = []
                continue

            m = self.InstructionLinePattern.match(line)
            if m!=None:
                parsed_results.append(
                    {
                        'Address': util.common.Int(m.group(1)), 
                        'Bytes': util.common.HexStrToBytes(m.group(2)),
                        'Op': m.group(3),
                        'Operands': self.ParseOperandLine(m.group(4)), 
                        'Registers': registers, 
                        'Location': current_location
                    }
                )
                registers = {}
                current_location = []
                continue
                
            registers = self.ParseRegisterLine(line)
            if len(registers)>0:
                continue

            m = self.CurrentLocationPattern.match(line)
            if m!=None:
                current_location = ((m.group(1), m.group(2), util.common.Int(m.group(3))))
                continue

            m = self.CurrentLocationWithSourcePattern.match(line)
            if m!=None:
                current_location = ((m.group(1), m.group(2), util.common.Int(m.group(3))))
                continue

            m = self.CurrentLocationShortPattern.match(line)
            if m!=None:
                current_location = ((m.group(1), m.group(2), 0))
                continue

            m = self.CurrentLocationShortWithSourcePattern.match(line)
            if m!=None:
                current_location = ((m.group(1), m.group(2), 0))
                continue
            
        return parsed_results
        
    def ParseT(self,data):
        return self.ParseInstructionLines(data.splitlines())
        
    def ParseOperandLine(self,operand_line):
        operand = operand_line
        pointer_line = ''
        m = self.Pointer64DumpPattern.match(operand_line)
        if m!=None:
            operand = m.group(1)
            pointer_line = m.group(2)
        else:
            m = self.PointerDumpPattern.match(operand_line)
            if m!=None:
                operand = m.group(1)
                pointer_line = m.group(2)
            else:
                m = self.JmpLinePattern.match(operand_line)
                if m!=None:
                    operand = m.group(1)
                else:
                    m = self.JmpLinePattern2.match(operand_line)
                    if m!=None:
                        operand = m.group(1)            

        operands = operand.split(',')    
        return (operands, pointer_line)

    def ParseX(self,data):
        map = {}
        for line in data.splitlines():
            try:
                name = ''
                for pattern in self.XPatterns:
                    m = pattern.match(line)
                    if m:
                        address = util.common.Int(m.group(1),0x10)
                        name = m.group(2)
                        map[address] = name
                        break

                if name == '':
                    self.logger.debug('ParseX: none matched line - %s' % line)
            except:
                pass
        return map

    def ParseLMVM(self,data):
        info = {}
        for line in data.splitlines():
            toks = re.split(":[ ]+",re.sub("^[ ]+","",line))
            
            if len(toks) == 2:
                info[toks[0]] = toks[1]
        return info
        
    def ParseAddress(self, data, debug = 0):
        lines = data.splitlines()
        address_list = []
        for line in lines:
            mem_info = {}
            m = self.AddressesPattern.match(line)
            if m:
                mem_info = {
                    'BaseAddr': util.common.Int(m.groups()[0]),
                    'EndAddr': util.common.Int(m.groups()[1]),
                    'RgnSize': util.common.Int(m.groups()[2]),
                    'Type': m.groups()[3],
                    'State': m.groups()[4],
                    'Protect': m.groups()[5],
                    'Usage': m.groups()[6],
                    'Comment': m.groups()[7]
                }
                pass
            else:
                m = self.Addresses2Pattern.match(line)
                if m:
                    mem_info = {
                        'BaseAddr': util.common.Int(m.groups()[0]),
                        'EndAddr': util.common.Int(m.groups()[1]),
                        'RgnSize': util.common.Int(m.groups()[2]),
                        'Type': m.groups()[3],
                        'State': m.groups()[4],
                        'Usage': m.groups()[5],
                        'Comment': m.groups()[6]
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

    def Dump(self,level = 0):
        for (seq, cmd_line, parsed_results, result_lines) in self.CmdResults:
            print('* %.4d: %s' % (seq , cmd_line))
            
            if parsed_results!=None:
                for parsed_result in parsed_results:
                    if not parsed_result.has_key('Address'):
                        continue
                    addr = parsed_result['Address']
                    op = parsed_result['Op']
                    operands = parsed_result['Operands'][0]
                    bytes = parsed_result['Bytes']

                    print('>> Disasm: %.8x %s %s' % (addr, op, ','.join(operands)))
                    print('\t', util.common.BytesToHexStr(bytes))
                    if self.UseVex:
                        parser = vex.windbg.Parser(bytes,addr,'x64')
                        (read_commands,write_commands) = parser.GetWinDBGDumpCommands()
                        
                        print('>> Commands: ', read_commands,write_commands)
                    print('')
                print('')
                
            if level>0:
                pprint.pprint(result_lines)
                print('')
                

    def SkipSpaces(self,line):
        m = re.search('^[ \t]+', line)        
        if m:
            line = line[m.end():]
        return line

    # 76b89910 55              push    ebp
    def ParseDisasmLine(self,line):
        parsed_disasm_line = {'Line':line}
        # Address
        m = re.search('^([0-9a-fA-F]+)[ \t]+', line)
        
        if m == None or m.end() == 0:
            return None

        parsed_disasm_line['Address'] = int(m.group(1),16)
        line = line[m.end():]

        # Hex bytes
        insn_bytes = ''
        while 1:
            m = re.search('^([0-9a-fA-F][0-9a-fA-F])', line)
            
            if not m:
                break

            insn_bytes+=chr(int(line[:m.end()],0x10))
            line = line[m.end():]

        parsed_disasm_line['Bytes'] = insn_bytes
        line = self.SkipSpaces(line)
            
        m = re.search('^[^ \t]+', line)
        if m:
            op = line[:m.end()]
            if op.endswith(':') or op.endswith(';'):
                return

            parsed_disasm_line['Op'] = op
            line = line[m.end():]

        line = self.SkipSpaces(line)
        operands = []
        for operand in re.split(',[ \t]*',line):
            operand = operand.strip()
            operands.append(operand)
        parsed_disasm_line['Operands'] = operands
        
        return parsed_disasm_line

    def ParseRunLogOutput(self):
        bp_point = {}
        self.RunLogOutputLines = []
        for line in self.Data.splitlines():
            # * :003123ec call eax
            m = re.match('^\* ([^:]*):([a-fA-F0-9]+) (.*)',line)
            if m:
                self.RunLogOutputLines.append(bp_point)
                bp_point = {}
                bp_point['Function'] = m.group(1)
                bp_point['Address'] = int(m.group(2),16)            
                bp_point['Disasm Line'] = m.group(3)
                continue
                    
            # kernel32!LocalAlloc:
            m = re.match('^([^!]+)!(.*):$',line)
            if m:
                (module, func_name) = (m.group(1), m.group(2))
                bp_point['Target Module'] = module
                bp_point['Target Function'] = func_name
                continue
                
            # 0029ea58  00000040
            m = re.match('^([0-9a-fA-F]{8})  ([0-9a-fA-F]{8})',line)
            if m:
                (address, value) = (int(m.group(1),16), int(m.group(2),16))
                if not bp_point.has_key('Memory'):
                    bp_point['Memory'] = []
                bp_point['Memory'].append((address,value))
                continue
                
            parsed_disasm_line = self.ParseDisasmLine(line)
            
            if parsed_disasm_line!=None:
                if not bp_point.has_key('DisasmLines'):
                    bp_point['DisasmLines'] = []
                bp_point['DisasmLines'].append(parsed_disasm_line)
                continue

        self.RunLogOutputLines.append(bp_point)

    def ParseRunLogOutputLines(self):
        echo_cmd_maps = {}
        for line in self.Data.splitlines():
            (bp_cmd,addr,cmd) = line.split(' ', 2)
            cmds = cmd.split(';')
            echo_cmd_maps.setdefault(cmds[0],[]).append((bp_cmd,addr,cmd))

        keys = echo_cmd_maps.keys()
        keys.sort()
        for key in keys:
            for (bp_cmd,addr,cmd) in echo_cmd_maps[key]:
                print(bp_cmd,addr,cmd)
                print('%s %.16X %s' % (bp_cmd,int(addr,16)+(new_addr-orig_addr),cmd))
                
    def DumpRunLogOutput(self):
        for log_output in self.RunLogOutputLines:
            if not log_output.has_key('Address'):
                continue

            address = log_output['Address']
            
            lines = []
            
            function = ''
            if log_output.has_key('Target Module'):
                function+=log_output['Target Module']
            if log_output.has_key('Target Function'):
                function+='!' + log_output['Target Function']
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
    parser.add_option("-a","--address_list",dest = "address_list",type = "string",default = "",metavar = "ADDRESS_LIST",help = "Set address list filename")
    parser.add_option("-r","--run_log",dest = "run_log",type = "string",default = "",metavar = "RUN_LOG",help = "Parser run log file")

    (options,args) = parser.parse_args(sys.argv)

    use_vex = True
    if options.address_list:
        fd = open(options.address_list,'r')
        data = fd.read()
        fd.close()
        log_parser = Parser(use_vex = use_vex)
        pprint.pprint(log_parser.ParseAddress(data))
    elif options.run_log:
        parser = Parser(options.run_log)
        parser.DumpRunLogOutput()
    else:
        filename = args[1]
        log_parser = Parser(filename,use_vex = use_vex)
        log_parser.Dump()

