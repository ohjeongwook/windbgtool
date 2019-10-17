import sys
import pprint
import re

class Generator:
    def __init__(self,target_base_address = 0,src_base_address = 0,arch = 'x86',exclusions = None):
        self.Arch = arch       
        self.TargetBaseAddress = target_base_address
        self.SrcBaseAddress = src_base_address
        self.ImageBaseDiff = self.TargetBaseAddress-self.SrcBaseAddress

        if exclusions!=None:
            self.Exclusions = exclusions
        else:
            self.Exclusions = {
                'cs:HeapAlloc':1,
                'cs:HeapCreate':1,
                'cs:DecodePointer':1,
                'cs:EncodePointer':1
            }

    def GetOperandStr(self,operand):
        operand_type = operand['Type']
        operand_str = ''
        if operand.has_key('Value'):
            operand_str = str(operand['Value'])
        elif operand.has_key('Address'):
            operand_str = '%.8x' % (operand['Address'])
        elif operand_type == 'Displacement':        
            if operand['Index']:
                index_str = '+'+operand['Index']
            else:
                index_str = ''
            offset = operand['Offset']
            if offset:
                if operand['Offset'] & 0x80000000:
                    offset = (0x100000000-offset)*-1

            if offset>0:
                operand_str = '%s%s+%x'% (operand['Base'], index_str, offset)
            else:
                operand_str = '%s%s%x'% (operand['Base'], index_str, offset)
        
        return operand_str

    def GenerateCommandsForInstruction(self,instruction,func_name = ''):
        windbg_commands = []
        current = instruction['Address']
        op = instruction['Op']

        disasm_cmd = ''
        operand_dump_commands = []
        operand_str_list = []
        for operand in instruction['Operands']:
            operand_str = self.GetOperandStr(operand)
            operand_str_list.append(operand_str)

            operand_type = operand['Type']
            if not self.Exclusions.has_key(operand_str):
                if operand_type == 'Register':
                    disasm_cmd+='u @%s L5; ' % (operand_str)
                elif operand_type == 'Memory' or operand_type == 'Displacement':
                    disasm_cmd+='u poi(%s) L5; ' % (operand_str)
                elif operand_type == 'Near':
                    pass
                else:
                    pass

        rebased_address = self.ImageBaseDiff+current
        dmp_command = 'bp %.8x ".echo * %s:%.8x %s %s; %s;' % (
                                            rebased_address, 
                                            func_name,
                                            rebased_address, 
                                            op, 
                                            ','.join(operand_dump_commands),
                                            disasm_cmd
                                        )

        if self.Arch == 'x86':
            dmp_command+='dps @esp L10'
        else:
            dmp_command+='r @rcx, @rdx, @r8, @r9'

        dmp_command += '; .echo; g"'
        windbg_commands.append(dmp_command)

        if op == 'call':
            next_address = current+instruction['Size']
            ret_command = 'bp %.8x ".echo * %.16x %s %s Return;' % (
                                                next_address+self.ImageBaseDiff, 
                                                rebased_address, 
                                                op, 
                                                ','.join(operand_str_list)
                                            )
            if self.Arch == 'x86':
                ret_command += "r @eax;"
            else:
                ret_command += "r @rax;"

            ret_command += '; .echo; g"'
            windbg_commands.append(ret_command)

        return windbg_commands

    def GenerateCommandsForInstructions(self,instructions,func_name = ''):
        windbg_commands = []        
        for instruction in instructions:
            windbg_commands+=self.GenerateCommandsForInstruction(instruction,func_name = func_name)
        return windbg_commands

    def SaveBreakpoints(self,filename,breakpoints):
        fd = open(filename,'w')

        for breakpoint in breakpoints:
            lines = []
            if breakpoint['Type'] == 'Instruction':
                lines+=self.GenerateCommandsForInstruction(breakpoint)
            elif breakpoint['Type'] == 'Function':
                lines.append('bp %.8x ".echo * %s (%.8x); ~#; kp 5; .echo ; g"' % (
                                                breakpoint['Address'],
                                                name,
                                                breakpoint['Address']
                                            )
                                        )
            else:
                line = ''

            for line in lines:
                print line
                fd.write(line+'\n')
        fd.close()

if __name__ == '__main__':
    pass

