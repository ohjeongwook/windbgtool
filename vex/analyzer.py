import pprint
from capstone import *
from capstone.x86 import *

class Disassembler:
    DebugLevel = 0
    def __init__(self, arch = 'x86', mode = 64):
        if arch == 'x86':
            arch_value = CS_ARCH_X86
            if mode == 64:
                mode_value = CS_MODE_64
            else:
                mode_value = CS_MODE_32

        self.capstone = Cs(arch_value, mode_value)
        self.capstone.detail = True

    def Disasm(self, bytes, address):
        instructions = []
        for insn in self.capstone.disasm(bytes, address):
            if self.DebugLevel>0:
                print("0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))
            
            operands = []
            for inst in insn.operands:
                operand = {'Type': inst.type}
                if inst.type == X86_OP_REG:
                    operand['TypeStr'] = 'Reg'
                    operand['Value'] = insn.reg_name(inst.value.reg)
                elif inst.type == X86_OP_IMM:
                    operand['TypeStr'] = 'Imm'
                    operand['Value'] = '%x' % inst.value.imm
                elif inst.type == X86_OP_MEM:
                    operand['TypeStr'] = 'Mem'
                    operand['Value'] = ''
                    if inst.value.mem.base != 0:
                        operand['Value'] += 'base: '+insn.reg_name(inst.value.mem.base)
                    if inst.value.mem.index != 0:
                        operand['Value'] += ' index: '+insn.reg_name(inst.value.mem.index)
                    operand['Value'] += ' scale: %.8x' % inst.value.mem.scale
                    operand['Value'] += ' disp: %.8x' % inst.value.mem.disp
                elif inst.type == X86_OP_FP:
                    operand['TypeStr'] = 'Fp'
                    operand['Value'] = inst.value.fp

                if self.DebugLevel>0:
                    print('\t', pprint.pformat(operand))

                operands.append(operand)
            instructions.append({'Opcode': insn.mnemonic, 'Operands': operands})
        return instructions

    def GetJumpAddress(self, bytes, address):
        crefs = []
        for insn in self.capstone.disasm(bytes, address):
            #print("0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))
            crefs.append(address+len(insn.bytes))
            for operand in insn.operands:
                if operand.type == X86_OP_IMM:
                    operand_type = 'Imm'
                    crefs.append(operand.value.imm)
        return crefs

if __name__ == '__main__':
    import os
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

    import util.common
    from optparse import OptionParser, Option

    parser = OptionParser(usage = "usage: %prog [options] args")
    parser.add_option("-b", "--bytes", dest = "bytes", type = "string", default = "", metavar = "BYTES", help = "Set bytes")
    parser.add_option("-a", "--address", dest = "address", type = "string", default = "0", metavar = "ADDRESS", help = "Set address")

    (options, args) = parser.parse_args(sys.argv)

    disasm = Analyzer()
    bytes = Util.Common.HexStrToBytes(options.bytes)
    address = int(options.address, 16)
    
    for instruction in disasm.Disasm(bytes, address):
        print(instruction['Opcode'])
        for operand in instruction['Operands']:
            print(operand['Value'])

    for cref in disasm.GetJumpAddress(bytes, address):
        print('cref: %.8x' % cref)
