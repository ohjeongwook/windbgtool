import sys
import pprint
from idaapi import *
from idc import *

import idaapi
import idautils
from idaapi import PluginForm
from PyQt5 import QtGui, QtCore, QtWidgets
import pprint
from TraceLoader import *
import IDA
import json
from Config import *
import PyVexAnalyzer
import Common

ida_util = IDA.Util()

for instruction_info in ida_util.DumpInstructions():
	addr = instruction_info['Address']
	bytes = instruction_info['Bytes']

	print('>> Disasm: %.8x %s' % (addr, instruction_info['Disasm']))
	parser = PyVexAnalyzer.Parser(bytes, addr, 'x64')
	parser.Print(False)
