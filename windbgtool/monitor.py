import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import re
import time
import json
import pprint
import logging
import base64

import pykdfix
import windbgtool.debugger

class Breakpoints:
    def __init__(self):
        self.debugger = windbgtool.debugger.DbgEngine()
        self.breakpoints_map = {}       
        self.return_breakpoints_map = {}

    def handle_breakpoint(self):
        eip = self.debugger.get_instruction_pointer()

        if eip in self.breakpoints_map:
            pass

    def __add_breakpoint(self, addr):
        if not address in self.breakpoints_map:
            self.breakpoints_map[address] = {}

        self.breakpoints_map[address]['bp'] = pykd.setBp(int(addr), self.handle_breakpoint)

    def __del__(self):
        self.clear()

    def clear(self):
        for (addr, bp) in self.breakpoints_map.items():
            bp.remove()
            del self.breakpoints_map[addr]
            
    def add(self, symbol, handler = None):
        address = self.debugger.resolve_symbol(symbol)
        
        if address>0:
            self.__add_breakpoint(address)
            self.breakpoints_map[address]['Symbol'] = symbol
