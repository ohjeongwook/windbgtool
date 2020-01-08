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
import log
import breakpoints

class PyKdDebugger(pykd.eventHandler):
    def __init__(self, executable_path = '', breakpoint_db = None):
        pykd.startProcess(executable_path)

        pykd.eventHandler.__init__(self)

        self.logger = logging.getLogger(__name__)
        out_hdlr = logging.StreamHandler(sys.stdout)
        out_hdlr.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
        out_hdlr.setLevel(logging.INFO)
        self.logger.addHandler(out_hdlr)
        self.logger.setLevel(logging.INFO)       

        self.BreakpointsMap = {}

        if breakpoint_db:
            breakpoints_db = breakpoints.DB(breakpoint_db)
            breakpoints_db.load()
            self.set_bp(breakpoints_db.Breakpoints)

    def set_bp(self, breakpoints):
        for breakpoint in breakpoints:
            if breakpoint['Type'] == 'Function':
                bp = pykd.setBp(breakpoint['Address'], self.handle_breakpoint)
                self.logger.debug('Seting breakpoint on %.8x - %d %s' % (breakpoint['Address'], bp.getId(), breakpoint['Name']))

    def on_breakpoint_hit(self, bp_id):
        self.logger.debug('on_breakpoint_hit: %d' % bp_id)
        return eventResult.Break

    def on_exception(self, exceptInfo):
        return eventResult.Break

    def handle_breakpoint(self, id):
        self.logger.debug('* handle_breakpoint: %d' % id)

    def go(self):
        pykd.go()

if __name__ == '__main__':
    pykd_debugger = PyKdDebugger(executable_path = 'notepad.exe')
    pykd_debugger.go()

