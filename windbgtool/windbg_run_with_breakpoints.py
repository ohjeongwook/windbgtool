import sys
import os
import logging
import windbgtool

from optparse import OptionParser, Option

parser = OptionParser(usage="usage: %prog [options] args")
parser.add_option("-b", "--breakpoint_db", dest="breakpoint_db", type="string", default="", metavar="BREAKPOINT_DB",
                  help="Breakpoint DB filename")
parser.add_option("-l", "--log", dest="log", type="string", default="", metavar="LOG", help="Log filename")

(options, args) = parser.parse_args(sys.argv)

root_dir = os.path.dirname(sys.argv[-3])

if options.breakpoint_db == '':
    options.breakpoint_db = os.path.join(root_dir, 'bp.db')

if options.log == '':
    options.log = os.path.join(root_dir, time.strftime("Record-%Y%m%d-%H%M%S.db"))

logging.basicConfig(level=logging.DEBUG)
root = logging.getLogger()

windbgtoolRun = windbgtool.Run()
# windbgtoolRun.SetSymbolPath()

if options.breakpoint_db:
    windbgtoolRun.LoadBreakPoints(options.breakpoint_db, options.log)
    windbgtoolRun.Continue()
