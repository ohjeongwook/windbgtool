import sys
import os
import string

try:
    import ctypes
except:
    pass
import re

def hex_string_to_bytes(hex_str):
    hex_str = re.sub('[ \t\r\n]+', '', hex_str)
    bytes = ''
    for i in range(0, len(hex_str), 2):
        bytes += chr(int(hex_str[i:i+2], 16))
    return bytes

def bytes_to_hex_string(bytes):
    hex_str = ''
    for ch in bytes:
        hex_str += '%.2x' % ord(ch)
    return hex_str
    
def convert_to_int(addr_str, base = 0x10):
    if addr_str.find("`")>0:
        addr_str = addr_str.replace("`", "")
    return int(addr_str, base)

OSMap = {
    6:
        {
            1: 
            {
                7600: ('Windows 7', 'SP0'), 
                7601: ('Windows 7', 'SP1')
            }, 		
            2: 
            {
                9200: ('Windows 8', '8.0')
            }, 
            3:
            {
                9200: ('Windows 8', '8.1'), 
                9600: ('Windows 8', '8.1')
            }
        }
}

def get_os_information():
    processor_architecture = os.environ['PROCESSOR_ARCHITECTURE']

    if processor_architecture == 'AMD64':
        arch = 'x64'
    else:
        if 'ctypes' not in sys.modules:
            return None

        i = ctypes.c_int() 
        kernel32 = ctypes.windll.kernel32 
        process = kernel32.GetCurrentProcess() 
        if kernel32.IsWow64Process(process, ctypes.byref(i)):
            arch = 'x64'
        else:
            arch = 'x86'

    wv = sys.getwindowsversion()

    build_number_str = "%d.%d.%d" % (wv.major, wv.minor, wv.build)
    os_str = ''
    sp_str = ''
    if wv.major in OSMap and wv.minor in OSMap[wv.major] and wv.build in OSMap[wv.major][wv.minor]:
        (os_str, sp_str) = OSMap[wv.major][wv.minor][wv.build]
    return {'Arch': arch, 'OS': os_str, 'SP': sp_str, 'Build': build_number_str}

def get_offset_string(i, show_offset):
    if show_offset:
        return '%.4x  ' % i
    return ''

def dump_hex(data, style = None, prefix = '', 
            show_offset = False, put_space = True, upper_case = False, show_ascii = True):
    if not data:
        return ''

    dump_str = ''

    if show_offset:
        dump_str += prefix + ' ' * 5
        for i in range(0, 0x10, 1):
            dump_str += ' %.2x' % i
        dump_str += '\n'

    if upper_case:
        format_str = 'X'
    else:
        format_str = 'x'

    i = 0
    if style == 'string':
        dump_str += prefix + get_offset_string(i, show_offset) + "'"
    else:
        dump_str += prefix + get_offset_string(i, show_offset) + ''

    ascii_string = ''
    for ch in data:
        if style == 'string':
            dump_str += ( '\\' + format_str + '%.2x' ) % ord(ch)
        else:
            dump_str += ( '%.2' + format_str ) % ( ord(ch) )
            if put_space:
                dump_str += ' '

        if show_ascii:
            if ord(ch) < 127 and ch in string.printable and ch != '\r' and ch != '\n' and ch != '\t':
                ascii_string += ch
            else:
                ascii_string += '.'

        if i%16 == 15:
            dump_str += '\t' + ascii_string
            ascii_string = ''

            if style == 'string':
                dump_str += "' + \\\n" + prefix  + get_offset_string(i + 1, show_offset) + "'"
            else:
                dump_str += '\n' + prefix + get_offset_string(i + 1, show_offset)
        i += 1

    if ascii_string:
        dump_str += '   ' * (16-i%16) + '\t' + ascii_string
    
    if style == 'string':
        dump_str += "'"

    return dump_str
