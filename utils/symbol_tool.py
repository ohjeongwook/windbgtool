import os
import ctypes
from ctypes.wintypes import *
from dbghelp import *

GetCurrentProcess = ctypes.windll.kernel32.GetCurrentProcess
GetCurrentProcess.restype = HANDLE
ctypes.windll.kernel32.LoadLibraryA('symsrv')

class Symbol:
    def __init__(self, debug_level = 0):
        self.process = GetCurrentProcess()
        SymInitialize(self.process, None, False)
        options = SymGetOptions()

        if debug_level > 0:
            options |= SymOpts.SYMOPT_DEBUG
        
        options |= SymOpts.SYMOPT_UNDNAME
        SymSetOptions(options)

    def set_symbol_path(self, sym_path = 'srv*https://msdl.microsoft.com/download/symbols'):
        SymSetSearchPath(self.process, sym_path)

    def __del__(self):
        SymCleanup(self.process)

    def load_image(self, image_name):        
        module_base = SymLoadModuleEx(self.process, 0, ctypes.c_char_p(image_name.encode('utf-8')), None, 0, 0, None, 0)
        if not module_base:
            raise Exception('Failed SymLoadModuleEx last error:  %d' % ctypes.GetLastError())
        return module_base

    def load_pdb(self, pdb_filename):
        size = os.path.getsize(pdb_filename)
        module_base = 0x10000000
        module_base = SymLoadModuleEx(
                        self.process,
                        0,
                        ctypes.c_char_p(pdb_filename.encode('utf-8')),
                        None,
                        module_base,
                        size,
                        None,
                        0
                    )
        if not module_base:
            raise Exception('Failed SymLoadModuleEx last error:  %d' % ctypes.GetLastError())

        print('module_base: %x' % module_base)
        return module_base

    def load(self, filename):
        if filename.lower().endswith('.pdb'):
            return self.load_pdb(filename)
        else:
            return self.load_image(filename)

    def print_symtype(self, symtype):
        pass
        
    def print_module_info(self, module_base):
        imagehlp_module = IMAGEHLP_MODULE()
        imagehlp_module.SizeOfStruct  = ctypes.sizeof(IMAGEHLP_MODULE)
        ret = SymGetModuleInfo(self.process, module_base, byref(imagehlp_module));

        if ret:
            print('imagehlp_module.ModuleName: %s' % imagehlp_module.ModuleName)
            for field_name, field_type in imagehlp_module._fields_:
                print(field_name + ': ' + str(eval('imagehlp_module.' + field_name)))
                self.print_symtype(imagehlp_module.SymType)

        imagehlp_module64 = IMAGEHLP_MODULE64()
        imagehlp_module64.SizeOfStruct  = ctypes.sizeof(IMAGEHLP_MODULE64)
        ret = SymGetModuleInfo64(self.process, module_base, byref(imagehlp_module64)); 
        if ret:
            print('imagehlp_module64.ModuleName: %s' % imagehlp_module64.ModuleName)
            for field_name, field_type in imagehlp_module64._fields_:
                print(field_name + ': ' + str(eval('imagehlp_module64.' + field_name)))
                self.print_symtype(imagehlp_module64.SymType)

    def print_syminfo(self, syminfo):
        name = ctypes.string_at(ctypes.addressof(syminfo)+SYMBOL_INFO.Name.offset)
        print('syminfo.Name: %s' % name)
        print('syminfo.SizeOfStruct: %x' % syminfo.SizeOfStruct)
        print('syminfo.TypeIndex: %x' % syminfo.TypeIndex)
        print('syminfo.Index: %x' % syminfo.Index)
        print('syminfo.Size: %x' % syminfo.Size)
        print('syminfo.ModBase: %x' % syminfo.ModBase)
        print('syminfo.Flags: %x' % syminfo.Flags)
        print('syminfo.Value: %x' % syminfo.Value)
        print('syminfo.Address: %x' % syminfo.Address)
        print('syminfo.Register: %x' % syminfo.Register)
        print('syminfo.Scope: %x' % syminfo.Scope)
        print('syminfo.Tag: %x' % syminfo.Tag)
        print('syminfo.NameLen: %x' % syminfo.NameLen)
        print('syminfo.MaxNameLen: %x' % syminfo.MaxNameLen)
        
    def _enum_symbol_callback(self, syminfo, symsize, module_base):
        print('_enum_symbol_callback')
        self.print_syminfo(syminfo)

    def _get_callback(self, module_base = 0):
        def callbackwrapper(syminfo, symbol_size, context):
            print('callbackwrapper')
            self._enum_symbol_callback(syminfo.contents, symbol_size, module_base)

        return ctypes.WINFUNCTYPE(None, PSYMBOL_INFO, ULONG, PVOID)(callbackwrapper)

    def enumerate(self, module_base):
        mask = ctypes.c_char_p(r"*".encode('utf-8'))
        SymEnumSymbols(self.process, module_base, None, self._get_callback(module_base), None)

    def get_sym_from_address(self, address):
        displacement = DWORD64()

        # struct_size = ctypes.sizeof(SYMBOL_INFO) + 512
        # byte_array = (ctypes.c_byte * struct_size)()
        # symbol_info = ctypes.cast(byte_array, PSYMBOL_INFO)
        # symbol_info.SizeOfStruct = struct_size
        symbol_info = SYMBOL_INFO()
        SymFromAddr(self.process, address, byref(displacement), byref(symbol_info))
        print('* get_function_symbol:')
        self.print_syminfo(symbol_info)
        print('* displacement:')
        print(displacement)

    def get_function_symbol(self, module_base, address):
        imagehlp_stack_frame = IMAGEHLP_STACK_FRAME()
        imagehlp_stack_frame.InstructionOffset = address
        ret = SymSetContext(self.process, byref(imagehlp_stack_frame), 0)
        print('SymSetContext: %d' % ret)

        if ret:
            locals_number = DWORD()
            SymEnumSymbols(self.process, 0, None, self._get_callback(module_base), byref(locals_number))
            print(locals_number)

if __name__ == '__main__':
    import os
    import sys    
    import argparse

    def auto_int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser(description='symbol_tool.py')
    parser.add_argument("-c", "--command", dest = "command", default = "enumerate", metavar = "COMMAND", help = "Set command to run")
    parser.add_argument('filename', metavar='FILENAME', help = "filename")
    args = parser.parse_args()
    
    symbol = Symbol(debug_level = 1)
    symbol.set_symbol_path()

    module_base = symbol.load(args.filename)    

    if args.command == 'enumerate':
        symbol.enumerate(module_base)
    elif args.command == 'info':
        symbol.print_module_info(module_base)
