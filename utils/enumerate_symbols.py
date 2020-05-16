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
        sym_path = 'srv*https://msdl.microsoft.com/download/symbols'
        SymSetSearchPath(self.process, sym_path)

    def __del__(self):
        SymCleanup(self.process)

    def load(self, image_name):
        module_base = SymLoadModuleEx(self.process, 0, ctypes.c_char_p(image_name.encode('utf-8')), None, 0, 0, None, 0)
        if not module_base:
            raise Exception('Failed SymLoadModuleEx last error:  %d' % ctypes.GetLastError())
        return module_base

    def print_symtype(self, symtype):
        pass
        
    def get_module_info(self, module_base):
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
        print('')

    def _get_callback(self, module_base):
        print('_get_callback')
        CALLBACK = ctypes.WINFUNCTYPE(None, ctypes.POINTER(SYMBOL_INFO), ctypes.c_ulong, PVOID)
        def callbackwrapper(syminfo, symsize, opq):
            print('callbackwrapper')
            self._enum_symbol_callback(syminfo.contents, symsize, module_base)

        return CALLBACK(callbackwrapper)

    def enumerate(self, module_base):
        mask = ctypes.c_char_p(r"*".encode('utf-8'))
        SymEnumSymbols(self.process, module_base, mask, self._get_callback(module_base), None)

if __name__ == '__main__':
    symbol = Symbol()
    module_base = symbol.load(r'c:\\windows\\system32\\kernel32.dll')
    symbol.get_module_info(module_base)
    symbol.enumerate(module_base)
    
