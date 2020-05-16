import ctypes
from ctypes import *
from ctypes.wintypes import *
from win32defs import *

class SymOpts(object):
    SYMOPT_EXACT_SYMBOLS = 0x00000400
    SYMOPT_DEBUG = 0x80000000
    SYMOPT_UNDNAME = 0x00000002

windll.kernel32.LoadLibraryA('dbghelp.dll')
dbghelp = windll.dbghelp

class GUID(Structure):
    _fields_ = [("Data1", DWORD),
                ("Data2", WORD),
                ("Data3", WORD),
                ("Data4", BYTE * 8)]

class SYMBOL_INFO(Structure):
    _fields_ = [
        ('SizeOfStruct', DWORD),
        ('TypeIndex', DWORD),
        ('Reserved', ULONGLONG*2),
        ('Index', DWORD),
        ('Size', DWORD),
        ('ModBase', ULONGLONG),
        ('Flags', DWORD),
        ('Value', ULONGLONG),
        ('Address', ULONGLONG),
        ('Register', DWORD),
        ('Scope', DWORD),
        ('Tag', DWORD),
        ('NameLen', DWORD),
        ('MaxNameLen', DWORD),
        ('Name', c_char*1)
    ]

class IMAGEHLP_MODULE (Structure):
    _fields_ = [
        ("SizeOfStruct",    DWORD),
        ("BaseOfImage",     DWORD),
        ("ImageSize",       DWORD),
        ("TimeDateStamp",   DWORD),
        ("CheckSum",        DWORD),
        ("NumSyms",         DWORD),
        ("SymType",         DWORD),         # SYM_TYPE
        ("ModuleName",      CHAR * 32),
        ("ImageName",       CHAR * 256),
        ("LoadedImageName", CHAR * 256),
    ]
PIMAGEHLP_MODULE = POINTER(IMAGEHLP_MODULE)

class IMAGEHLP_MODULE64 (Structure):
    _fields_ = [
        ("SizeOfStruct",    DWORD),
        ("BaseOfImage",     DWORD64),
        ("ImageSize",       DWORD),
        ("TimeDateStamp",   DWORD),
        ("CheckSum",        DWORD),
        ("NumSyms",         DWORD),
        ("SymType",         DWORD),         # SYM_TYPE
        ("ModuleName",      CHAR * 32),
        ("ImageName",       CHAR * 256),
        ("LoadedImageName", CHAR * 256),
        ("LoadedPdbName",   CHAR * 256),
        ("CVSig",           DWORD),
        ("CVData",          CHAR * (MAX_PATH * 3)),
        ("PdbSig",          DWORD),
        ("PdbSig70",        GUID),
        ("PdbAge",          DWORD),
        ("PdbUnmatched",    BOOL),
        ("DbgUnmatched",    BOOL),
        ("LineNumbers",     BOOL),
        ("GlobalSymbols",   BOOL),
        ("TypeInfo",        BOOL),
        ("SourceIndexed",   BOOL),
        ("Publics",         BOOL),
    ]
PIMAGEHLP_MODULE64 = POINTER(IMAGEHLP_MODULE64)


SymInitialize = dbghelp.SymInitialize
SymInitialize.argtypes = [
            HANDLE,
            PVOID,
            c_bool
        ]


SymCleanup = dbghelp.SymCleanup
SymCleanup.argtypes = [
            HANDLE
        ]

SymGetOptions = dbghelp.SymGetOptions
SymGetOptions.restype = c_ulong

SymSetOptions = dbghelp.SymSetOptions

# BOOL IMAGEAPI SymGetModuleInfo(
#   HANDLE           hProcess,
#   DWORD            dwAddr,
#   PIMAGEHLP_MODULE ModuleInfo
# );

SymGetModuleInfo = dbghelp.SymGetModuleInfo
SymGetModuleInfo.restype = bool
SymGetModuleInfo.argtypes = [
            HANDLE,
            DWORD,
            PIMAGEHLP_MODULE
        ]

# BOOL IMAGEAPI SymGetModuleInfo64(
#   HANDLE             hProcess,
#   DWORD64            qwAddr,
#   PIMAGEHLP_MODULE64 ModuleInfo
# );

SymGetModuleInfo64 = dbghelp.SymGetModuleInfo64
SymGetModuleInfo64.restype = bool
SymGetModuleInfo64.argtypes = [
            HANDLE,
            ULONGLONG,
            PIMAGEHLP_MODULE64
        ]

SymSetSearchPath = dbghelp.SymSetSearchPath
SymSetSearchPath.argtypes = [
            HANDLE,
            c_wchar_p
        ]
SymEnumSymbols = dbghelp.SymEnumSymbols
SymEnumSymbols.restype = DWORD
SymEnumSymbols.argtypes = [
            DWORD,
            ULONGLONG,
            c_char_p,
            PVOID,
            PVOID,
        ]

# DWORD64 IMAGEAPI SymLoadModuleEx(
#   HANDLE        hProcess,
#   HANDLE        hFile,
#   PCSTR         ImageName,
#   PCSTR         ModuleName,
#   DWORD64       BaseOfDll,
#   DWORD         DllSize,
#   PMODLOAD_DATA Data,
#   DWORD         Flags
# );

SymLoadModuleEx = dbghelp.SymLoadModuleEx
SymLoadModuleEx.restype = PVOID
SymLoadModuleEx.argtypes = [
            HANDLE,
            HANDLE,
            c_char_p,
            c_char_p,
            PVOID,
            c_ulong,
            PVOID,
            c_ulong
        ]

# BOOL IMAGEAPI SymEnumSymbols(
#   HANDLE                         hProcess,
#   ULONG64                        BaseOfDll,
#   PCSTR                          Mask,
#   PSYM_ENUMERATESYMBOLS_CALLBACK EnumSymbolsCallback,
#   PVOID                          UserContext
# );

SymEnumSymbols = dbghelp.SymEnumSymbols
SymEnumSymbols.restype = bool
SymEnumSymbols.argtypes = [
            HANDLE,
            ULONGLONG,
            c_char_p,
            PVOID,
            PVOID
        ]
