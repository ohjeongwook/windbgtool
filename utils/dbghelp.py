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

class Flag(int):
    def __new__(cls, name, value):
        return super(Flag, cls).__new__(cls, value)

    def __init__(self, name, value):
        self.name = name

    def __repr__(self):
        return "{0}({1:#x})".format(self.name, self)

    # Custom __str__ removed for multiple reason
    # Main one -> it breaks the json encoding of structure with flags :)
    # Moving to a new politic -> if people want the name in a string use {x!r}
    # The __str__ of security descriptor & guid will change soon as well :)

    # __str__ = __repr__

   # Fix pickling with protocol 2
    def __getnewargs__(self, *args):
        return self.name, int(self)

class FlagMapper(dict):
    def __init__(self, *values):
        self.update({x:x for x in values})

    def __missing__(self, key):
        return key

class EnumValue(Flag):
    def __new__(cls, enum_name, name, value):
        return super(EnumValue, cls).__new__(cls, name, value)

    def __init__(self, enum_name, name, value):
        self.enum_name = enum_name
        self.name = name

    def __repr__(self):
        return "{0}.{1}({2})".format(self.enum_name, self.name, hex(self))

    # Fix pickling with protocol 2
    def __getnewargs__(self, *args):
        return self.enum_name, self.name, int(self)

class EnumType(DWORD):
    values = ()
    mapper = {}

    @property
    def value(self):
        raw_value = super_noissue(EnumType, self).value
        return self.mapper.get(raw_value, raw_value)

    def __repr__(self):
        raw_value = super_noissue(EnumType, self).value
        if raw_value in self.values:
            value = self.value
            return "<{0} {1}({2})>".format(type(self).__name__, value.name, hex(raw_value))
        return "<{0}({1})>".format(type(self).__name__, hex(self.value))

SymTagNull = EnumValue("_SymTagEnum", "SymTagNull", 0x0)
SymTagExe = EnumValue("_SymTagEnum", "SymTagExe", 0x1)
SymTagCompiland = EnumValue("_SymTagEnum", "SymTagCompiland", 0x2)
SymTagCompilandDetails = EnumValue("_SymTagEnum", "SymTagCompilandDetails", 0x3)
SymTagCompilandEnv = EnumValue("_SymTagEnum", "SymTagCompilandEnv", 0x4)
SymTagFunction = EnumValue("_SymTagEnum", "SymTagFunction", 0x5)
SymTagBlock = EnumValue("_SymTagEnum", "SymTagBlock", 0x6)
SymTagData = EnumValue("_SymTagEnum", "SymTagData", 0x7)
SymTagAnnotation = EnumValue("_SymTagEnum", "SymTagAnnotation", 0x8)
SymTagLabel = EnumValue("_SymTagEnum", "SymTagLabel", 0x9)
SymTagPublicSymbol = EnumValue("_SymTagEnum", "SymTagPublicSymbol", 0xa)
SymTagUDT = EnumValue("_SymTagEnum", "SymTagUDT", 0xb)
SymTagEnum = EnumValue("_SymTagEnum", "SymTagEnum", 0xc)
SymTagFunctionType = EnumValue("_SymTagEnum", "SymTagFunctionType", 0xd)
SymTagPointerType = EnumValue("_SymTagEnum", "SymTagPointerType", 0xe)
SymTagArrayType = EnumValue("_SymTagEnum", "SymTagArrayType", 0xf)
SymTagBaseType = EnumValue("_SymTagEnum", "SymTagBaseType", 0x10)
SymTagTypedef = EnumValue("_SymTagEnum", "SymTagTypedef", 0x11)
SymTagBaseClass = EnumValue("_SymTagEnum", "SymTagBaseClass", 0x12)
SymTagFriend = EnumValue("_SymTagEnum", "SymTagFriend", 0x13)
SymTagFunctionArgType = EnumValue("_SymTagEnum", "SymTagFunctionArgType", 0x14)
SymTagFuncDebugStart = EnumValue("_SymTagEnum", "SymTagFuncDebugStart", 0x15)
SymTagFuncDebugEnd = EnumValue("_SymTagEnum", "SymTagFuncDebugEnd", 0x16)
SymTagUsingNamespace = EnumValue("_SymTagEnum", "SymTagUsingNamespace", 0x17)
SymTagVTableShape = EnumValue("_SymTagEnum", "SymTagVTableShape", 0x18)
SymTagVTable = EnumValue("_SymTagEnum", "SymTagVTable", 0x19)
SymTagCustom = EnumValue("_SymTagEnum", "SymTagCustom", 0x1a)
SymTagThunk = EnumValue("_SymTagEnum", "SymTagThunk", 0x1b)
SymTagCustomType = EnumValue("_SymTagEnum", "SymTagCustomType", 0x1c)
SymTagManagedType = EnumValue("_SymTagEnum", "SymTagManagedType", 0x1d)
SymTagDimension = EnumValue("_SymTagEnum", "SymTagDimension", 0x1e)

class _SymTagEnum(EnumType):
    values = [SymTagNull, SymTagExe, SymTagCompiland, SymTagCompilandDetails, SymTagCompilandEnv, SymTagFunction, SymTagBlock, SymTagData, SymTagAnnotation, SymTagLabel, SymTagPublicSymbol, SymTagUDT, SymTagEnum, SymTagFunctionType, SymTagPointerType, SymTagArrayType, SymTagBaseType, SymTagTypedef, SymTagBaseClass, SymTagFriend, SymTagFunctionArgType, SymTagFuncDebugStart, SymTagFuncDebugEnd, SymTagUsingNamespace, SymTagVTableShape, SymTagVTable, SymTagCustom, SymTagThunk, SymTagCustomType, SymTagManagedType, SymTagDimension]
    mapper = FlagMapper(*values)

SymTagEnum = _SymTagEnum

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

PSYMBOL_INFO = POINTER(SYMBOL_INFO)

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


# typedef struct _IMAGEHLP_STACK_FRAME {
#   ULONG64 InstructionOffset;
#   ULONG64 ReturnOffset;
#   ULONG64 FrameOffset;
#   ULONG64 StackOffset;
#   ULONG64 BackingStoreOffset;
#   ULONG64 FuncTableEntry;
#   ULONG64 Params[4];
#   ULONG64 Reserved[5];
#   BOOL    Virtual;
#   ULONG   Reserved2;
# } IMAGEHLP_STACK_FRAME, *PIMAGEHLP_STACK_FRAME;

class _IMAGEHLP_STACK_FRAME(Structure):
    _fields_ = [
        ("InstructionOffset", ULONG64),
        ("ReturnOffset", ULONG64),
        ("FrameOffset", ULONG64),
        ("StackOffset", ULONG64),
        ("BackingStoreOffset", ULONG64),
        ("FuncTableEntry", ULONG64),
        ("Params", ULONG64 * (4)),
        ("Reserved", ULONG64 * (5)),
        ("Virtual", BOOL),
        ("Reserved2", ULONG),
    ]
IMAGEHLP_STACK_FRAME = _IMAGEHLP_STACK_FRAME
PIMAGEHLP_STACK_FRAME = POINTER(_IMAGEHLP_STACK_FRAME)

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
SymGetOptions.restype = DWORD

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

# DWORD64 IMAGEAPI SymLoadModule64(
#   HANDLE  hProcess,
#   HANDLE  hFile,
#   PCSTR   ImageName,
#   PCSTR   ModuleName,
#   DWORD64 BaseOfDll,
#   DWORD   SizeOfDll
# );

SymLoadModule64 = dbghelp.SymLoadModule64        
SymLoadModule64.restype = DWORD64
SymLoadModule64.argtypes = [
            HANDLE,
            HANDLE,
            PCSTR,
            PCSTR,
            DWORD64,
            DWORD
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
            PCSTR,
            PCSTR,
            PVOID,
            DWORD,
            PVOID,
            DWORD
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
            ULONG64,
            PCSTR,
            PVOID,
            PVOID
        ]

# BOOL IMAGEAPI SymFromAddr(
#   HANDLE       hProcess,
#   DWORD64      Address,
#   PDWORD64     Displacement,
#   PSYMBOL_INFO Symbol
# );

SymFromAddr = dbghelp.SymFromAddr
SymFromAddr.restype = bool
SymFromAddr.argtypes = [
            HANDLE,
            DWORD64,
            PDWORD64,
            PSYMBOL_INFO
        ]

# BOOL IMAGEAPI SymSetContext(
#   HANDLE                hProcess,
#   PIMAGEHLP_STACK_FRAME StackFrame,
#   PIMAGEHLP_CONTEXT     Context
# );

SymSetContext = dbghelp.SymSetContext
SymSetContext.restype = bool
SymSetContext.argtypes = [
            HANDLE,
            PIMAGEHLP_STACK_FRAME,
            PVOID
        ]
