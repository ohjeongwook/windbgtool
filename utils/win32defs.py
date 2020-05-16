from ctypes import *
from ctypes.wintypes import *

# Map of basic C types to Win32 types
LPVOID      = c_void_p
CHAR        = c_char
WCHAR       = c_wchar
BYTE        = c_ubyte
SBYTE       = c_byte
WORD        = c_uint16
SWORD       = c_int16
DWORD       = c_uint32
SDWORD      = c_int32
QWORD       = c_uint64
SQWORD      = c_int64
SHORT       = c_int16
USHORT      = c_uint16
INT         = c_int32
UINT        = c_uint32
LONG        = c_int32
ULONG       = c_uint32
LONGLONG    = c_int64        # c_longlong
ULONGLONG   = c_uint64       # c_ulonglong
LPSTR       = c_char_p
LPWSTR      = c_wchar_p
INT8        = c_int8
INT16       = c_int16
INT32       = c_int32
INT64       = c_int64
UINT8       = c_uint8
UINT16      = c_uint16
UINT32      = c_uint32
UINT64      = c_uint64
LONG32      = c_int32
LONG64      = c_int64
ULONG32     = c_uint32
ULONG64     = c_uint64
DWORD32     = c_uint32
DWORD64     = c_uint64
BOOL        = c_int32
FLOAT       = c_float        # not sure on cygwin
DOUBLE      = c_double       # not sure on cygwin

# Map size_t to SIZE_T
try:
    SIZE_T  = c_size_t
    SSIZE_T = c_ssize_t
except AttributeError:
    # Size of a pointer
    SIZE_T  = {1:BYTE, 2:WORD, 4:DWORD, 8:QWORD}[sizeof(LPVOID)]
    SSIZE_T = {1:SBYTE, 2:SWORD, 4:SDWORD, 8:SQWORD}[sizeof(LPVOID)]
PSIZE_T     = POINTER(SIZE_T)

# Not really pointers but pointer-sized integers
DWORD_PTR   = SIZE_T
ULONG_PTR   = SIZE_T
LONG_PTR    = SIZE_T

# Other Win32 types, more may be added as needed
PVOID       = LPVOID
PPVOID      = POINTER(PVOID)
PSTR        = LPSTR
PWSTR       = LPWSTR
PCHAR       = LPSTR
PWCHAR      = LPWSTR
LPBYTE      = POINTER(BYTE)
LPSBYTE     = POINTER(SBYTE)
LPWORD      = POINTER(WORD)
LPSWORD     = POINTER(SWORD)
LPDWORD     = POINTER(DWORD)
LPSDWORD    = POINTER(SDWORD)
LPULONG     = POINTER(ULONG)
LPLONG      = POINTER(LONG)
PDWORD      = LPDWORD
PDWORD_PTR  = POINTER(DWORD_PTR)
PULONG      = LPULONG
PLONG       = LPLONG
CCHAR       = CHAR
BOOLEAN     = BYTE
PBOOL       = POINTER(BOOL)
LPBOOL      = PBOOL
TCHAR       = CHAR      # XXX ANSI by default?
UCHAR       = BYTE
DWORDLONG   = ULONGLONG
LPDWORD32   = POINTER(DWORD32)
LPULONG32   = POINTER(ULONG32)
LPDWORD64   = POINTER(DWORD64)
LPULONG64   = POINTER(ULONG64)
PDWORD32    = LPDWORD32
PULONG32    = LPULONG32
PDWORD64    = LPDWORD64
PULONG64    = LPULONG64
ATOM        = WORD
HANDLE      = LPVOID
PHANDLE     = POINTER(HANDLE)
LPHANDLE    = PHANDLE
HMODULE     = HANDLE
HINSTANCE   = HANDLE
HTASK       = HANDLE
HKEY        = HANDLE
PHKEY       = POINTER(HKEY)
HDESK       = HANDLE
HRSRC       = HANDLE
HSTR        = HANDLE
HWINSTA     = HANDLE
HKL         = HANDLE
HDWP        = HANDLE
HFILE       = HANDLE
HRESULT     = LONG
HGLOBAL     = HANDLE
HLOCAL      = HANDLE
HGDIOBJ     = HANDLE
HDC         = HGDIOBJ
HRGN        = HGDIOBJ
HBITMAP     = HGDIOBJ
HPALETTE    = HGDIOBJ
HPEN        = HGDIOBJ
HBRUSH      = HGDIOBJ
HMF         = HGDIOBJ
HEMF        = HGDIOBJ
HENHMETAFILE = HGDIOBJ
HMETAFILE   = HGDIOBJ
HMETAFILEPICT = HGDIOBJ
HWND        = HANDLE
NTSTATUS    = LONG
PNTSTATUS   = POINTER(NTSTATUS)
KAFFINITY   = ULONG_PTR
RVA         = DWORD
RVA64       = QWORD
WPARAM      = DWORD
LPARAM      = LPVOID
LRESULT     = LPVOID
ACCESS_MASK = DWORD
REGSAM      = ACCESS_MASK
PACCESS_MASK = POINTER(ACCESS_MASK)
PREGSAM     = POINTER(REGSAM)
