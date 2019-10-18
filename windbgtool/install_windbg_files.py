import os
import platform
import pprint
import shutil

if 'PROGRAMFILES(X86)' in os.environ:
    bits = '64bit'
else:
    bits = '32bit'

windbg_folders64 = []
windbg_folders32 = []

python_folders64 = []
python_folders32 = []

pykd_folder = r'\Lib\site-packages\pykd'
if bits == '64bit':
    windbg_folders64.append(os.environ["ProgramW6432"] + r'\Windows Kits\10\Debuggers\x64')
    windbg_folders64.append(os.environ["ProgramW6432"] + r'\Debugging Tools for Windows (x64)')

    windbg_folders32.append(os.environ["ProgramFiles(x86)"] + r'\Windows Kits\10\Debuggers\x86')
    windbg_folders32.append(os.environ["ProgramW6432"] + r'\Debugging Tools for Windows (x64)\Wow64')

    python_folders64.append(r'C:\python27-x64' + pykd_folder)
    python_folders64.append(os.environ['LOCALAPPDATA'] + r'\Programs\Python\Python37' + pykd_folder)

    python_folders32.append(r'C:\Python27' + pykd_folder)
    python_folders32.append(os.environ['LOCALAPPDATA'] + r'\Programs\Python\Python37-32' + pykd_folder)

elif bits == '32bit':
    windbg_folders32.append(os.environ["ProgramFiles"])
    python_folders32.append(r'C:\Python27' + pykd_folder)

def CopyFiles(src_folder, dst_folders):
    for windbg_folder in src_folder:
        if not os.path.isdir(windbg_folder):
            continue

        for python_folder in dst_folders:
            if not os.path.isdir(python_folder):
                continue        
            print('\t'+windbg_folder + ' -> ' + python_folder)

            for filename in ('dbgeng.dll', 'dbghelp.dll', 'DbgModel.dll', 'msdia140.dll', 'srcsrv.dll', 'symsrv.dll'):
                try:
                    src_filename = os.path.join(windbg_folder, filename)
                    print('Copying ' + src_filename)
                    shutil.copy(src_filename, os.path.join(python_folder, filename))
                except:
                    pass

            for filename in os.listdir(os.path.join(windbg_folder, 'winext')):
                if not filename.endswith('.dll'):
                    continue

                try:
                    src_filename = os.path.join(windbg_folder + '\winext', filename)
                    print('Copying ' + src_filename)
                    shutil.copy(src_filename, os.path.join(python_folder, filename))
                except:
                    pass

print('* Copying 64bit files:')
CopyFiles(windbg_folders64, python_folders64)

print('* Copying 32bit files:')
CopyFiles(windbg_folders32, python_folders32)
