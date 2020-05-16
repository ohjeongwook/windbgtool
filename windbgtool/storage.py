import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import sqlite3
import pprint
import json
import base64

import windbgtool.util

class Storage:
    def __init__(self,filename,module_name = '',prototype_filename = ''):
        self.module_name = module_name
        
        if prototype_filename:
            self.load_prototype(prototype_filename)

        if filename.lower().endswith('.db'):
            try:
                self.Conn = sqlite3.connect(filename)
            except:
                pass
            self.Cursor = self.Conn.cursor()
            self.create_tables()
            
            self.JSONData = ''
        else:
            self.Cursor = None
            fd = open(filename,'r')
            self.JSONData = fd.read()
            fd.close()

    def create_tables(self):
        create_table_sql = """CREATE TABLE
                            IF NOT EXISTS Breakpoints (
                                id integer PRIMARY KEY,
                                Address integer,
                                ModuleName text,
                                RVA integer,
                                Symbol text,
                                DumpTargets text,
                                Type text,
                                unique (Address, ModuleName, RVA, Symbol, DumpTargets, Type)
                            );"""
        self.Cursor.execute(create_table_sql)

    def save(self,breakpoints):
        for entry in breakpoints:
            if entry['Type'] == 'Instruction':
                try:
                    operands = self.get_dump_targets(entry['Operands'])
                    self.Cursor.execute('INSERT INTO Breakpoints (ModuleName, Address, RVA, DumpTargets, Type) VALUES (?,?,?,?,?)',
                        (self.module_name, entry['Address'], entry['RVA'], json.dumps(operands), entry['Type']))
                except:
                    pass
            elif entry['Type'] == 'Function':
                try:
                    self.Cursor.execute('INSERT INTO Breakpoints (ModuleName, Address, RVA,  DumpTargets, Type) VALUES (?,?,?,?,?)',
                        (self.module_name, entry['Address'], entry['RVA'], json.dumps([entry]), entry['Type']))
                except:
                    pass

        self.Conn.commit()

    def load_prototype(self,filename):
        print('Loading prototype file:', filename)
        if os.path.isfile(filename):
            fd = open(filename,'r')
            self.PrototypeMap = json.load(fd)
            fd.close()
        else:
            self.PrototypeMap = {}

    def find_api_parameters(self,function_name):
        if function_name in self.PrototypeMap and 'Parameters' in self.PrototypeMap[function_name]:
            return self.PrototypeMap[function_name]['Parameters']
        return []

    def find_api_return_parameters(self,function_name):
        if function_name in self.PrototypeMap and 'ReturnParameters' in self.PrototypeMap[function_name]:
            return self.PrototypeMap[function_name]['ReturnParameters']
        return {}

    def add_api(self,module_name,function_name):
        parameters = self.find_api_parameters(function_name)
        return_parameters = self.find_api_return_parameters(function_name)
        pp = pprint.PrettyPrinter(indent = 4)
        try:
            if len(parameters)>0:
                dump_targets = [{
                                'Type': 'Parameters',
                                'Value': parameters
                              },
                              {
                                'Type': 'ReturnParameters',
                                'Value': return_parameters
                              }
                             ]
            else:   
                dump_targets = []
            print('Adding API: %s!%s' % (module_name, function_name))
            self.Cursor.execute('INSERT INTO Breakpoints (ModuleName, Symbol, DumpTargets, Type) VALUES (?,?,?,?)',
                (module_name, function_name, json.dumps(dump_targets), 'Function'))
        except:
            pass

        self.Conn.commit()

    def get_dump_targets(self,operands):
        dump_targets = []
        for operand in operands:
            if 'Use' in operand and 'Use' in operand:
                dump_targets.append({'Type': 'Operand', 'DataType':'DWORD', 'Value': operand})
        return dump_targets

    def load(self):
        self.AddressBreakpoints = {}
        self.ModuleBreakpoints = {}
        self.SymbolBreakpoints = {}
        if self.Cursor!=None:
            for (module, address, rva, symbol, dump_targets_json, type) in \
                    self.Cursor.execute('SELECT ModuleName, Address, RVA, Symbol, DumpTargets, Type FROM Breakpoints'):
                    
                dump_targets = []
                if dump_targets_json!=None:
                    dump_targets = json.loads(dump_targets_json)

                if address == None:
                    if symbol:
                        if not module in self.SymbolBreakpoints:
                            self.SymbolBreakpoints[module] = {}
                        self.SymbolBreakpoints[module][symbol] = dump_targets

                    else:
                        if not module in self.ModuleBreakpoints:
                            self.ModuleBreakpoints[module] = {}
                        self.ModuleBreakpoints[module][rva] = dump_targets
                else:
                    if not module in self.AddressBreakpoints:
                        self.AddressBreakpoints[module] = {}
                    self.AddressBreakpoints[module][address] = dump_targets

        elif self.JSONData:
            for item in json.loads(self.JSONData):
                if not 'RVA' in item:
                    continue

                address = item['RVA']
                type = item['Type']
                module = 'image'

                if "Module" in item:
                    module = item["Module"]
                    if module.find('.')>0:
                        module = module.split('.')[0]

                if type == 'Instruction':
                    name = item['Disasm']
                    dump_targets = self.get_dump_targets(item['Operands'])

                else:
                    name = item['Name']
                    dump_targets = item['DumpTargets']

                if not module in self.ModuleBreakpoints:
                    self.ModuleBreakpoints[module] = {}
                self.ModuleBreakpoints[module][address] = dump_targets

    def load_dump_targets(self):
        breakpoints_map = {}
        for (address, dump_targets, type) in self.Cursor.execute('SELECT Address, DumpTargets, Type FROM Breakpoints'):
            if dump_targets!=None:
                breakpoints_map[address] = json.loads(dump_targets)
        return breakpoints_map

class Record:
    def __init__(self,filename):
        self.Filename = filename
        
        print('Opening',self.Filename)
        if self.Filename.lower().endswith('.db'):
            try:
                self.Conn = sqlite3.connect(self.Filename)
            except:
                pass
            self.Cursor = self.Conn.cursor()           
            self.create_tables()
            self.JSONData = ''
        else:
            self.Cursor = None
            fd = open(self.Filename,'r')
            self.JSONData = fd.read()
            fd.close()

    def create_tables(self):
        create_table_sql = """CREATE TABLE
                            IF NOT EXISTS Records (
                                id integer PRIMARY KEY,
                                Type text,
                                Address integer,
                                Module text,
                                RVA integer,
                                Symbol text,
                                ThreadContext integer,
                                StackPointer integer,
                                DumpTargets text
                            );"""

        self.Cursor.execute(create_table_sql)

    def write_record(self,record):
        if 'DumpTargets' in record:
            dump_targets_text = json.dumps(record['DumpTargets'])
        else:
            dump_targets_text = ''

        self.Cursor.execute('INSERT INTO Records (Type, Address, Module, RVA, Symbol, ThreadContext, StackPointer, DumpTargets) VALUES (?,?,?,?,?,?,?,?)',
                (
                    record['Type'],
                    record['Address'],
                    record['Module'],
                    record['RVA'],
                    record['Symbol'],
                    record['ThreadContext'],
                    record['StackPointer'],
                    dump_targets_text
                )
            )
        self.Conn.commit()

    def load_records(self,dump_targets_map = {}):
        threads = {}
        for (record_type, address, module, symbol, thread_context, stack_pointer, dump_targets_text) in self.Cursor.execute('SELECT Type, Address, Module, Symbol, ThreadContext, StackPointer, DumpTargets FROM Records'):
            if not thread_context in threads:
                threads[thread_context] = []
                
            if dump_targets_text:
                dump_targets = json.loads(dump_targets_text)
            else:
                dump_targets = []

            threads[thread_context].append((record_type, address, module, symbol, stack_pointer, dump_targets))
            
        for (thread_context,records) in threads.items():
            stack_pointers = {}
            for (record_type, address, module, symbol, stack_pointer, dump_targets) in records:
                stack_pointers[stack_pointer] = 1

            stack_pointers_list = stack_pointers.keys()
            stack_pointers_list.sort(reverse = True)
            stack_pointer_offsets = {}
            offset = 0
            for stack_pointer in stack_pointers_list:
                stack_pointer_offsets[stack_pointer] = offset
                offset+=1

            offsets = []
            for (record_type, address, module, symbol, stack_pointer, dump_targets) in records:
                offsets.append(stack_pointer_offsets[stack_pointer])
            
            def find_min_offset(offsets):
                min_offset = 0xffffffff
                for offset in offsets:
                    if offset<min_offset:
                        min_offset = offset                     
                return min_offset

            def find_le_offset_index_forward(offsets,start,offset):
                for index in range(start,len(offsets),1):
                    if offsets[index]<=offset:
                        return index
                return len(offsets)

            def find_le_offset_index_backward(offsets,end,offset):
                for index in range(end,-1,-1):
                    if offsets[index]<=offset:
                        return index
                return -1

            def find_ge_offset_index(offsets,start,offset):
                for index in range(start,len(offsets),1):
                    if offsets[index]>=offset:
                        return index
                return -1

            def optimize_tree(offsets = [],start_index = 0,end_index = 0):
                min_offset = find_min_offset(offsets[start_index+1:end_index])              
                
                if min_offset!=0xffffffff:
                    offset_decrease = min_offset-offset-1                        
                    if offset_decrease>0:
                        for index3 in range(start_index+1, end_index, 1):
                            offsets[index3] -= offset_decrease
            
            start_index = 0
            for offset in offsets:
                end_index = find_le_offset_index_forward(offsets,start_index+1,offset)
                if end_index>=0:
                    optimize_tree(offsets, start_index, end_index)
                start_index+=1
                
            end_index = 1
            for offset in offsets[1:]:
                start_index = find_le_offset_index_backward(offsets,end_index-1,offset)
                if start_index>=0:
                    optimize_tree(offsets, start_index, end_index)
                end_index+=1
            
            index = 0
            for (record_type, address, module, symbol, stack_pointer, dump_targets) in records:
                offset = offsets[index]     
                index+=1
                
            seq = 0
            filename_base = os.path.basename(self.Filename).split('.')[0]
            filename = '%s-%.8x-%.3d.log' % (filename_base,thread_context, seq)

            fd = open(filename,'w')
            index = 0
            for (record_type, address, module, symbol, stack_pointer, dump_targets) in records:
                offset = offsets[index]
                prefix = ' ' * offset
                name = ''
                target_str = ''

                if address in dump_targets_map:
                    for dump_target in dump_targets_map[address]:                    
                        if 'Name' in dump_target:
                            name = dump_target['Name']
                            break

                target_str = ''
                parameter_lines = []
                for dump_target in dump_targets:
                    if 'Type' in dump_target['Target']:
                        type = dump_target['Target']['Type']
                    elif 'DumpInstruction' in dump_target['Target']:
                        for line in windbgtool.util.dump_hex(base64.b64decode(dump_target['Value']),prefix = '\t\t').splitlines():
                            parameter_lines.append(line)
                        continue

                    if 'Name' in dump_target['Target']:
                        name = dump_target['Target']['Name']

                    value = dump_target['Value']

                    if type == 'Operand':
                        if isinstance(value['Operand'],(int,long)):
                            target_str = ' (%.8x)' % value['Operand']
                    elif type == 'Parameters':
                        for parameter in value:
                            parametr_name = parameter['Parameter']['Name']
                            parametr_value = parameter['Value']
                            parameter_lines.append('%s: %.8x' % (parametr_name, parametr_value))
                            if 'WString' in parameter:
                                parameter_lines.append('\t'+parameter['WString'].decode('utf-16'))
                            elif 'String' in parameter:
                                parameter_lines.append('\t'+parameter['String'])
                            elif 'Bytes' in parameter:
                                for line in windbgtool.util.dump_hex(base64.b64decode(parameter['Bytes']),prefix = '\t\t').splitlines():
                                    parameter_lines.append(line)

                    elif type == 'Function':
                        for arg in value:
                            parameter_lines.append('\t%s: %.8x' % (arg['Name'], arg['Value']))
                            if arg['Bytes']:
                                for line in windbgtool.util.dump_hex(base64.b64decode(arg['Bytes']),prefix = '\t\t').splitlines():
                                    parameter_lines.append(line)
                    
                if symbol:
                    name = symbol

                if module:
                    name = module+'!'+name

                fd.write('%s%s %.8x %.8x %s %s\n' % (prefix, record_type, address, stack_pointer, name, target_str))
                for parameter_line in parameter_lines:
                    fd.write('%s\t%s\n' % (prefix, parameter_line))

                index+=1
            fd.close()

    def get_log_entries(self):
        return self.LogEntries

    def build_hit_map(self):
        self.HitMap = {}
        for entry in self.LogEntries:
            if not 'Module' in entry:
                continue

            #key = '%s!%x' % (entry['Module'],entry['RVA'])
            key = entry['RVA']
            
            if not key in self.HitMap:
                self.HitMap[key] = 0
            self.HitMap[key]+=1
        
    def print_hit_map(self):
        for (rva,count) in sorted(self.HitMap.items(),key = operator.itemgetter(1)):
            print("%x %d" % (rva,count))
        
    def remove_hits(self,breakpoint_filename,output_breakpoint_filename,threshold):
        fd = open(breakpoint_filename,'r')
        data = fd.read()
        fd.close()
        
        new_breakpoints = []
        breakpoints = json.loads(data)
        for breakpoint in breakpoints:
            rva = breakpoint['RVA']
            if rva in self.HitMap and self.HitMap[rva]>threshold:
                print('Removing %x (%d hits)' % (rva,self.HitMap[rva]))
            else:
                new_breakpoints.append(breakpoint)
        
        fd = open(output_breakpoint_filename,'w')
        fd.write(json.dumps(new_breakpoints))
        fd.close()


if __name__ == '__main__':
    import sys
    import os
    import logging

    root_dir = os.path.dirname(sys.argv[0])

    from optparse import OptionParser, Option

    parser = OptionParser(usage = "usage: %prog [options] args")
    parser.add_option("-b", "--breakpoint_db", dest = "breakpoint_db", type = "string", default = "", metavar = "BREAKPOINT_DB", help = "Breakpoint DB filename")
    parser.add_option("-r", "--record_db", dest = "record_db", type = "string", default = "", metavar = "RECORD", help = "Record db filename")
    parser.add_option("-a", "--api_filename", dest = "api_filename", type = "string", default = "", metavar = "API_FILENAME", help = "API filename")
    parser.add_option("-p", "--prototype_filename", dest = "prototype_filename", type = "string", default = os.path.join(root_dir, 'Prototype.json'), metavar = "LOG", help = "Log filename")

    (options, args) = parser.parse_args(sys.argv)

    logging.basicConfig(level = logging.DEBUG)
    root = logging.getLogger()
    
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(message)s')
    ch.setFormatter(formatter)
    root.addHandler(ch)

    
    if options.breakpoint_db:
        db = Storage(options.breakpoint_db,
              prototype_filename = options.prototype_filename
            )
        #db.load()

    else:
        db = None
        
    if options.api_filename:
        fd = open(options.api_filename)
        for line in fd.read().splitlines():
            (module_name, function_name) = line.split('!')
            db.add_api(module_name, function_name)
        fd.close()
    
    if options.record_db:
        if db!=None:
            dump_targets_map = db.load_dump_targets()
        else:
            dump_targets_map = {}
        record = Record(options.record_db)
        record.load_records(dump_targets_map)
