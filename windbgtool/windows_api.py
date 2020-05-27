import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import json
import pprint

class Resolver:
    def __init__(self, windows_api_filename = 'windows_api.json'):
        self.windows_api = {}
        if not os.path.isfile(windows_api_filename):
            windows_api_filename = os.path.join(os.path.dirname(os.path.realpath(__file__)), windows_api_filename)

        print('Loading ' + windows_api_filename)
        if os.path.isfile(windows_api_filename):
            self.load_windows_api_defs(windows_api_filename)
        
    def load_windows_api_defs(self, filename):
        with open(filename, 'r') as fd:
            self.windows_api = json.load(fd)

        self.functions = {}
        for funcdef in self.windows_api['funcdefs']:
            if 'name' in funcdef['type']:
                name = funcdef['type']['name']
                self.functions[name] = funcdef

    def find_function(self, name):
        if name in self.functions:
            return self.functions[name]

if __name__ == '__main__':
    resolver = Resolver()
    create_process_a_def = resolver.find_function('CreateProcessA')
    pprint.pprint(create_process_a_def)

    create_process_a_def = resolver.find_function('CreateProcessW')
    pprint.pprint(create_process_a_def)
