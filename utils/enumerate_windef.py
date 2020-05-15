import sys
import pprint
import json

import windows.generated_def.winfuncs
import windows.generated_def.winstructs
import windows.generated_def.interfaces

from ctypes import _CFuncPtr, Structure, _Pointer, Union, _SimpleCData, CDLL, c_ulong

class Dumper:
    def __init__(self, debug_level = 0):
        self.debug_level = debug_level
        self.function_prototypes = {}
        self.argtypes = {}
        self.structures = {}
        self.enums = {}
        self.pointers = {}

    def enumerate_winfuncs(self):
        for obj in vars(windows.generated_def.winfuncs):
            instance = eval("windows.generated_def.winfuncs." + obj)

            if hasattr(instance, '__bases__') and instance.__bases__[0] is _CFuncPtr:
                function_name = obj[0:-1 * len('Prototype')]
                if not function_name in self.function_prototypes:
                    self.function_prototypes[function_name] = {}

                self.function_prototypes[function_name]['restype'] = instance._restype_.__name__
                argtypes = []
                for argtype in instance._argtypes_:
                    argtypes.append(argtype.__name__)

                    if not argtype in self.argtypes:
                        self.argtypes[argtype.__name__] = 1

                self.function_prototypes[function_name]['arg_types'] = argtypes

            elif obj.endswith('Params'):
                function_name = obj[0:-1 * len('Params')]
                if not function_name in self.function_prototypes:
                    self.function_prototypes[function_name] = {}

                self.function_prototypes[function_name]['arg_names'] = instance

    def dump_pointer(self, name, instance):
        print('Pointer: ' + name)
        print('   _type_: ' + str(instance._type_))
        print('   _type_.__name__: ' + str(instance._type_.__name__))
        print('   contents: ' + str(instance.contents))
        print('   _objects: ' + str(instance._objects))

    def dump_union(self, name, instance):
        print('Union: ' + name)
        print('    dir: ' + str(dir(instance)))
        print('    _fields_: ')
        for field in instance._fields_:
            (field_name, field_type) = field[0:2]
            print('        %s: %s' % (field_name, field_type.__name__))

    def dump_object(self, name, instance):
        print('-'*80)
        print('Object: ' + name)
        print('    type: ' + str(type(instance)))

        if hasattr(instance, '__bases__'):
            print('    instance.__bases__[0]: ' + str(instance.__bases__[0]))
            print('        base name: ' + str(instance.__bases__[0].__name__))


        if hasattr(instance, 'attributes'):
            print('   attributes: ' + str(instance.attributes))

        if hasattr(instance, '_objects'):
            print('   _objects: ' + str(instance._objects))

        if hasattr(instance, '_fields_'):
            print('    _fields_: ')
            for field in instance._fields_:
                (field_name, field_type) = field[0:2]
                print('        %s: %s' % (field_name, field_type.__name__))

        print(dir(instance))
        print('')

    def get_fields(self, instance):
        fields = []
        if hasattr(instance, '_fields_'):
            for field in instance._fields_:
                (field_name, field_type) = field[0:2]
                fields.append((field_name, field_type.__name__))
        return fields

    def enumerate_winstructs(self):
        for obj in vars(windows.generated_def.winstructs):
            instance = eval("windows.generated_def.winstructs." + obj)

            if hasattr(instance, '__bases__'):
                if instance.__bases__[0] is Structure or instance.__bases__[0] is Union or hasattr(instance, '_fields_'):
                    self.structures[obj] = {}
                    self.structures[obj]['type'] = instance.__bases__[0].__name__
                    self.structures[obj]['fields'] = self.get_fields(instance)

                elif instance.__bases__[0] is windows.generated_def.winstructs.EnumType:
                    self.enums[obj] = {}
                    enum_values = []
                    for value in instance.values:
                        enum_values.append({'name': value.name, 'real': value.real})
                    self.enums[obj]['values'] = enum_values

                elif instance.__bases__[0] is _Pointer:
                    self.pointers[obj] = {}
                    self.pointers[obj]['type_name'] = instance._type_.__name__

                elif instance.__bases__[0] is _SimpleCData:
                    continue
                elif instance.__bases__[0] is CDLL:
                    continue
                elif instance.__bases__[0] is object:
                    continue
                elif instance.__bases__[0] is dict:
                    continue
                elif instance.__bases__[0] is c_ulong:
                    continue
                elif instance.__bases__[0] is Exception:
                    continue
                else:
                    if self.debug_level > 0:
                        self.dump_object(obj, instance)
    def save(self, filename):
        with open(filename, 'w') as fd:
            json.dump({
                'functions': self.function_prototypes,
                'structures': self.structures,
                'enums': self.enums,
                'pointers': self.pointers,
            }, fd, indent = 4)

    def print(self):
        print('* Functions:')
        for function, attributes in self.function_prototypes.items():
            print(function)
            pprint.pprint(attributes)
            print('')
            

        print('* Structures:')
        for structure, attributes in self.structures.items():
            print(structure)
            pprint.pprint(attributes)
            print('')

        print('* Pointers:')
        for pointer, attributes in self.pointers.items():
            print(pointer)
            pprint.pprint(attributes)
            print('')

        print('* Enumerators:')
        for enum, attributes in self.enums.items():
            print(enum)
            pprint.pprint(attributes)
            print('')

        print('* ArgTypes:')
        argtypes_list = list(self.argtypes.keys())
        argtypes_list.sort()
        for argtype in argtypes_list:
            print(argtype)

if __name__ == '__main__':
    dumper = Dumper()
    dumper.enumerate_winfuncs()
    dumper.enumerate_winstructs()
    dumper.print()
    dumper.save("output.json")