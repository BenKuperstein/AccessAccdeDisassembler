import os
import typing
import posixpath
import dataclasses
import traceback

import construct
import pefile

import config
import tree_storage
import vba_structs
from common import FunctionTypeInfo, Symbol, VBAFunction, VBAModule


def get_srp_file_name(index: int):
    return f"__SRP_{index:x}"


VBA_FILES_DIR_PATH = "MSysAccessStorage_ROOT/VBA/VBAProject/VBA"
PROJECT_SRP_PATH = posixpath.join(VBA_FILES_DIR_PATH, get_srp_file_name(0))
VBA_PROJECT_PATH = posixpath.join(VBA_FILES_DIR_PATH, "_VBA_PROJECT")

POINTER_SIZE = 4 if config.IS_32_BIT_VBA6 else 8
RESOURCE_TAG_SIZE = POINTER_SIZE

if config.IS_32_BIT_VBA6:
    IMPORTED_DLL_LOOKUP_DIR = r"C:\Program Files (x86)\Common Files\Microsoft Shared\VBA\VBA6"
else:
    IMPORTED_DLL_LOOKUP_DIR = \
        r"C:\Program Files\Microsoft Office\root\vfs\ProgramFilesCommonX64\Microsoft Shared\VBA\VBA7.1"


def get_memory_representation(module_flag: int, resource) -> list[tuple[typing.Any, int]]:
    prop_a = vba_structs.get_module_prop_a(module_flag)

    match prop_a:
        case 1:
            return [(resource.count, POINTER_SIZE), (resource.data, len(resource.data))]
        case 2:
            return [(resource.data, len(resource.data))]
        case 3:
            return [(resource.data, len(resource.data))]
        case 5:
            return [(resource.unk1, 2), (resource.pointer1, POINTER_SIZE), (resource.pointer1, POINTER_SIZE),
                    (resource.pointer2, POINTER_SIZE),
                    (resource.pointer3, POINTER_SIZE)]
        case 6:
            return [(resource.pointer1, POINTER_SIZE), (resource.pointer2, POINTER_SIZE)]
        case 7:
            return [(resource.pointer1, POINTER_SIZE),
                    (resource.pointer2, POINTER_SIZE),
                    (resource.unk1, 2),
                    (resource.unk2, 2),
                    (resource.pointer3, POINTER_SIZE)] + [(resource.pointer4, POINTER_SIZE)] if hasattr(resource,
                                                                                                        "pointer4") \
                else []
        case 10:
            return [(resource.pointer1, POINTER_SIZE), (resource.pointer2, POINTER_SIZE), (resource.unk1, 2),
                    (resource.unk2, 2),
                    (resource.unk3, 4), (resource.pointers, POINTER_SIZE * len(resource.pointers)),
                    (resource.unk4, POINTER_SIZE),
                    (resource.unk5, POINTER_SIZE)]
        case 12:
            return [(resource.length, POINTER_SIZE), (resource.data, len(resource.data))]
        case 13:
            return [(resource.data, len(resource.data))]
        case 14:
            return [(resource.unk1, 1), (resource.count, 1), (resource.unk2, 2), (resource.data, len(resource.data))]
        case 18:
            return [(resource.unk1, 2), (resource.pointer, POINTER_SIZE)]
        case _:
            return []


def extract_offset_to_resource_map(srp):
    resources = srp.resources
    address_to_resource = {}
    offset = 0
    for resource in resources:
        resource_size = vba_structs.get_module_prop_b(resource.module_flag)
        try:
            address_to_resource[offset + RESOURCE_TAG_SIZE] = resource
            offset += resource_size + RESOURCE_TAG_SIZE
        except AttributeError:
            pass
    return address_to_resource


def extract_offset_to_inner_resource_value_map(offset_to_resource_map: dict[int, typing.Any]):
    address_to_inner_resource_value = {}
    for base_address, resource in offset_to_resource_map.items():
        try:
            items = get_memory_representation(resource.module_flag, resource.resource.resource)
            in_resource_offset = 0

            for item, item_length in items:
                address_to_inner_resource_value[base_address + in_resource_offset] = item
                in_resource_offset += item_length
        except AttributeError:
            pass
    return address_to_inner_resource_value


class ParsedSRP:
    def __init__(self, srp_object):
        self.srp_object = srp_object
        self.offset_to_resource = extract_offset_to_resource_map(self.srp_object)
        self.offset_to_inner_resource_value = extract_offset_to_inner_resource_value_map(self.offset_to_resource)


def get_resources_of_type(srp_object, resource_type: int):
    return [resource.value.resource for resource in srp_object.resources if
            vba_structs.get_module_prop_a(resource.value.module_flag) == resource_type]


@dataclasses.dataclass
class LocalFunctionImport64Bit:
    function_index: int
    srp_index: int


@dataclasses.dataclass
class LocalFunctionImport32Bit:
    function_index: int


@dataclasses.dataclass
class NativeFunctionImport:
    dll_name: vba_structs.Fixup
    function_name_or_ordinal: typing.Union[vba_structs.Fixup, int]


@dataclasses.dataclass
class BasicValueImport:
    value: any


ImportTypes = NativeFunctionImport | LocalFunctionImport64Bit | BasicValueImport


@dataclasses.dataclass
class VBAModuleInfo:
    name: str
    index: int
    function_names: list[str]


def try_decode_ascii(byte_string: bytes):
    if not byte_string:
        return ""
    try:
        return byte_string.decode("ascii")
    except Exception:
        return ""


class VBAProject:
    def __init__(self, vba_tree_storage: tree_storage.ITreeStorage):
        self._index_to_parsed_srp: dict[int, ParsedSRP] = {}
        self._vba_tree_storage = vba_tree_storage

        project_srp_stream = vba_tree_storage.get_node_content(PROJECT_SRP_PATH)
        self._srp0 = vba_structs.SRP0.parse_stream(project_srp_stream)
        self._index_to_parsed_srp[0] = ParsedSRP(self._srp0.srp)
        self._load_vba_project()

        self._all_functions: list[str] = []
        self._module_name_to_module_info: dict[str, VBAModuleInfo] = {}
        self._module_index_to_module_info: dict[int, VBAModuleInfo] = {}

        for i, module in enumerate(self._project_resource.modules):
            module_name = self._resolve_fixup(module.name, inner_value=True).decode("ascii")
            function_names = [try_decode_ascii(self._resolve_fixup(function_name_fixup, inner_value=True)) for
                              function_name_fixup
                              in
                              module.functions]

            module_info = VBAModuleInfo(module_name, i, function_names)
            self._module_name_to_module_info[module_name] = module_info
            self._module_index_to_module_info[i] = module_info
            self._all_functions.extend(function_names)
        self._imported_dlls: dict[str, pefile.PE] = {}

    def _get_symbols_linked_list(self, types_buffer: bytes, starting_index: int):
        child_offset = starting_index
        result = []
        while not (child_offset == -1 or child_offset == 0):
            try:
                child = vba_structs.DEFN.parse(types_buffer[child_offset:])
                arg_address = child.var.const_val

                try:
                    arg_name = self._get_symbol_table_string(child.hlnam)
                except IndexError:
                    arg_name = "<failed_to_get_symbol>"

                result.append(Symbol(arg_address, arg_name, child))
                child_offset = child.next
            except Exception:
                print("Error while parsing argument names:")
                print(traceback.format_exc())
                break
        return result

    def _get_global_symbols(self, module: vba_structs.Module) -> list[Symbol]:
        var_defn_offset = module.dtmb.type_data.unknown2[2]
        types_buffer = module.dtmb.type_data.blk.blk_desc.data
        return self._get_symbols_linked_list(types_buffer, var_defn_offset)

    def _get_functions_symbols(self, module: vba_structs.Module) -> dict[str, list[Symbol]]:
        result = {}
        function_defn_offset = module.dtmb.type_data.unknown2[0]
        types_buffer = module.dtmb.type_data.blk.blk_desc.data
        while function_defn_offset != -1:
            function_defn = vba_structs.DEFN.parse(types_buffer[function_defn_offset:])
            args = []
            if function_defn.children_offset != -1:
                function_children = vba_structs.DEFN_CHILDREN_ARRAY.parse(
                    types_buffer[function_defn.children_offset:])
                for child_offset in function_children:
                    args.extend(self._get_symbols_linked_list(types_buffer, child_offset))

            function_name = self._get_symbol_table_string(function_defn.hlnam)
            result[function_name] = args
            function_defn_offset = function_defn.next
        return result

    def _get_non_srp_module_object(self, module_name):
        inner_name = self._module_name_to_inner_name[module_name]
        module_path = posixpath.join(VBA_FILES_DIR_PATH, inner_name)
        module_stream = self._vba_tree_storage.get_node_content(module_path)
        return vba_structs.Module.parse_stream(module_stream)

    def _load_vba_project(self):
        vba_project_stream = self._vba_tree_storage.get_node_content(VBA_PROJECT_PATH)

        vba_project = vba_structs.VBA_PROJECT.parse_stream(vba_project_stream)
        vba_project_module_entries = vba_project.stlib.gtloe.module_entries

        self._module_name_to_inner_name = {entry.module_name.data: entry.inner_name.data for entry in
                                           vba_project_module_entries}
        self._name_manger_strings = [try_decode_ascii(i.unk12) for i in
                                     vba_project.stlib.gtloe.unk17.unk5]

        self._name_manger_string_base = self._get_symbol_table_base_index()

    def _get_symbol_table_base_index(self):
        for module_name in self._module_name_to_inner_name.keys():
            module = self._get_non_srp_module_object(module_name)
            dtbm_data = module.dtmb.type_data.blk.blk_desc.data
            if "Form" in module_name or "Report" in module_name:
                continue
            module_defn_index = module.dtmb.type_data.unknown2[-2]
            module_defn = vba_structs.DEFN.parse(dtbm_data[module_defn_index:])
            return module_defn.hlnam - self._name_manger_strings.index(module_name)

    def _get_symbol_table_string(self, hlnam: int):
        return self._name_manger_strings[hlnam - self._name_manger_string_base]

    def _fully_resolve_import(self, function_import: ImportTypes):
        match function_import:
            case LocalFunctionImport64Bit():
                _, module_index = self._get_srp_type_and_module_index(function_import.srp_index)
                return self._module_index_to_module_info[module_index].function_names[function_import.function_index]
            case LocalFunctionImport32Bit():
                return self._all_functions[function_import.function_index]
            case NativeFunctionImport():
                match function_import.function_name_or_ordinal:
                    case int():
                        dll_name = self._resolve_fixup(function_import.dll_name, inner_value=True)
                        if dll_name in self._imported_dlls:
                            dll = self._imported_dlls[dll_name]
                        else:
                            dll = pefile.PE(os.path.join(IMPORTED_DLL_LOOKUP_DIR,
                                                         dll_name.decode("ascii")))
                            self._imported_dlls[dll_name] = dll

                        for exp in dll.DIRECTORY_ENTRY_EXPORT.symbols:
                            # Check if the symbol's ordinal matches the one we're looking for
                            if exp.ordinal == function_import.function_name_or_ordinal:
                                return exp.name.decode() if exp.name else "Ordinal not associated with a name"
                    case construct.Container():
                        return self._resolve_fixup(function_import.function_name_or_ordinal, inner_value=True)
                    case _:
                        raise RuntimeError(f"Failed to resolve function import fully resolve {function_import}")
            case BasicValueImport():
                return function_import.value
            case _:
                raise RuntimeError(f"Failed to resolve import fully resolve {function_import}")

    def _partial_resolve_import(self, import_fixup: vba_structs):
        import_resource = self._resolve_fixup(import_fixup, inner_value=False)
        if not import_resource:
            return None
        match vba_structs.get_module_prop_a(import_resource.module_flag):
            case 11:
                return BasicValueImport(import_resource.resource.resource.data)
            case 7:
                function_name_pointer = import_resource.resource.resource.pointer2
                function_ordinal = import_resource.resource.resource.unk1
                return NativeFunctionImport(
                    dll_name=import_resource.resource.resource.pointer1,
                    function_name_or_ordinal=function_name_pointer if function_name_pointer.srp_index is not None
                    else function_ordinal)
            case 18:
                if config.IS_32_BIT_VBA6:
                    return LocalFunctionImport32Bit(import_resource.resource.resource.unk1)
                return LocalFunctionImport64Bit(
                    srp_index=import_resource.resource.resource.pointer.srp_index,
                    function_index=import_resource.resource.resource.unk1)
            case _:
                return None

    def _load_srp(self, srp_index: int) -> ParsedSRP:
        srp_stream = self._vba_tree_storage.get_node_content(
            posixpath.join(VBA_FILES_DIR_PATH,
                           get_srp_file_name(srp_index)))
        srp_object = vba_structs.create_srp(self._get_srp_info(srp_index)).parse_stream(
            srp_stream)
        new_object = ParsedSRP(srp_object)
        self._index_to_parsed_srp[srp_index] = new_object
        return new_object

    @property
    def _project_resource(self):
        return self._srp0.srp.resources[0].resource.resource

    def _get_srp_type_and_module_index(self, srp_index: int) -> tuple[vba_structs.SRPModuleType, int]:
        srp_entry = self._srp0.entries[srp_index]
        if srp_entry.module_index == 0xffff:
            if srp_entry.file_type == 0:
                return vba_structs.SRPModuleType.PROJECT, srp_entry.module_index
            elif srp_entry.file_type == 2:
                return vba_structs.SRPModuleType.PROJECT_TYPE, srp_entry.module_index
        if srp_entry.file_type == 0:
            return vba_structs.SRPModuleType.MODULE, srp_entry.module_index
        elif srp_entry.file_type == 2:
            return vba_structs.SRPModuleType.MODULE_TYPE, srp_entry.module_index

    def _get_srp_info(self, srp_index: int) -> vba_structs.SRPInfo:
        srp_type, module_index = self._get_srp_type_and_module_index(srp_index)
        args = {}
        if srp_index > 1:
            module_entry = self._project_resource.modules[module_index]
            module_flag = module_entry.unk
            args["func_num"] = module_entry.count
            args["module_flag"] = module_flag

        return vba_structs.SRPInfo(type=srp_type, args=args)

    def _resolve_fixup(self, fixup: vba_structs.Fixup, inner_value=False):
        if fixup.srp_index == 0xffff or fixup.srp_index is None:
            return None
        if fixup.srp_index not in self._index_to_parsed_srp:
            self._load_srp(fixup.srp_index)
        if inner_value:
            srp_resource_map = self._index_to_parsed_srp[fixup.srp_index].offset_to_inner_resource_value
        else:
            srp_resource_map = self._index_to_parsed_srp[fixup.srp_index].offset_to_resource
        normalized_address = fixup.address // 2
        return srp_resource_map.get(normalized_address, None)

    def get_vba_module(self, module_name: str) -> VBAModule:
        module_info = self._module_name_to_module_info[module_name]
        module_struct = self._project_resource.modules[module_info.index]
        module_code_srp_index = module_struct.code_pointer.srp_index
        module_srp = self._load_srp(module_code_srp_index)

        module_resource = module_srp.srp_object.resources[0].resource.resource

        partially_resolved_imports = [self._partial_resolve_import(import_entry) for import_entry in
                                      module_resource.imports]
        resolved_imports = []
        for partial_import in partially_resolved_imports:
            try:
                resolved_imports.append(self._fully_resolve_import(partial_import))
            except RuntimeError:
                resolved_imports.append("<failed_to_resolve>")

        function_bytecodes = [rtmi.data[:rtmi.code_size] if rtmi.data else None for rtmi in module_resource.rtmis]
        module = self._get_non_srp_module_object(module_name)
        function_symbols = self._get_functions_symbols(module)

        module_functions = [VBAFunction(byte_code, name, FunctionTypeInfo(), function_symbols[name]) for name, byte_code
                            in
                            zip(module_info.function_names, function_bytecodes)]
        module_symbols = self._get_global_symbols(module)

        return VBAModule(name=module_name,
                         function_name_to_function={func.name: func for func in module_functions},
                         imports=resolved_imports,
                         module_symbols=module_symbols,
                         )

    @property
    def modules(self):
        return self._module_index_to_module_info.values()
