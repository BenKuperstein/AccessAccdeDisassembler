import dataclasses
import typing

import vba_structs


@dataclasses.dataclass
class FunctionTypeInfo:
    pass


@dataclasses.dataclass
class Symbol:
    address: int
    name: str
    extra: vba_structs.DEFN


@dataclasses.dataclass
class VBAFunction:
    bytecode: bytes
    name: str
    type_info: FunctionTypeInfo
    function_symbols: list[Symbol]


@dataclasses.dataclass
class VBAModule:
    name: str
    function_name_to_function: dict[str, VBAFunction]
    imports: list[typing.Any]
    module_symbols: list[Symbol]
