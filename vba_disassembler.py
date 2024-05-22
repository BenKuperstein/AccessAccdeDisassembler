import os
import io
import json
import dataclasses

import config
import common
from scripts import parse_opcode_handlers
from scripts.parse_opcode_handlers import *

VBA6_MAX_MNEMONIC = 250


def add_custom_opcodes(original_opcodes: typing.List[parse_opcode_handlers.Opcode]):
    opcode_mapping = {opcode.name: opcode for opcode in original_opcodes}

    for name in ['GetRecOwner3', 'PutRecOwner3']:
        opcode_mapping[name] = Opcode(
            mnemonics=opcode_mapping[name].mnemonics,
            name=name,
            handler_address=opcode_mapping[name].handler_address,
            args=[
                OpcodeArg(offset=0, size=2),
                VariableSizeOpcodeArg(offset=2, index_of_size=0, op_on_size=lambda x: (x, 1))
            ],
            init=True,
        )

    opcode_mapping['CopyBytes'] = Opcode(
        mnemonics=opcode_mapping['CopyBytes'].mnemonics,
        name='CopyBytes',
        handler_address=opcode_mapping["CopyBytes"].handler_address,
        variable_length=True,
        args=[
            OpcodeArg(offset=0, size=2),  # arg_1
            OpcodeArg(offset=100, size=0)
        ],
        init=True,
    )

    if not config.IS_32_BIT_VBA6:
        # Opcodes with two int16 arguments
        for name in ['VCallUI1', 'VCallBasicAd', 'PrintObject', 'PrintFile', 'WriteFile', 'InputFile']:
            opcode_mapping[name] = Opcode(
                mnemonics=opcode_mapping[name].mnemonics,
                name=name,
                handler_address=opcode_mapping[name].handler_address,
                args=[OpcodeArg(offset=0, size=2), OpcodeArg(offset=2, size=2), OpcodeArg(offset=100, size=0)],
                init=True,
            )

        # Opcodes with int32 and int16 arguments
        for name in ['IStDargUnkFunc', 'ForStepVar']:
            opcode_mapping[name] = Opcode(
                mnemonics=opcode_mapping[name].mnemonics,
                name=name,
                handler_address=opcode_mapping[name].handler_address,
                args=[OpcodeArg(offset=0, size=4), OpcodeArg(offset=4, size=2), OpcodeArg(offset=100, size=0)],
                init=True,
            )

        for name in ['BosStub', 'IWMemStDargUnkFunc']:
            opcode_mapping[name] = Opcode(
                mnemonics=opcode_mapping[name].mnemonics,
                name=name,
                handler_address=opcode_mapping[name].handler_address,
                # Further investigation needed for these opcodes
                args=[OpcodeArg(offset=-1, size=0)],
                init=False
            )

        for name in ['PrintObject', 'PrintFile', 'WriteFile', 'InputFile']:
            opcode_mapping[name] = Opcode(
                mnemonics=opcode_mapping[name].mnemonics,
                name=name,
                handler_address=opcode_mapping[name].handler_address,
                args=[OpcodeArg(offset=0, size=2), OpcodeArg(offset=2, size=2), OpcodeArg(offset=100, size=0)],
                init=True,
                # Further analysis may be needed to confirm additional arguments
            )
    if config.IS_32_BIT_VBA6:
        opcode_mapping["Bos"] = Opcode(
            mnemonics=opcode_mapping["Bos"].mnemonics,
            name="Bos",
            handler_address=opcode_mapping["Bos"].handler_address,
            args=[OpcodeArg(offset=0, size=1), OpcodeArg(offset=1, size=1)],
            init=True,
        )

        opcode_mapping["CCyCy"] = Opcode(
            mnemonics=opcode_mapping["CCyCy"].mnemonics,
            name="CCyCy",
            handler_address=opcode_mapping["CCyCy"].handler_address,
            args=[OpcodeArg(offset=0, size=1), OpcodeArg(offset=1, size=1)],
            init=True,
        )

        # Opcodes with int16 arg_1 and potentially more arguments
    for name in ['FFreeVar', 'FFreeStr', 'FFreeAd']:
        opcode_mapping[name] = Opcode(
            mnemonics=opcode_mapping[name].mnemonics,
            name=name,
            handler_address=opcode_mapping[name].handler_address,
            args=[OpcodeArg(offset=0, size=2),
                  VariableSizeOpcodeArg(offset=2, index_of_size=0, op_on_size=lambda x: (4, x / 2)),
                  OpcodeArg(offset=100, size=0)],
            init=True,
            # Further analysis may be needed to confirm additional arguments
        )

    for name in ['Branch']:
        opcode_mapping[name] = Opcode(
            mnemonics=opcode_mapping[name].mnemonics,
            name=name,
            handler_address=opcode_mapping[name].handler_address,
            args=[OpcodeArg(offset=0, size=2 if config.IS_32_BIT_VBA6 else 4), OpcodeArg(offset=100, size=0)],
            init=True,
            # Further analysis may be needed to confirm additional arguments
        )

    for opcode in opcode_mapping.values():
        if not opcode.init:
            opcode.args = []
        else:
            opcode.args = sorted(opcode.args, key=lambda i: i.offset)[:-1]

    for opcode_name, opcode in opcode_mapping.items():
        if "AdCall" in opcode_name:
            opcode.args[0].type = OpcodeArgType.IMPORT_INDEX
        if "LitVarStr" in opcode_name:
            opcode.args[1].type = OpcodeArgType.IMPORT_INDEX
        if "LitStr" in opcode_name:
            opcode.args[0].type = OpcodeArgType.IMPORT_INDEX
        if len([i for i in ("Var", "FLd", "FSt") if i in opcode_name]):
            if len(opcode.args) > 0:
                opcode.args[0].type = OpcodeArgType.VAR_ADDRESS

    return opcode_mapping.values()


def read_num(stream: io.BytesIO, size, signed=False):
    raw = stream.read(size)
    if len(raw) != size:
        raise EOFError
    return int.from_bytes(raw, byteorder="little", signed=signed)


@dataclasses.dataclass
class ParsedOpcode:
    mnemonic: int
    opcode: Opcode
    args_raw: list[int]


class Disassembler:
    def __init__(self, opcodes_file: pathlib.Path):
        with open(os.path.join(os.path.dirname(__name__), opcodes_file), "r") as opcodes_file:
            model = pydantic.RootModel[typing.List[parse_opcode_handlers.Opcode]]
            opcodes = model.model_validate(json.load(opcodes_file)).root
        self._opcodes = add_custom_opcodes(opcodes)
        self._code_to_opcode = {}
        for opcode in self._opcodes:
            for code in opcode.mnemonics:
                self._code_to_opcode[code] = opcode

    @classmethod
    def _read_next_opcode_vba6(cls, bytecode: io.BytesIO) -> int:
        opcode_mnemonic = read_num(bytecode, 1)
        if opcode_mnemonic <= VBA6_MAX_MNEMONIC:
            return opcode_mnemonic
        second_opcode_mnemonic = read_num(bytecode, 1)
        return ((opcode_mnemonic - VBA6_MAX_MNEMONIC) * 0xff) + second_opcode_mnemonic

    @classmethod
    def _read_next_opcode_vba7(cls, bytecode: io.BytesIO) -> int:
        return read_num(bytecode, 2)

    def _read_next_opcode(self, bytecode: io.BytesIO) -> ParsedOpcode:
        if config.IS_32_BIT_VBA6:
            opcode_mnemonic = self._read_next_opcode_vba6(bytecode)
        else:
            opcode_mnemonic = self._read_next_opcode_vba7(bytecode)

        opcode = self._code_to_opcode[opcode_mnemonic]

        raw_args = []
        for arg in opcode.args:
            if isinstance(arg, OpcodeArg):
                opcode_size = arg.size
                arg_value = read_num(bytecode, opcode_size, signed=True)
                raw_args.append(arg_value)
            else:
                opcode_size, count = arg.op_on_size(raw_args[arg.index_of_size])
                for i in range(int(count)):
                    raw_args.append(read_num(bytecode, opcode_size, signed=True))
        return ParsedOpcode(opcode_mnemonic, opcode, raw_args)

    @classmethod
    def _get_address_to_var_name_map(cls, vba_module: common.VBAModule, vba_function: common.VBAFunction):
        address_to_var_name = {}
        for sym in vba_module.module_symbols:
            address_to_var_name[sym.address] = sym.name

        for sym in vba_function.function_symbols:
            address_to_var_name[sym.address] = sym.name
        return address_to_var_name

    def disassemble(self, vba_module: common.VBAModule, func_name: str):
        function = vba_module.function_name_to_function[func_name]
        bytecode = io.BytesIO(function.bytecode)
        address_to_var_name = self._get_address_to_var_name_map(vba_module, function)
        disassembly = []
        while True:
            opcode_index = bytecode.tell()
            try:
                opcode = self._read_next_opcode(bytecode)
                parsed_args = []
                for arg_raw_value, arg in zip(opcode.args_raw, opcode.opcode.args):
                    match arg.type:
                        case OpcodeArgType.IMPORT_INDEX:
                            if 0 <= arg_raw_value <= len(vba_module.imports):
                                parsed_args.append(f"{vba_module.imports[arg_raw_value]}<{hex(arg_raw_value)}>")
                            else:
                                parsed_args.append(hex(arg_raw_value))
                        case OpcodeArgType.VAR_ADDRESS:
                            if arg_raw_value in address_to_var_name:
                                parsed_args.append(address_to_var_name[arg_raw_value])
                            else:
                                parsed_args.append(hex(arg_raw_value))
                        case _:
                            parsed_args.append(hex(arg_raw_value))

                disassembly.append(
                    f"{hex(opcode_index)}: {opcode.opcode.name}({','.join([i for i in parsed_args])}) [{hex(opcode.mnemonic)}]")
            except EOFError:
                break
            except KeyError:
                disassembly.append(f"{hex(opcode_index)}: Failed to read opcode")

        return "\n".join(disassembly)
