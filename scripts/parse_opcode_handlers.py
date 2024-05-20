import typing
import argparse
import dataclasses
import pathlib
import enum
import time
import logging

import angr
import pydantic

import config

logging.getLogger('angr').setLevel('ERROR')

MAX_SECOND_PER_HANDLER = 5


class OpcodeArgType(enum.Enum):
    IMPORT_INDEX = enum.auto()
    VAR_ADDRESS = enum.auto()
    OTHER = enum.auto()


@dataclasses.dataclass(frozen=__name__ == "__main__")
class OpcodeArg:
    offset: int
    size: int
    type: OpcodeArgType = OpcodeArgType.OTHER


@dataclasses.dataclass
class VariableSizeOpcodeArg:
    offset: int
    index_of_size: int
    op_on_size: typing.Callable[[int], typing.Tuple[int, int]]
    type: OpcodeArgType = OpcodeArgType.OTHER


@dataclasses.dataclass
class Opcode:
    mnemonics: typing.List[int]
    name: str
    handler_address: int
    init: bool = False
    variable_length: bool = False
    args: typing.Union[None, typing.List[typing.Union[OpcodeArg, VariableSizeOpcodeArg]]] = None


def load_opcodes_from_addresses_file(address_file_path: pathlib.Path,
                                     file_base_address: int,
                                     default_base_address: int) -> typing.Iterable[Opcode]:
    """
    In order to create the addresses_vba7.txt file the windbg command: dps VBE7!tblDispatch L1000 was used, and the output was further edited manually
    """
    with open(str(address_file_path), "r") as db_file:
        opcodes = {}
        for index, line in enumerate(db_file.readlines()):
            addr_str, name = line.split()
            handler_address = int(addr_str, base=16) - file_base_address + default_base_address
            if name in opcodes:
                opcodes[name].mnemonics.append(index)
            else:
                opcodes[name] = (Opcode([index], name, handler_address))
        return opcodes.values()


def get_handler_end_opcode_data():
    return 0xff2485 if config.IS_32_BIT_VBA6 else 0xff24c3


BYTECODE_START_ADDRESS = 0x2000
BYTECODE_END_ADDRESS = 0x2100


def generate_mapping(emulated_dll: pathlib.Path, output_mapping: pathlib.Path, opcodes: typing.Iterable[Opcode]):
    project = angr.Project(
        str(emulated_dll),
        auto_load_libs=True)

    for opcode in opcodes:
        if opcode.name in {"AddStr"}:
            continue
        print(f"Loading {opcode.name}")
        state = project.factory.blank_state(addr=opcode.handler_address, add_options={angr.options.CALLLESS})
        if config.IS_32_BIT_VBA6:
            state.regs.esi = BYTECODE_START_ADDRESS
        else:
            state.regs.rsi = BYTECODE_START_ADDRESS

        simgr = project.factory.simgr(state)
        args = set()

        def on_read(s: angr.SimState):
            read_address = s.solver.eval(s.inspect.mem_read_address)
            if BYTECODE_START_ADDRESS <= read_address < BYTECODE_END_ADDRESS:
                offset = read_address - BYTECODE_START_ADDRESS
                size = s.inspect.mem_read_length
                arg = OpcodeArg(offset, size)
                if arg not in args:
                    args.add(arg)

        state.inspect.b("mem_read", action=on_read)
        start_time = time.time()
        while not (hasattr(simgr, "over") and len(simgr.over) > 0 and args) and simgr.active:
            simgr = simgr.step(num_inst=1)
            simgr = simgr.move("active", "over", lambda s: s.solver.eval(
                s.memory.load(s.addr, 3)) == get_handler_end_opcode_data())
            simgr = simgr.move("unconstrained", "active")
            if "Exit" in opcode.name:
                try:
                    simgr = simgr.move("active", "over", lambda s: s.solver.eval(s.memory.load(s.addr, 1)) == 0xc7)
                except Exception:
                    pass
            if time.time() - start_time > MAX_SECOND_PER_HANDLER:
                args = list()
                break
        opcode.args = list(args)
        if len(args) > 0:
            opcode.init = True

    with open(str(output_mapping), "w") as opcode_file:
        opcode_file.write(pydantic.RootModel[typing.List[Opcode]](opcodes).model_dump_json())
    print(f"Number of opcodes failed to map: {len([opcode for opcode in opcodes if not opcode.init])}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-mapping-path", type=pathlib.Path, required=True)
    parser.add_argument("--emulated-dll-path", type=pathlib.Path, required=True)
    parser.add_argument("--addresses-file-path", type=pathlib.Path, required=True)

    if config.IS_32_BIT_VBA6:
        addresses_file_base_address = 0x66000000
        image_default_base_address = 0x66000000
    else:
        addresses_file_base_address = 0x00007ffadfea0000
        image_default_base_address = 0x180000000

    args = parser.parse_args()
    opcodes = load_opcodes_from_addresses_file(args.addresses_file_path,
                                               addresses_file_base_address,
                                               image_default_base_address)
    generate_mapping(args.emulated_dll_path, args.output_mapping_path, opcodes)
