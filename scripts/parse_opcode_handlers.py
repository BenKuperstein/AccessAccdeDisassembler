import os
import typing
import dataclasses
import argparse
import time

import angr
import pydantic

import logging

logging.getLogger('angr').setLevel('ERROR')

ADDRESSES_FILE_BASE_ADDRESS = 0x00007ffadfea0000
IMAGE_DEFAULT_BASE_ADDRESS = 0x180000000
ADDRESSES_FILE_PATH = os.path.join(os.path.dirname(__file__), "addresses.txt")


@dataclasses.dataclass(frozen=True)
class OpcodeArg:
    offset: int
    size: int


@dataclasses.dataclass
class VariableSizeOpcodeArg:
    offset: int
    index_of_size: int
    op_on_size: typing.Callable[int, int]


@dataclasses.dataclass
class Opcode:
    mnemonics: typing.List[int]
    name: str
    handler_address: int
    init: bool = False
    variable_length: bool = False
    args: typing.Union[None, typing.List[typing.Union[OpcodeArg, VariableSizeOpcodeArg]]] = None


def load_opcodes_from_db_file() -> typing.List[Opcode]:
    """
    In order to create the addresses.txt file the windbg command: dps VBE7!tblDispatch L1000 was used, and the output was further edited manually
    """
    with open(ADDRESSES_FILE_PATH, "r") as db_file:
        opcodes = {}
        for index, line in enumerate(db_file.readlines()):
            addr_str, name = line.split()
            handler_address = int(addr_str, base=16) - ADDRESSES_FILE_BASE_ADDRESS + IMAGE_DEFAULT_BASE_ADDRESS
            if name in opcodes:
                opcodes[name].mnemonics.append(index)
            else:
                opcodes[name] = (Opcode([index], name, handler_address))
        return opcodes.values()


def main():
    opcodes = load_opcodes_from_db_file()
    project = angr.Project(
        r"C:\Program Files\Microsoft Office\root\vfs\ProgramFilesCommonX64\Microsoft Shared\VBA\VBA7.1\VBE7.DLL",
        auto_load_libs=True)
    for opcode in opcodes:
        if opcode.name in {"AddStr"}:
            continue

        for i in range(2):
            print(f"Loading {opcode.name}")
            state = project.factory.blank_state(addr=opcode.handler_address, add_options={angr.options.CALLLESS})
            state.regs.r12 = 0x1000
            state.regs.rsi = 0x2000
            state.regs.rbp = 0x3000
            state.mem[state.regs.rbp - 0xA].uint64_t = 0x4000
            state.regs.rsp = 0x5000
            state.regs.r14 = 0x6000
            state.regs.rbx = 0x7000
            state.regs.rdi = 0x8000
            state.regs.r13 = 0x9000
            state.regs.r15 = 0xa000
            state.regs.gs = 0x2b
            state.mem[state.regs.r14].uint64_t = 0xb000
            state.mem[state.regs.r14 + 8].uint64_t = 0xc000
            state.mem[state.regs.r14 + 16].uint64_t = 0xd000
            state.mem[state.regs.r14 + 24].uint64_t = 0xe000
            state.mem[state.regs.r14 + 32].uint64_t = 0xf000
            state.mem[0xb000].uint64_t = 8
            state.mem[0xb000 + 8].uint64_t = 0x10000

            state.mem[0xc000].uint64_t = 8
            state.mem[0xc000 + 8].uint64_t = 0x11000

            state.mem[0xd000].uint64_t = 8
            state.mem[0xd000 + 8].uint64_t = 0x12000

            state.mem[0xe000].uint64_t = 8
            state.mem[0xe000 + 8].uint64_t = 0x13000

            state.mem[0xf000].uint64_t = 8
            state.mem[0xf000 + 8].uint64_t = 0x14000

            if i == 1:
                for j in range(32):
                    state.mem[0x2000 + j].uint8_t = 0xaa

            simgr = project.factory.simgr(state)
            args = set()

            def on_read(s: angr.SimState):
                read_address = s.solver.eval(s.inspect.mem_read_address)
                if 0x2000 <= read_address < 0x2100:
                    print(hex(read_address))
                    offset = read_address - 0x2000
                    size = s.inspect.mem_read_length
                    arg = OpcodeArg(offset, size)
                    if arg not in args:
                        args.add(arg)

            state.inspect.b("mem_read", action=on_read)
            start_time = time.time()
            while not (hasattr(simgr, "over") and len(simgr.over) > 0 and args) and simgr.active:
                simgr = simgr.step(num_inst=1)
                simgr = simgr.move("active", "over", lambda s: s.solver.eval(s.memory.load(s.addr, 3)) == 0xff24c3)
                simgr = simgr.move("unconstrained", "active")
                if "Exit" in opcode.name:
                    simgr = simgr.move("active", "over", lambda s: s.solver.eval(s.memory.load(s.addr, 1)) == 0xc3)

                if time.time() - start_time > 5:
                    args = set()
                    break
            if opcode.args != None and opcode.args != args:
                opcode.variable_length = True
            opcode.args = args
            if len(args) > 0:
                opcode.init = True
    for i in opcodes:
        print(i)
    with open("opcodes.json", "w") as opcode_file:
        opcode_file.write(pydantic.RootModel[typing.List[Opcode]](opcodes).model_dump_json())
    print(f"fail count: {len([opcode for opcode in opcodes if not opcode.init])}")
    print(f"failed: {[opcode for opcode in opcodes if not opcode.init]}")


if __name__ == "__main__":
    main()
