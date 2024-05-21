import os
import argparse
import pathlib
import traceback

import access_file
import access_project
import config
import vba_disassembler

VBA6_OPCODE_FILE = pathlib.Path(__file__).parent.joinpath("generated/opcodes_vba6.json")
VBA7_OPCODE_FILE = pathlib.Path(__file__).parent.joinpath("generated/opcodes_vba7.json")

def disassemble_all(file_path: str):
    if config.IS_32_BIT_VBA6:
        opcodes_file_path = VBA6_OPCODE_FILE
    else:
        opcodes_file_path = VBA7_OPCODE_FILE

    with access_file.AccessDBFile(file_path) as db_file:
        tree_storage = db_file.get_vba_tree_storage()
        project = access_project.VBAProject(tree_storage)
        disassembler = vba_disassembler.Disassembler(opcodes_file_path)
        for module in project.modules:
            vba_module = project.get_vba_module(module.name)
            print(f"Module: module.name")
            for function in vba_module.function_name_to_function.values():
                try:
                    print(f"Function: {function.name}")
                    print(disassembler.disassemble(vba_module, function.name))
                except Exception:
                    print(f"Failed to parse func {function.name}:")
                    print(traceback.format_exc())


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--accde-file-path", type=pathlib.Path, required=True)
    args = parser.parse_args()
    disassemble_all(args.accde_file_path)
