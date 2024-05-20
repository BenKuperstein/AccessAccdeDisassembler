import json
import os
import base64
import argparse


def decode_binary(binary_str):
    print(binary_str)
    return base64.b64decode(binary_str.encode())


def build_tree(json_entries):
    nodes = {entry["Id"]: entry for entry in json_entries}
    return nodes


def get_path(entries, node_id):
    node = entries[node_id]
    if node["ParentId"] == node["Id"]:
        return node["Name"]
    return os.path.join(get_path(entries, node["ParentId"]), node["Name"])


def create_structure(entries, path="."):
    for node in entries.values():
        print(node["Type"])
        if node["Type"] == 2:  # File
            current_path = get_path(entries, node["Id"])
            os.makedirs(os.path.dirname(current_path), exist_ok=True)
            with open(current_path, 'wb') as f:
                binary_str = node.get("Lv", {}).get("$binary", "")
                f.write(decode_binary(binary_str))


def main():
    parser = argparse.ArgumentParser(description="Process a JSON file to create directory structure.")
    parser.add_argument("json_file", type=str, help="Path to the input JSON file. created by the command "
                                                    "mdb-json <db_path> MSysAccessStorage | jq -s")
    args = parser.parse_args()

    with open(args.json_file, 'r') as file:
        entries = json.load(file)

    tree = build_tree(entries)
    create_structure(tree)


if __name__ == "__main__":
    main()
