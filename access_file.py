import io
import dataclasses

import pyodbc

import tree_storage


def mdb_connect(db_file, user='admin', password='', old_driver=False) -> pyodbc.Connection:
    driver_ver = '*.mdb'
    if not old_driver:
        driver_ver += ', *.accdb'

    odbc_conn_str = ('DRIVER={Microsoft Access Driver (%s)}'
                     ';DBQ=%s;UID=%s;PWD=%s' %
                     (driver_ver, db_file, user, password))
    return pyodbc.connect(odbc_conn_str)


VBA_TABLE_NAME = "MSysAccessStorage"


@dataclasses.dataclass
class FileNode:
    id: str
    name: str
    type: int


class AccessTreeStorage(tree_storage.ITreeStorage):

    def __init__(self, db: pyodbc.Connection):
        self._dir_tree = self._get_dir_tree(db)
        self._db = db

    @classmethod
    def _get_dir_tree(cls, access_db: pyodbc.Connection, root_node=None) -> dict[str, dict | FileNode]:
        result = {}
        with access_db.cursor() as cursor:
            cursor.execute(
                f"SELECT Id, ParentId, Type, Name "
                f"FROM {VBA_TABLE_NAME} WHERE {'Id=ParentID' if root_node is None else 'ParentId=' + str(root_node)}")
            rows = cursor.fetchall()
            for row in rows:
                file_id, parent_id, file_type, file_name = row
                if root_node == file_id:
                    continue
                if file_type == 2:
                    node = FileNode(id=file_id, name=file_name, type=file_type)
                    result[node.name] = node
                else:
                    result[file_name] = cls._get_dir_tree(access_db, file_id)
        return result

    def _get_node_at_path(self, node_path: str) -> FileNode | dict[str, FileNode | dict]:
        path_list = node_path.split("/")
        current_node = self._dir_tree
        for current_node_name in path_list:
            current_node = current_node[current_node_name]
        return current_node

    def get_node_content(self, node_path: str) -> io.BytesIO:
        node = self._get_node_at_path(node_path)
        if not isinstance(node, FileNode):
            raise RuntimeError(f"the node at the path {node_path} is not a file")
        with self._db.cursor() as cursor:
            cursor.execute(f"SELECT Lv from {VBA_TABLE_NAME} where Id = {node.id}")
            rows = cursor.fetchall()
            if len(rows) != 1:
                raise RuntimeError("Could not fetch row's data")
            data, = rows[0]
            return io.BytesIO(data)

    def set_node_content(self, node_path: str, new_content: io.BytesIO):
        # TODO: implement
        pass


class AccessDBFile:

    def __init__(self, file_path: str):
        self._file_path = file_path

    def __enter__(self):
        self._db = mdb_connect(self._file_path)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._db.close()

    def get_vba_tree_storage(self) -> tree_storage.ITreeStorage:
        return AccessTreeStorage(self._db)
