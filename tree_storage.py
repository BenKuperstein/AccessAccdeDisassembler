import abc
import io


class ITreeStorage(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def get_node_content(self, node_path: str) -> io.BytesIO:
        pass

    @abc.abstractmethod
    def set_node_content(self, node_path: str, new_content: io.BytesIO):
        pass
