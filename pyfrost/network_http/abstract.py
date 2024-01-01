from abc import ABC, abstractmethod
from typing import Dict, List


class DataManager(ABC):
    @abstractmethod
    def get_nonces(self) -> List:
        pass

    @abstractmethod
    def set_nonces(self, nonces_list) -> None:
        pass

    @abstractmethod
    def set_key(self,  key, value) -> None:
        pass

    @abstractmethod
    def get_key(self, key):
        pass


class NodeInfo(ABC):
    @abstractmethod
    def lookup_node(self, node_id: str):
        pass

    @abstractmethod
    def get_all_nodes(self, n: int = None) -> Dict:
        pass


class Validators(ABC):
    @staticmethod
    @abstractmethod
    def caller_validator(ip: str, method: str):
        pass

    @staticmethod
    @abstractmethod
    def data_validator(self, input_data: Dict):
        pass
