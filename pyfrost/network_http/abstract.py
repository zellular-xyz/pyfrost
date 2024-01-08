from abc import ABC, abstractmethod
from typing import Dict, List, Any


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


class NodesInfo(ABC):
    @abstractmethod
    def lookup_node(self, node_id: str):
        pass

    @abstractmethod
    def get_all_nodes(self, n: int = None) -> Dict:
        pass

# TODO: Use request object instead of method


class Validators(ABC):
    @staticmethod
    @abstractmethod
    def caller_validator(ip: str, request: Any):
        pass

    @staticmethod
    @abstractmethod
    def data_validator(self, input_data: Dict):
        pass
