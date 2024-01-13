from abc import ABC, abstractmethod
from typing import Dict, List, Any


class DataManager(ABC):
    @abstractmethod
    def get_nonce(self, nonce_public: str) -> List:
        pass

    @abstractmethod
    def set_nonce(self, nonce_public: str, nonce_private: str) -> None:
        pass
    
    @abstractmethod
    def remove_nonce(self, nonce_public: str) -> None:
        pass

    @abstractmethod
    def set_key(self,  key, value) -> None:
        pass

    @abstractmethod
    def get_key(self, key):
        pass
    
    @abstractmethod
    def remove_key(self, key):
        pass


class NodesInfo(ABC):
    @abstractmethod
    def lookup_node(self, peer_id: str, node_id: str = None):
        pass

    @abstractmethod
    def get_all_nodes(self, n: int = None) -> Dict:
        pass


class Validators(ABC):
    @staticmethod
    @abstractmethod
    def caller_validator(ip: str, method: Any):
        pass

    @staticmethod
    @abstractmethod
    def data_validator(self, input_data: Dict):
        pass
