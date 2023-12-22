from abc import ABC, abstractmethod
from libp2p.typing import TProtocol
from typing import Dict, List


class DataManager(ABC):
    @abstractmethod
    def get_nonces(self) -> List:
        pass

    @abstractmethod
    def set_nonces(self, nonces_list: List) -> None:

        pass

    @abstractmethod
    def set_dkg_key(self,  key, value) -> None:
        pass

    @abstractmethod
    def get_dkg_key(self, key):
        pass


class NodeInfo(ABC):
    @abstractmethod
    def lookup_node(self, peer_id: str, node_id: str = None):
        pass

    @abstractmethod
    def get_all_nodes(self, n: int = None) -> Dict:
        pass


class Validators(ABC):
    @staticmethod
    @abstractmethod
    def caller_validator(sender_id: str, protocol: TProtocol):
        pass

    @staticmethod
    @abstractmethod
    def data_validator(self, input_data: Dict):
        pass
