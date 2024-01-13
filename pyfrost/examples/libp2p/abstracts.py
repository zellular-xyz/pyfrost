from pyfrost.network_libp2p.abstract import Validators, DataManager, NodesInfo as BaseNodeInfo
from config import VALIDATED_CALLERS, generate_secrets_and_nodes_info
from itertools import islice
from typing import Dict, Any
import hashlib
import json


class NodeDataManager(DataManager):
    def __init__(self) -> None:
        super().__init__()
        self.__dkg_keys = {}
        self.__nonces = {}

    def set_nonce(self, nonce_public: str, nonce_private: str) -> None:
        self.__nonces[nonce_public] = nonce_private

    def get_nonce(self, nonce_public: str):
        return self.__nonces[nonce_public]

    def remove_nonce(self, nonce_public: str) -> None:
        del self.__nonces[nonce_public]

    def set_key(self, key, value) -> None:
        self.__dkg_keys[key] = value

    def get_key(self, key):
        return self.__dkg_keys.get(key, {})
    
    def remove_key(self, key):
        del self.__nonces[key]


class NodeValidators(Validators):
    def __init__(self) -> None:
        super().__init__()

    @staticmethod
    def caller_validator(ip: str, method: Any):
        if method in VALIDATED_CALLERS.get(str(ip), {}):
            return True
        return False

    @staticmethod
    def data_validator(input_data: Dict):
        result = {
            'data': input_data
        }
        hash_obj = hashlib.sha3_256(json.dumps(result['data']).encode())
        hash_hex = hash_obj.hexdigest()
        result['hash'] = hash_hex
        return result


class NodesInfo(BaseNodeInfo):
    def __init__(self):
        self.nodes, _ = generate_secrets_and_nodes_info()

    def lookup_node(self, peer_id: str, node_id: str = None):
        if node_id is None:
            for node_id, data in self.nodes.items():
                result = data.get(peer_id, None)
                if result is not None:
                    return result, node_id
            return None
        return self.nodes.get(node_id, {}).get(peer_id, None), node_id

    def get_all_nodes(self, n: int = None) -> Dict:
        if n is None:
            n = len(self.nodes)
        result = {}
        for node, data in islice(self.nodes.items(), n):
            result[node] = list(data.keys())
        return result