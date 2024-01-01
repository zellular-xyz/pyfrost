from pyfrost.network_libp2p.abstract import Validators, DataManager, NodeInfo as BaseNodeInfo
from libp2p.typing import TProtocol
from config import VALIDATED_CALLERS , generate_secrets_and_node_info
from itertools import islice
from typing import Dict, List
import hashlib
import json


class NodeDataManager(DataManager):
    def __init__(self) -> None:
        super().__init__()
        self.__dkg_keys = {}
        self.__nonces = []

    def set_nonces(self, nonces_list = List) -> None:
        self.__nonces = nonces_list

    def get_nonces(self):
        return self.__nonces

    def set_key(self, key, value) -> None:
        self.__dkg_keys[key] = value

    def get_key(self, key):
        return self.__dkg_keys.get(key, {})


class NodeValidators(Validators):
    def __init__(self) -> None:
        super().__init__()

    @staticmethod
    def caller_validator(sender_id: str, protocol: TProtocol):
        if protocol in VALIDATED_CALLERS.get(str(sender_id), {}):
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


class NodeInfo(BaseNodeInfo):
    def __init__(self):
        self.nodes, _ = generate_secrets_and_node_info()
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