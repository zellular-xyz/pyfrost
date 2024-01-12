from .libp2p_base import Libp2pBase, PROTOCOLS_ID
from .abstract import NodesInfo, DataManager
from pyfrost.frost import Key, KeyGen
from pyfrost import create_nonces
from libp2p.network.stream.net_stream_interface import INetStream
from libp2p.crypto.secp256k1 import Secp256k1PublicKey

from typing import Dict, List

import json
import logging
import types


def stream_handler(handler):
    async def wrapper(self, stream: INetStream):
        sender_id = stream.muxed_conn.peer_id
        if self.caller_validator(sender_id.to_base58(), stream.get_protocol()):
            message = await stream.read()
            message = message.decode('utf-8')
            data = json.loads(message)
            logging.debug(
                f'{sender_id}{stream.get_protocol()} Got message: {json.dumps(data, indent=4)}')
            data = await handler(self, data)
            response = json.dumps(data).encode('utf-8')
            await stream.write(response)
            logging.debug(
                f'{sender_id}{stream.get_protocol()} Sent message: {json.dumps(data, indent=4)}')
            await stream.close()
        else:
            raise Exception('Error. Unauthorized SA.')
    return wrapper


class Node(Libp2pBase):
    def __init__(self, data_manager: DataManager, address: Dict[str, str],
                 secret: str, nodes_info: NodesInfo, caller_validator: types.FunctionType,
                 data_validator: types.FunctionType) -> None:
        super().__init__(address, secret)
        self.nodes_info: NodesInfo = nodes_info
        self.key_gens: Dict[str, KeyGen] = {}
        self.caller_validator = caller_validator
        self.data_validator = data_validator

        # Define handlers for various protocol methods
        handlers = {
            'round1': self.round1_handler,
            'round2': self.round2_handler,
            'round3': self.round3_handler,
            'generate_nonces': self.generate_nonces_handler,
            'sign': self.sign_handler,
        }
        self.set_protocol_and_handler(PROTOCOLS_ID, handlers)
        self.data_manager: DataManager = data_manager

    @stream_handler
    async def round1_handler(self, data: Dict) -> None:

        parameters = data['parameters']
        dkg_id = parameters['dkg_id']
        party: Dict = parameters['party']
        threshold = parameters['threshold']

        assert self.peer_id in list(
            party.values()), f'This node is not amoung specified party for app {dkg_id}'
        assert threshold <= len(
            party), f'Threshold must be <= n for Dkg {dkg_id}'

        partners = [str(node_id)
                    for node_id in party if self.peer_id.to_base58() not in party[node_id]]
        node_id = self.nodes_info.lookup_node(
            self.peer_id.to_base58())[1]
        self.key_gens[dkg_id] = KeyGen(
            dkg_id, threshold, node_id, partners)

        round1_broadcast_data = self.key_gens[dkg_id].round1()
        broadcast_bytes = json.dumps(round1_broadcast_data).encode('utf-8')
        data = {
            'broadcast': round1_broadcast_data,
            'validation': self._key_pair.private_key.sign(broadcast_bytes).hex(),
            'status': 'SUCCESSFUL',
        }
        return data

    @stream_handler
    async def round2_handler(self, data: Dict) -> None:

        parameters = data['parameters']
        dkg_id = parameters['dkg_id']
        whole_broadcasted_data = parameters['broadcasted_data']

        broadcasted_data = []
        for peer_id, data in whole_broadcasted_data.items():
            # TODO: error handling (if verification failed)
            data_bytes = json.dumps(data['broadcast']).encode('utf-8')
            validation = bytes.fromhex(data['validation'])
            public_key_bytes = bytes.fromhex(
                self.nodes_info.lookup_node(peer_id)[0]['public_key'])
            public_key = Secp256k1PublicKey.deserialize(public_key_bytes)
            broadcasted_data.append(data['broadcast'])
            logging.debug(
                f'Verification of sent data from {peer_id}: {public_key.verify(data_bytes, validation)}')

        round2_broadcast_data = self.key_gens[dkg_id].round2(broadcasted_data)
        data = {
            'broadcast': round2_broadcast_data,
            'status': 'SUCCESSFUL',
        }
        return data

    @stream_handler
    async def round3_handler(self, data: Dict) -> None:

        parameters = data['parameters']
        dkg_id = parameters['dkg_id']
        send_data = parameters['send_data']

        round3_data = self.key_gens[dkg_id].round3(send_data)
        if round3_data['status'] == 'COMPLAINT':
            if self.key_gens.get(dkg_id) is not None:
                del self.key_gens[dkg_id]

        round3_data['validation'] = None
        if round3_data['status'] == 'SUCCESSFUL':
            sign_data = json.dumps(round3_data['data']).encode('utf-8')
            round3_data['validation'] = self._key_pair.private_key.sign(
                sign_data).hex()

            self.data_manager.set_key(
                str(round3_data['dkg_key_pair']['dkg_public_key']), round3_data['dkg_key_pair'])

        data = {
            'data': round3_data['data'],
            'status': round3_data['status'],
            'validation': round3_data['validation']
        }
        return data

    @stream_handler
    async def generate_nonces_handler(self, data: Dict) -> None:

        parameters = data['parameters']
        number_of_nonces = parameters['number_of_nonces']

        node_id = self.nodes_info.lookup_node(
            self.peer_id.to_base58())[1]
        nonces, save_data = create_nonces(
            int(node_id), number_of_nonces)
        for nonce in save_data:
            nonce_e_public, nonce_e_private = nonce['nonce_e_pair'].popitem()
            self.data_manager.set_nonce(str(nonce_e_public), nonce_e_private)
            nonce_d_public, nonce_d_private = nonce['nonce_d_pair'].popitem()
            self.data_manager.set_nonce(str(nonce_d_public), nonce_d_private)
        data = {
            'nonces': nonces,
            'status': 'SUCCESSFUL',
        }
        return data

    @stream_handler
    async def sign_handler(self, data: Dict) -> None:
        parameters = data['parameters']
        dkg_public_key = parameters['dkg_public_key']
        nonces_dict = parameters['nonces_dict']
        sa_data = data['data']

        result = {}
        result = self.data_validator(sa_data)
        key_pair = self.data_manager.get_key(str(dkg_public_key))
        node_id = self.nodes_info.lookup_node(
            self.peer_id.to_base58())[1]
        key = Key(key_pair, node_id)
        nonce_public_pair = nonces_dict[node_id]
        nonce_d_public = nonce_public_pair['public_nonce_d']
        nonce_e_public = nonce_public_pair['public_nonce_e']
        nonce_d_private = self.data_manager.get_nonce(str(nonce_d_public))
        nonce_e_private = self.data_manager.get_nonce(str(nonce_e_public))
        nonce = {
            'nonce_d': nonce_d_private,
            'nonce_e': nonce_e_private
        }
        result['signature_data'] = key.sign(
            nonces_dict, result['hash'], nonce)
        self.data_manager.remove_nonce(str(nonce_d_public))
        self.data_manager.remove_nonce(str(nonce_e_public))

        result['status'] = 'SUCCESSFUL'
        return result
