from libp2p.crypto.secp256k1 import Secp256k1PublicKey
from libp2p.peer.id import ID as PeerID
from libp2p.host.host_interface import IHost
from typing import List, Dict

from .abstract import NodesInfo
from .libp2p_base import Libp2pBase, PROTOCOLS_ID, RequestObject

import trio
import logging
import json
import uuid


class Dkg(Libp2pBase):
    def __init__(self, address: Dict[str, str], secret: str, nodes_info: NodesInfo,
                 max_workers: int = 0, default_timeout: int = 200, host:  IHost = None) -> None:

        super().__init__(address, secret, host)

        self.nodes_info: NodesInfo = nodes_info
        if max_workers != 0:
            self.semaphore = trio.Semaphore(max_workers)
        else:
            self.semaphore = None
        self.default_timeout = default_timeout

    def __gather_round2_data(self, peer_id: str, data: Dict) -> List:
        round2_data = []
        for _, round_data in data.items():
            for entry in round_data['broadcast']:
                if entry['receiver_id'] == peer_id:
                    round2_data.append(entry)
        return round2_data

    async def request_dkg(self, threshold: int, party: Dict) -> Dict:
        logging.info(
            f'Requesting DKG with threshold: {threshold}, party: {party}')
        dkg_id = str(uuid.uuid4())

        if len(party) < threshold:
            response = {
                'result': 'FAILED',
                'dkg_id': None,
                'response': {}
            }
            logging.error(
                f'DKG id {dkg_id} has FAILED due to insufficient number of available nodes')
            return response

        call_method = 'round1'

        parameters = {
            'party': party,
            'dkg_id': dkg_id,
            'threshold': threshold,
        }
        request_object = RequestObject(dkg_id, call_method, parameters)
        round1_response = {}
        async with trio.open_nursery() as nursery:
            for node_id, peer_id in party.items():
                destination_address = self.nodes_info.lookup_node(peer_id, node_id)[
                    0]
                nursery.start_soon(self.send, destination_address, peer_id,
                                   PROTOCOLS_ID[call_method], request_object.get(), round1_response, self.default_timeout, self.semaphore)

        logging.debug(
            f'Round1 dictionary response: \n{json.dumps(round1_response, indent=4)}')
        for response in round1_response.values():
            if response['status'] == 'SUCCESSFUL':
                continue
            response = {
                'result': 'FAILED',
                'dkg_id': dkg_id,
                'call_method': call_method,
                'response': round1_response
            }
            logging.info(f'DKG request result: {response}')
            return response

        # TODO: error handling (if verification failed)
        for node_id, data in round1_response.items():
            data_bytes = json.dumps(data['broadcast']).encode('utf-8')
            validation = bytes.fromhex(data['validation'])
            peer_info = self.nodes_info.lookup_node(node_id)[0]
            public_key_bytes = bytes.fromhex(
                peer_info['public_key'])

            public_key = Secp256k1PublicKey.deserialize(public_key_bytes)
            logging.debug(
                f'Verification of sent data from {node_id}: {public_key.verify(data_bytes, validation)}')

        call_method = 'round2'
        parameters = {
            'dkg_id': dkg_id,
            'broadcasted_data': round1_response
        }
        request_object = RequestObject(dkg_id, call_method, parameters)

        round2_response = {}
        async with trio.open_nursery() as nursery:
            for node_id, peer_id in party.items():
                destination_address = self.nodes_info.lookup_node(peer_id, node_id)[
                    0]
                nursery.start_soon(self.send, destination_address, peer_id,
                                   PROTOCOLS_ID[call_method], request_object.get(), round2_response, self.default_timeout, self.semaphore)

        logging.debug(
            f'Round2 dictionary response: \n{json.dumps(round2_response,indent=4)}')

        for response in round2_response.values():
            if response['status'] == 'SUCCESSFUL':
                continue
            response = {
                'result': 'FAILED',
                'dkg_id': dkg_id,
                'call_method': call_method,
                'response': round2_response,
            }
            logging.info(f'DKG request result: {response}')
            return response

        call_method = 'round3'

        round3_response = {}

        async with trio.open_nursery() as nursery:
            for node_id, peer_id in party.items():
                parameters = {
                    'dkg_id': dkg_id,
                    'send_data': self.__gather_round2_data(node_id, round2_response)
                }
                request_object = RequestObject(dkg_id, call_method, parameters)

                destination_address = self.nodes_info.lookup_node(peer_id, node_id)[
                    0]
                nursery.start_soon(self.send, destination_address, peer_id,
                                   PROTOCOLS_ID[call_method], request_object.get(), round3_response, self.default_timeout, self.semaphore)

        logging.debug(
            f'Round3 dictionary response: \n{json.dumps(round3_response, indent=4)}')

        for response in round3_response.values():
            if response['status'] == 'SUCCESSFUL':
                continue
            response = {
                'result': 'FAILED',
                'dkg_id': dkg_id,
                'call_method': call_method,
                'round1_response': round1_response,
                'round2_response': round2_response,
                'response': round3_response
            }
            logging.info(f'DKG request result: {response}')
            return response

        for id1, data1 in round3_response.items():
            for id2, data2 in round3_response.items():
                # TODO: handle this assertion
                assert data1['data']['dkg_public_key'] == data2['data']['dkg_public_key'], \
                    f'The DKG key of node {id1} is not consistance with the DKG key of node {id2}'

        public_key = list(round3_response.values())[
            0]['data']['dkg_public_key']
        public_shares = {}
        validations = {}
        for id, data in round3_response.items():
            public_shares[self.nodes_info.lookup_node(
                id)[1]] = data['data']['public_share']
            validations[self.nodes_info.lookup_node(
                id)[1]] = data['validation']

        response = {
            'dkg_id': dkg_id,
            'public_key': public_key,
            'public_shares': public_shares,
            'party': party,
            'validations': validations,
            'result': 'SUCCESSFUL'
        }
        logging.info(f'DKG response: {response}')
        return response
