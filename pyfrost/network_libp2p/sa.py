from libp2p.host.host_interface import IHost
from libp2p.peer.id import ID as PeerID
from libp2p.typing import TProtocol
from typing import Dict
from .libp2p_base import Libp2pBase, PROTOCOLS_ID, RequestObject
from .abstract import NodesInfo
import pyfrost
import types
import json
import trio
import logging
import uuid


class SA(Libp2pBase):

    def __init__(self, address: Dict[str, str], secret: str, nodes_info: NodesInfo,
                 max_workers: int = 0, default_timeout: int = 50, host: IHost = None) -> None:

        super().__init__(address, secret, host)
        self.nodes_info: NodesInfo = nodes_info
        self.token = ''
        if max_workers != 0:
            self.semaphore = trio.Semaphore(max_workers)
        else:
            self.semaphore = None
        self.default_timeout = default_timeout

    async def request_nonces(self, party: Dict, number_of_nonces: int = 10):
        call_method = 'generate_nonces'
        req_id = str(uuid.uuid4())
        parameters = {
            'number_of_nonces': number_of_nonces,
        }
        request_object = RequestObject(req_id, call_method, parameters)
        nonces_response = {}
        async with trio.open_nursery() as nursery:
            for node_id, peer_id in party.items():
                destination_address = self.nodes_info.lookup_node(peer_id, node_id)[
                    0]
                nursery.start_soon(self.send, destination_address, peer_id,
                                   PROTOCOLS_ID[call_method], request_object.get(), nonces_response, self.default_timeout, self.semaphore)
        logging.debug(
            f'Nonces dictionary response: \n{json.dumps(nonces_response, indent=4)}')
        return nonces_response

    async def request_signature(self, dkg_key: Dict, nonces_dict: Dict,
                                sa_data: Dict, sign_party: Dict) -> Dict:
        call_method = 'sign'
        dkg_public_key = dkg_key['public_key']
        request_id = str(uuid.uuid4())
        if not set(sign_party).issubset(set(dkg_key['party'])):
            response = {
                'result': 'FAILED',
                'signatures': None
            }
            return response

        parameters = {
            'dkg_public_key': dkg_public_key,
            'nonces_dict': nonces_dict,
        }
        request_object = RequestObject(
            request_id, call_method, parameters, sa_data)

        signatures = {}
        async with trio.open_nursery() as nursery:
            for peer_id in sign_party.values():
                destination_address = self.nodes_info.lookup_node(peer_id)[0]
                nursery.start_soon(Wrappers.sign, self.send, dkg_key, destination_address, peer_id,
                                   PROTOCOLS_ID[call_method], request_object.get(), signatures, self.default_timeout, self.semaphore)
        logging.debug(
            f'Signatures dictionary response: \n{json.dumps(signatures, indent=4)}')
        sample_result = []
        signs = []
        aggregated_public_nonces = []
        str_message = None
        for data in signatures.values():
            _hash = data.get('hash')
            _signature_data = data.get('signature_data')
            _aggregated_public_nonce = data.get(
                'signature_data', {}).get('aggregated_public_nonce')
            if _hash and str_message is None:
                str_message = _hash
                sample_result.append(data)
            if _signature_data:
                signs.append(_signature_data)
            if _aggregated_public_nonce:
                aggregated_public_nonces.append(_aggregated_public_nonce)

        response = {
            'result': 'SUCCESSFUL',
            'signatures': None
        }
        if not len(set(aggregated_public_nonces)) == 1:
            aggregated_public_nonce = pyfrost.aggregate_nonce(
                str_message, nonces_dict)
            aggregated_public_nonce = pyfrost.frost.pub_to_code(
                aggregated_public_nonce)
            for peer_id, data in signatures.items():
                if data['signature_data']['aggregated_public_nonce'] != aggregated_public_nonce:
                    data['status'] = 'MALICIOUS'
                    response['result'] = 'FAILED'
        for data in signatures.values():
            if data['status'] == 'MALICIOUS':
                response['result'] = 'FAILED'
                break

        if response['result'] == 'FAILED':
            response = {
                'result': 'FAILED',
                'signatures': signatures
            }
            logging.info(f'Signature response: {response}')
            return response

        # TODO: Remove pub_to_code
        aggregated_public_nonce = pyfrost.frost.code_to_pub(
            aggregated_public_nonces[0])
        aggregated_sign = pyfrost.aggregate_signatures(
            str_message, signs, aggregated_public_nonce, dkg_key['public_key'])
        if pyfrost.frost.verify_group_signature(aggregated_sign):
            aggregated_sign['message_hash'] = str_message
            aggregated_sign['result'] = 'SUCCESSFUL'
            aggregated_sign['signature_data'] = sample_result
            aggregated_sign['request_id'] = request_object.request_id
            logging.info(
                f'Aggregated sign result: {aggregated_sign["result"]}')
        else:
            aggregated_sign['result'] = 'FAILED'
        return aggregated_sign


class Wrappers:
    @staticmethod
    async def sign(send: types.FunctionType, dkg_key, destination_address: Dict[str, str], destination_peer_id: PeerID, protocol_id: TProtocol,
                   message: Dict, result: Dict = None, timeout: float = 5.0, semaphore: trio.Semaphore = None):

        await send(destination_address, destination_peer_id, protocol_id,
                   message, result, timeout, semaphore)

        if result[destination_peer_id]['status'] != 'SUCCESSFUL':
            return

        sign = result[destination_peer_id]['signature_data']
        msg = result[destination_peer_id]['hash']
        nonces_list = message['parameters']['nonces_dict']
        aggregated_public_nonce = pyfrost.frost.code_to_pub(
            sign['aggregated_public_nonce'])
        res = pyfrost.verify_single_signature(
            sign['id'], msg, nonces_list, aggregated_public_nonce, dkg_key['public_shares'][str(sign['id'])], sign, dkg_key['public_key'])
        if not res:
            result[destination_peer_id]['status'] = 'MALICIOUS'
