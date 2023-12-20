import json
from libp2p_base import Libp2pBase, PROTOCOLS_ID, RequestObject
import pyfrost
from .abstract import NodeInfo

from libp2p.host.host_interface import IHost
from libp2p.peer.id import ID as PeerID
from libp2p.typing import TProtocol
from typing import List, Dict

import types
import pprint
import trio
import logging
import uuid


class SA(Libp2pBase):

    def __init__(self, address: Dict[str, str], secret: str, node_info: NodeInfo,
                 max_workers: int = 0, default_timeout: int = 50, host: IHost = None) -> None:

        super().__init__(address, secret, host)
        self.node_info: NodeInfo = node_info
        self.token = ''
        if max_workers != 0:
            self.semaphore = trio.Semaphore(max_workers)
        else:
            self.semaphore = None
        self.default_timeout = default_timeout

    async def request_nonces(self, party: List, number_of_nonces: int = 10):
        nonces = {}
        for peer_id in party:
            req_id = str(uuid.uuid4())
            call_method = 'generate_nonces'
            parameters = {
                'number_of_nonces': number_of_nonces,
            }
            request_object = RequestObject(req_id, call_method, parameters)

            destination_address = self.node_info.lookup_node(peer_id)
            await self.send(destination_address, peer_id,
                            PROTOCOLS_ID[call_method], request_object.get(), nonces, self.default_timeout, self.semaphore)

            logging.debug(
                f'Nonces dictionary response: \n{pprint.pformat(nonces)}')
        return nonces

    async def request_signature(self, dkg_key: Dict, commitments_dict: Dict,
                                input_data: Dict, sign_party: List) -> Dict:
        call_method = 'sign'
        dkg_id = dkg_key['dkg_id']
        if not set(sign_party).issubset(set(dkg_key['party'])):
            response = {
                'result': 'FAILED',
                'signatures': None
            }
            return response

        parameters = {
            'dkg_id': dkg_id,
            'commitments_list': commitments_dict,
        }
        request_object = RequestObject(
            dkg_id, call_method, parameters, input_data)

        signatures = {}
        async with trio.open_nursery() as nursery:
            for peer_id in sign_party:
                destination_address = self.node_info.lookup_node(peer_id)
                nursery.start_soon(Wrappers.sign, self.send, dkg_key, destination_address, peer_id,
                                   PROTOCOLS_ID[call_method], request_object.get(), signatures, self.default_timeout, self.semaphore)
        logging.debug(
            f'Signatures dictionary response: \n{pprint.pformat(signatures)}')
        str_message = [i['hash'] for i in signatures.values()][0]
        signs = [i['signature_data'] for i in signatures.values()]
        aggregated_public_nonces = [
            i['signature_data']['aggregated_public_nonce'] for i in signatures.values()]
        response = {
            'result': 'SUCCESSFUL',
            'signatures': None
        }
        if not len(set(aggregated_public_nonces)) == 1:
            aggregated_public_nonce = pyfrost.aggregate_nonce(
                str_message, commitments_dict, dkg_key['public_key'])
            aggregated_public_nonce = pyfrost.Utils.pub_to_code(
                aggregated_public_nonce)
            for peer_id, data in signatures.items():
                if data['signature_data']['aggregated_public_nonce'] != aggregated_public_nonce:
                    data['status'] = 'MALICIOUS'
                    response['result'] = 'FAILED'
        # TODO: result must be FAILED if any malicious status received

        if response['result'] == 'FAILED':
            response = {
                'result': 'FAILED',
                'signatures': signatures
            }
            logging.info(f'Signature response: {response}')
            return response

        aggregated_public_nonce = pyfrost.Utils.code_to_pub(
            aggregated_public_nonces[0])
        aggregated_sign = pyfrost.aggregate_signatures(
            str_message, signs, aggregated_public_nonce, dkg_key['public_key'])
        if pyfrost.verify_group_signature(aggregated_sign):
            aggregated_sign['signatures'] = signatures
            aggregated_sign['result'] = 'SUCCESSFUL'
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
        commitments_dict = message['parameters']['commitments_list']
        aggregated_public_nonce = pyfrost.Utils.code_to_pub(
            sign['aggregated_public_nonce'])
        res = pyfrost.verify_single_signature(
            sign['id'], msg, commitments_dict, aggregated_public_nonce, dkg_key['public_shares'][str(sign['id'])], sign, dkg_key['public_key'])
        if not res:
            result[destination_peer_id]['status'] = 'MALICIOUS'
