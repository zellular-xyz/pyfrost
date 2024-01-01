from flask import Flask, request, jsonify, abort
from functools import wraps
from pyfrost.frost import Key, KeyGen
from pyfrost.crypto_utils import code_to_pub
from pyfrost import create_nonces
from typing import Dict, List
from fastecdsa import ecdsa, curve, keys
from .abstract import NodeInfo, DataManager
import json
import logging
import types


def caller_authenticator(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        route_path = request.url_rule.rule if request.url_rule else None
        if not self.caller_validator(request.remote_addr, route_path):
            abort(403)
        return func(self, *args, **kwargs)

    return wrapper



class Node:

    def __init__(self, data_manager: DataManager, node_id: int, private: int, node_info: NodeInfo, caller_validator: types.FunctionType,
                 data_validator: types.FunctionType) -> None:

        self.app = Flask(__name__)
        self.node_info: NodeInfo = node_info
        self.private = private
        self.node_id = str(node_id)
        self.key_gens: Dict[str, KeyGen] = {}
        self.caller_validator = caller_validator
        self.data_validator = data_validator
        self.data_manager: DataManager = data_manager
        self.app.route('/v1/dkg/round1', methods=['POST'])(self.round1_handler)
        self.app.route('/v1/dkg/round2', methods=['POST'])(self.round2_handler)
        self.app.route('/v1/dkg/round3', methods=['POST'])(self.round3_handler)
        self.app.route('/v1/sign', methods=['POST'])(self.sign_handler)
        self.app.route('/v1/generate-nonces',
                       methods=['POST'])(self.generate_nonces_handler)

    def run_app(self):
        port = self.node_info.lookup_node(self.node_id)['http'].split(':')[-1]
        self.app.run(port = int(port), debug = True, use_reloader = False)


    def add_new_key(self, dkg_id: str, threshold, party: List) -> None:
        assert self.node_id in party, f'This node is not amoung specified party for app {dkg_id}'
        assert threshold <= len(
            party), f'Threshold must be <= n for Dkg {dkg_id}'

        partners = [node_id for node_id in party if self.node_id != node_id]
        self.key_gens[dkg_id] = KeyGen(
            dkg_id, threshold, len(party), self.node_id, partners)

    def remove_key(self, dkg_id: str) -> None:
        if self.key_gens.get(dkg_id) is not None:
            del self.key_gens[dkg_id]
            # TODO: Maybe remove from database.

    @caller_authenticator
    def round1_handler(self):
        try:
            data = request.get_json()
            party = data.get('party')
            dkg_id = data.get('dkg_id')
            threshold = data.get('threshold')

            if None in [data, party, dkg_id, threshold]:
                return jsonify({'error': 'Invalid request format', 'status': 'ERROR'}), 403

            route_path = request.url_rule.rule if request.url_rule else None

            logging.debug(
                f'{request.remote_addr}{route_path} Got message: {data}')

            self.add_new_key(
                dkg_id,
                threshold,
                party,
            )

            round1_broadcast_data = self.key_gens[dkg_id].round1()
            broadcast_bytes = json.dumps(
                round1_broadcast_data, sort_keys=True).encode('utf-8')
            result = {
                'broadcast': round1_broadcast_data,
                'validation': ecdsa.sign(broadcast_bytes, self.private, curve.secp256k1),
                'status': 'SUCCESSFUL'
            }
            logging.debug(
                f'{request.remote_addr}{route_path} Sent message: {json.dumps(result, indent=4)}')
            return jsonify(result)

        except Exception as e:
            logging.error(
                f'Flask round1 handler => Exception occurred: {type(e).__name__}: {e}')
            return jsonify({'error': f'{type(e).__name__}: {e}', 'status': 'ERROR'}), 500

    @caller_authenticator
    def round2_handler(self):
        try:
            data = request.get_json()
            dkg_id = data.get('dkg_id')
            whole_broadcasted_data: Dict = data.get('broadcasted_data')
            validation = data.get('validation')

            if None in [data, whole_broadcasted_data, dkg_id]:
                return jsonify({'error': 'Invalid request format', 'status': 'ERROR'}), 403

            route_path = request.url_rule.rule if request.url_rule else None
            logging.debug(
                f'{request.remote_addr}{route_path} Got message: {json.dumps(data, indent=4)}')

            broadcasted_data = []
            for node_id, data in whole_broadcasted_data.items():
                # TODO: error handling (if verification failed)
                data_bytes = json.dumps(data['broadcast']).encode('utf-8')
                validation = data['validation']
                public_key = self.node_info.lookup_node(self.node_id)[
                    'public_key']
                verify_result = ecdsa.verify(
                    validation, data_bytes, code_to_pub(public_key), curve=curve.secp256k1)
                logging.debug(
                    f'Verification of sent data from {node_id}: {verify_result}')
                broadcasted_data.append(data['broadcast'])

            round2_broadcast_data = self.key_gens[dkg_id].round2(
                broadcasted_data)
            result = {
                'broadcast': round2_broadcast_data,
                'status': 'SUCCESSFUL',
            }
            logging.debug(
                f'{request.remote_addr}{route_path} Sent message: {json.dumps(result, indent=4)}')
            return jsonify(result)
        except Exception as e:
            logging.error(
                f'Flask round2 handler => Exception occurred: {type(e).__name__}: {e}')
            return jsonify({'error': f'{type(e).__name__}: {e}', 'status': 'ERROR'}), 500

    @caller_authenticator
    def round3_handler(self):
        try:
            data = request.get_json()
            dkg_id = data.get('dkg_id')
            send_data = data.get('send_data')

            if None in [data, send_data, dkg_id]:
                return jsonify({'error': 'Invalid request format', 'status': 'ERROR'}), 403

            route_path = request.url_rule.rule if request.url_rule else None
            logging.debug(
                f'{request.remote_addr}{route_path} Got message: {json.dumps(data, indent=4)}')

            round3_data = self.key_gens[dkg_id].round3(send_data)
            if round3_data['status'] == 'COMPLAINT':
                self.remove_key(dkg_id)

            round3_data['validation'] = None
            if round3_data['status'] == 'SUCCESSFUL':
                sign_data = json.dumps(round3_data['data']).encode('utf-8')
                round3_data['validation'] = ecdsa.sign(
                    sign_data, self.private, curve.secp256k1)

                self.data_manager.set_key(
                    dkg_id, round3_data['dkg_key_pair'])

            result = {
                'data': round3_data['data'],
                'status': round3_data['status'],
                'validation': round3_data['validation']
            }
            logging.debug(
                f'{request.remote_addr}{route_path} Sent message: {json.dumps(result, indent=4)}')
            return jsonify(result)
        except Exception as e:
            logging.error(
                f'Flask round3 handler => Exception occurred: {type(e).__name__}: {e}')
            return jsonify({'error': f'{type(e).__name__}: {e}', 'status': 'ERROR'}), 500

    @caller_authenticator
    def sign_handler(self):
        try:
            data = request.get_json()
            dkg_id = data['dkg_id']
            nonces_list = data['nonces_list']
            sa_data = data['data']

            if None in [data, nonces_list, dkg_id, sa_data]:
                return jsonify({'error': 'Invalid request format', 'status': 'ERROR'}), 403

            route_path = request.url_rule.rule if request.url_rule else None
            logging.debug(
                f'{request.remote_addr}{route_path} Got message: {json.dumps(data, indent=4)}')

            result = {}
            try:
                result = self.data_validator(sa_data)
                key_pair = self.data_manager.get_key(dkg_id)
                key = Key(key_pair, self.node_id)
                nonces = self.data_manager.get_nonces()
                result['signature_data'], remove_data = key.sign(
                    nonces_list, result['hash'], nonces)
                try:
                    nonces.remove(remove_data)
                except Exception as e:
                    logging.error(
                        f'Flask sign handler => Nonces dont\'t exist to remove: {remove_data}')
                self.data_manager.set_nonces(nonces)
                result['status'] = 'SUCCESSFUL'
            except Exception as e:
                logging.error(
                    f'Flask sign handler => Exception occurred: {type(e).__name__}: {e}')
                result = {
                    'status': 'FAILED'
                }
            logging.debug(
                f'{request.remote_addr}{route_path} Sent message: {json.dumps(result, indent=4)}')
            return jsonify(result)
        except Exception as e:
            logging.error(
                f'Flask sign handler => Exception occurred: {type(e).__name__}: {e}')
            return jsonify({'error': f'{type(e).__name__}: {e}', 'status': 'ERROR'}), 500

    @caller_authenticator
    def generate_nonces_handler(self):
        try:
            data = request.get_json()
            number_of_nonces = data['number_of_nonces']

            if None in [data, number_of_nonces]:
                return jsonify({'error': 'Invalid request format', 'status': 'ERROR'}), 403

            route_path = request.url_rule.rule if request.url_rule else None
            logging.debug(
                f'{request.remote_addr}{route_path} Got message: {json.dumps(data, indent=4)}')

            nonces, save_data = create_nonces(
                int(self.node_id), number_of_nonces)
            self.data_manager.set_nonces(save_data)
            result = {
                'nonces': nonces,
                'status': 'SUCCESSFUL',
            }
            logging.debug(
                f'{request.remote_addr}{route_path} Sent message: {json.dumps(result, indent=4)}')
            return jsonify(result)

        except Exception as e:
            logging.error(
                f'Flask generate nonces handler => Exception occurred: {type(e).__name__}: {e}')
            return jsonify({'error': f'{type(e).__name__}: {e}', 'status': 'ERROR'}), 500
    
    
