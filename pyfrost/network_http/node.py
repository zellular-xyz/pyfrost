from flask import Flask, request, jsonify, abort
from functools import wraps
from pyfrost.frost import Key, KeyGen
from pyfrost.crypto_utils import code_to_pub
from pyfrost import create_nonces
from typing import Dict, List
from fastecdsa import ecdsa, curve, keys
from .abstract import NodesInfo, DataManager
import json
import logging
import types

# TODO: how to simplify this


def handler_decorator(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        route_path = request.url_rule.rule if request.url_rule else None
        if not self.caller_validator(request.remote_addr, route_path):
            abort(403)
        try:
            logging.debug(
                f'{request.remote_addr}{route_path} Got message: {request.get_json()}')
            result: Dict = func(self, *args, **kwargs)
            to_sign = json.dumps(result, sort_keys=True).encode('utf-8')
            result['signature'] = ecdsa.sign(
                to_sign, self.private, curve.secp256k1)
            logging.debug(
                f'{request.remote_addr}{route_path} Sent message: {json.dumps(result, indent=4)}')
            return jsonify(result), 200
        except Exception as e:
            logging.error(
                f'Flask round1 handler => Exception occurred: {type(e).__name__}: {e}')
            return jsonify({'error': f'{type(e).__name__}: {e}', 'status': 'ERROR'}), 500
    return wrapper


class Node:

    def __init__(self, data_manager: DataManager, node_id: int, private: int, nodes_info: NodesInfo, caller_validator: types.FunctionType,
                 data_validator: types.FunctionType) -> None:

        self.app = Flask(__name__)
        self.private = private
        self.node_id = str(node_id)
        self.key_gens: Dict[str, KeyGen] = {}

        # TODO: Check validator functions if it cannot get as input. and just use in decorator.
        # Abstracts:
        self.nodes_info: NodesInfo = nodes_info
        self.caller_validator = caller_validator
        self.data_validator = data_validator
        self.data_manager: DataManager = data_manager

        # Adding routes:
        self.app.route('/v1/dkg/round1', methods=['POST'])(self.round1_handler)
        self.app.route('/v1/dkg/round2', methods=['POST'])(self.round2_handler)
        self.app.route('/v1/dkg/round3', methods=['POST'])(self.round3_handler)
        self.app.route('/v1/sign', methods=['POST'])(self.sign_handler)
        self.app.route('/v1/generate-nonces',
                       methods=['POST'])(self.generate_nonces_handler)

    def run_app(self):
        node_info = self.nodes_info.lookup_node(self.node_id)
        self.app.run(host=node_info['host'], port=int(
            node_info['port']), debug=True, use_reloader=False)

    @handler_decorator
    def round1_handler(self):
        data = request.get_json()
        party = data['party']
        dkg_id = data['dkg_id']
        threshold = data['threshold']

        assert self.node_id in party, f'This node is not amoung specified party for app {dkg_id}'
        assert threshold <= len(
            party), f'Threshold must be <= n for Dkg {dkg_id}'
        partners = [
            node_id for node_id in party if self.node_id != node_id]
        self.key_gens[dkg_id] = KeyGen(
            dkg_id, threshold, len(party), self.node_id, partners)

        round1_broadcast_data = self.key_gens[dkg_id].round1()

        broadcast_bytes = json.dumps(
            round1_broadcast_data, sort_keys=True).encode('utf-8')
        result = {
            'broadcast': round1_broadcast_data,
            'validation': ecdsa.sign(broadcast_bytes, self.private, curve.secp256k1),
            'status': 'SUCCESSFUL'
        }
        return result

    @handler_decorator
    def round2_handler(self):
        data = request.get_json()
        dkg_id = data['dkg_id']
        whole_broadcasted_data: Dict = data.get('broadcasted_data')

        broadcasted_data = []
        for node_id, data in whole_broadcasted_data.items():
            # TODO: error handling (if verification failed)
            data_bytes = json.dumps(data['broadcast']).encode('utf-8')
            validation = data['validation']
            public_key = self.nodes_info.lookup_node(self.node_id)[
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
        return result

    @handler_decorator
    def round3_handler(self):
        data = request.get_json()
        dkg_id = data['dkg_id']
        send_data = data['send_data']

        round3_data = self.key_gens[dkg_id].round3(send_data)
        if round3_data['status'] == 'COMPLAINT':
            if dkg_id in self.key_gens:
                del self.key_gens[dkg_id]
                # TODO: Maybe remove from database.

        round3_data['validation'] = None
        if round3_data['status'] == 'SUCCESSFUL':
            sign_data = json.dumps(round3_data['data']).encode('utf-8')
            round3_data['validation'] = ecdsa.sign(
                sign_data, self.private, curve.secp256k1)

            self.data_manager.set_key(
                str(round3_data['dkg_key_pair']['dkg_public_key']), round3_data['dkg_key_pair'])

        result = {
            'data': round3_data['data'],
            'validation': round3_data['validation'],
            'status': round3_data['status']
        }
        return result

    @handler_decorator
    def sign_handler(self):
        data = request.get_json()
        dkg_public_key = data['dkg_public_key']
        nonces_list = data['nonces_list']
        sa_data = data['data']
        request_id = data['request_id']
        result = self.data_validator(sa_data)
        key_pair = self.data_manager.get_key(str(dkg_public_key))
        key = Key(key_pair, self.node_id)
        nonces = self.data_manager.get_nonces()
        result['signature_data'], remove_data = key.sign(
            nonces_list, result['hash'], nonces)
        nonces.remove(remove_data)

        self.data_manager.set_nonces(nonces)

        result['status'] = 'SUCCESSFUL'
        result['request_id'] = request_id
        return result

    @handler_decorator
    def generate_nonces_handler(self):
        data = request.get_json()
        number_of_nonces = data['number_of_nonces']
        nonces, save_data = create_nonces(
            int(self.node_id), number_of_nonces)
        self.data_manager.set_nonces(save_data)
        result = {
            'data': nonces,
            'status': 'SUCCESSFUL',
        }
        return result
