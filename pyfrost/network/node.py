from flask import Blueprint, request, jsonify, abort
from functools import wraps
from pyfrost.frost import KeyGen, make_signature_share
from pyfrost import crypto_utils, create_nonces
from typing import Dict
from fastecdsa.encoding.sec1 import SEC1Encoder
from fastecdsa import ecdsa, curve
from .abstract import NodesInfo, DataManager
import json
import logging
import types


def request_handler(func):
	@wraps(func)
	def wrapper(self, *args, **kwargs):
		route_path = request.url_rule.rule if request.url_rule else None
		if not self.caller_validator(request.remote_addr, route_path):
			abort(403)
		try:
			logging.debug(
				f"{request.remote_addr}{route_path} Got message: {request.get_json()}"
			)
			result: Dict = func(self, *args, **kwargs)
			to_sign = json.dumps(result, sort_keys=True).encode("utf-8")
			result["node_signature"] = ecdsa.sign(
				to_sign, self.private, curve.secp256k1
			)
			logging.debug(
				f"{request.remote_addr}{route_path} Sent message: {json.dumps(result, indent=4)}"
			)
			return jsonify(result), 200
		except Exception as e:
			logging.error(
				f"Flask round1 handler => Exception occurred: {type(e).__name__}: {e}",
				exc_info=True,  # This will include the stack trace in the log
			)
			return jsonify(
				{"error": f"{type(e).__name__}: {e}", "status": "ERROR"}
			), 500

	return wrapper


class Node:
	def __init__(
		self,
		data_manager: DataManager,
		node_id: int,
		private: int,
		nodes_info: NodesInfo,
		caller_validator: types.FunctionType,
		data_validator: types.FunctionType,
	) -> None:
		self.blueprint = Blueprint("pyfrost", __name__)
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
		self.blueprint.route("/v1/dkg/round1", methods=["POST"])(self.round1)
		self.blueprint.route("/v1/dkg/round2", methods=["POST"])(self.round2)
		self.blueprint.route("/v1/dkg/round3", methods=["POST"])(self.round3)
		self.blueprint.route("/v1/sign", methods=["POST"])(self.sign)
		self.blueprint.route("/v1/generate-nonces", methods=["POST"])(
			self.generate_nonces
		)

	@request_handler
	def round1(self):
		data = request.get_json()
		party = data["party"]
		dkg_id = data["dkg_id"]
		threshold = data["threshold"]
		key_type = data["key_type"]
		assert (
			self.node_id in party
		), f"This node is not amoung specified party for app {dkg_id}"
		assert threshold <= len(party), f"Threshold must be <= n for Dkg {dkg_id}"
		
		party_pub_keys = dict(zip(
			party,
			[self.nodes_info.lookup_node(id)["public_key"] for id in party],
		));
		self.key_gens[dkg_id] = KeyGen(
			dkg_id, threshold, self.node_id, self.private, party, party_pub_keys, key_type=key_type
		)
		round1_broadcast_data = self.key_gens[dkg_id].round1()

		broadcast_bytes = json.dumps(round1_broadcast_data, sort_keys=True).encode(
			"utf-8"
		)
		result = {
			"broadcast": round1_broadcast_data,
			"validation": ecdsa.sign(broadcast_bytes, self.private, curve.secp256k1),
			"status": "SUCCESSFUL",
		}
		return result

	@request_handler
	def round2(self):
		data = request.get_json()
		dkg_id = data["dkg_id"]
		whole_broadcasted_data: Dict = data.get("broadcasted_data")
		broadcasted_data = {}
		for node_id, data in whole_broadcasted_data.items():
			if node_id == self.node_id:
				continue;
			# TODO: error handling (if verification failed)
			data_bytes = json.dumps(data['broadcast']).encode("utf-8")
			validation = data["validation"]
			public_key_code = self.nodes_info.lookup_node(self.node_id)["public_key"]
			public_key = SEC1Encoder.decode_public_key(
				bytes.fromhex(hex(public_key_code).replace("x", "")), curve.secp256k1
			)
			verify_result = ecdsa.verify(
				validation, data_bytes, public_key, curve=curve.secp256k1
			)
			logging.debug(f"Verification of sent data from {node_id}: {verify_result}")
			
			broadcasted_data[node_id] = data["broadcast"]
		round2_data = self.key_gens[dkg_id].round2(broadcasted_data)
		result = {
			"send_to": round2_data,
			"status": "SUCCESSFUL",
		}
		return result

	@request_handler
	def round3(self):
		data = request.get_json()
		dkg_id = data["dkg_id"]
		send_data = data["send_data"]

		# decrypt send_data
		for sender, data in send_data.items():
			dec = crypto_utils.decrypt_with_joint_key(
				data, 
				self.private, 
				self.nodes_info.lookup_node(sender)["public_key"]
			)
			send_data[sender] = json.loads(dec)

		round3_data = self.key_gens[dkg_id].round3(send_data)
		key_type = self.key_gens[dkg_id].key_type
		if round3_data["status"] == "COMPLAINT":
			if dkg_id in self.key_gens:
				del self.key_gens[dkg_id]

		round3_data["validation"] = None
		if round3_data["status"] == "SUCCESSFUL":
			sign_data = json.dumps(round3_data["pubkey_package"]).encode("utf-8")
			round3_data["validation"] = ecdsa.sign(
				sign_data, self.private, curve.secp256k1
			)
			self.data_manager.set_key(
				round3_data["pubkey_package"]["verifying_key"],
				{
					"key_type": key_type,
					"key_package": round3_data["key_package"],
					"pubkey_package": round3_data["pubkey_package"],
				}
			)

		result = {
			"pubkey_package": round3_data["pubkey_package"],
			"validation": round3_data["validation"],
			"status": round3_data["status"],
		}
		return result

	@request_handler
	def sign(self):
		data = request.get_json()
		
		dkg_public_key = data["dkg_public_key"]
		nonces_dict = data["nonces_dict"]
		sa_data = data["data"]
		request_id = data["request_id"]
		result = self.data_validator(sa_data)
		key_pair = self.data_manager.get_key(str(dkg_public_key))
		nonce_key = nonces_dict[self.node_id]["hiding"]
		nonce = self.data_manager.get_nonce(nonce_key)

		result["signature_data"] = make_signature_share(
			key_pair["key_type"],
			result["hash"],
			nonces_dict,
			nonce,
			key_pair["key_package"]
		);
		self.data_manager.remove_nonce(str(nonce_key))

		result["status"] = "SUCCESSFUL"
		result["request_id"] = request_id
		return result

	@request_handler
	def generate_nonces(self):
		data = request.get_json()
		dkg_pub_key = data["dkg_pub_key"]
		number_of_nonces = data["number_of_nonces"]

		key_data = self.data_manager.get_key(dkg_pub_key);

		nonces, commitments = create_nonces(
			key_data["key_type"], 
			key_data["key_package"]["signing_share"], 
			number_of_nonces
		)
		for nonce in nonces:
			self.data_manager.set_nonce(nonce["commitments"]["hiding"], nonce)

		result = {
			"commitments": commitments,
			"status": "SUCCESSFUL",
		}
		return result
