from typing import List, Dict, Literal
from fastecdsa import ecdsa, curve
from fastecdsa.encoding.sec1 import SEC1Encoder
from .abstract import NodesInfo
import frost_lib
from ..frost import KeyType
import logging
import json
import uuid
import asyncio
import aiohttp


def get_module(name):
	return getattr(frost_lib, name)

def ids_to_frost(key_type, party):
	module = get_module(key_type);
	return [module.num_to_id(int(id)) for id in party]

async def post_request(url: str, data: Dict, timeout: int = 10):
	async with aiohttp.ClientSession() as session:
		async with session.post(url, json=data, timeout=timeout) as response:
			try:
				return await response.json()
			except asyncio.TimeoutError:
				return {
					"status": "TIMEOUT",
					"error": "Communication timed out",
				}
			except Exception as e:
				return {
					"status": "ERROR",
					"error": f"An exception occurred: {type(e).__name__}: {e}",
				}

class Dkg:
	def __init__(self, nodes_info: NodesInfo, default_timeout: int = 200) -> None:
		self.nodes_info: NodesInfo = nodes_info
		self.default_timeout = default_timeout

	def __gather_round2_data(self, node_id: str, data: Dict) -> List:
		round2_data = []
		for _, round_data in data.items():
			for entry in round_data["send_to"]:
				if entry["receiver_id"] == node_id:
					round2_data.append(entry)
		return round2_data

	async def request_dkg(
		self, threshold: int, party: List, 
		key_type: KeyType = "secp256k1"
	) -> Dict:
		f_module = get_module(key_type)

		logging.info(f"Requesting DKG with threshold: {threshold} and party: {party}")
		dkg_id = str(uuid.uuid4())

		if len(party) < threshold:
			response = {"result": "FAILED", "dkg_id": None, "response": {}}
			logging.error(
				f"DKG id {dkg_id} has FAILED due to insufficient number of available nodes"
			)
			return response
		#===================== Round-1 ==========================
		call_method = self.nodes_info.prefix + "/v1/dkg/round1"
		request_data = {
			"party": party,
			"dkg_id": dkg_id,
			"threshold": threshold,
			"key_type": key_type,
		}

		# TODO: Check the sign verifications.

		node_info = [self.nodes_info.lookup_node(node_id) for node_id in party]
		urls = [
			f'http://{node["host"]}:{node["port"]}' + call_method for node in node_info
		]
		request_tasks = [
			post_request(url, request_data, self.default_timeout) for url in urls
		]
		responses = await asyncio.gather(*request_tasks)
		round1_response = dict(zip(party, responses))

		logging.debug(
			f"Round1 dictionary response: \n{json.dumps(round1_response, indent=4)}"
		)

		for response in round1_response.values():
			if response["status"] == "SUCCESSFUL":
				continue
			response = {
				"result": "FAILED",
				"dkg_id": dkg_id,
				"call_method": call_method,
				"response": round1_response,
			}
			logging.info(f"DKG request result: {response}")
			return response

		# TODO: error handling (if verification failed)
		for node_id, data in round1_response.items():
			data_bytes = json.dumps(data["broadcast"], sort_keys=True).encode("utf-8")
			signature = data["validation"]
			public_key_code = self.nodes_info.lookup_node(node_id)["public_key"]
			public_key = SEC1Encoder.decode_public_key(
				bytes.fromhex(hex(public_key_code).replace("x", "")), curve.secp256k1
			)
			verify_result = ecdsa.verify(
				signature, data_bytes, public_key, curve=curve.secp256k1
			)
			logging.debug(f"Verification of sent data from {node_id}: {verify_result}")

		#===================== Round-2 ==========================
		call_method = self.nodes_info.prefix + "/v1/dkg/round2"
		node_info = [self.nodes_info.lookup_node(node_id) for node_id in party]
		urls = [
			f'http://{node["host"]}:{node["port"]}' + call_method for node in node_info
		]
		request_data = {"dkg_id": dkg_id, "broadcasted_data": round1_response}
		request_tasks = [
			post_request(url, request_data, self.default_timeout) for url in urls
		]
		responses = await asyncio.gather(*request_tasks)
		round2_response = dict(zip(party, responses))

		logging.debug(
			f"Round2 dictionary response: \n{json.dumps(round2_response, indent=4)}"
		)

		for response in round2_response.values():
			if response["status"] == "SUCCESSFUL":
				continue
			response = {
				"result": "FAILED",
				"dkg_id": dkg_id,
				"call_method": call_method,
				"response": round2_response,
			}
			logging.info(f"DKG request result: {json.dumps(response, indent=4)}")
			return response

		#===================== Round-3 ==========================
		call_method = self.nodes_info.prefix + "/v1/dkg/round3"
		request_tasks = []
		for node_id in party:
			node_data = {}
			for sender, r2_data in round2_response.items():
				if sender == node_id:
					continue;
				node_data[sender] = r2_data["send_to"][node_id]
			request_data = {
				"dkg_id": dkg_id,
				"send_data": node_data,
			}
			node_info = self.nodes_info.lookup_node(node_id)
			url = f'http://{node_info["host"]}:{node_info["port"]}' + call_method
			request_tasks.append(post_request(url, request_data, self.default_timeout))
		responses = await asyncio.gather(*request_tasks)
		round3_response = dict(zip(party, responses))

		logging.debug(
			f"Round3 dictionary response: \n{json.dumps(round3_response, indent=4)}"
		)

		for response in round3_response.values():
			if response["status"] == "SUCCESSFUL":
				continue
			response = {
				"result": "FAILED",
				"call_method": call_method,
				"round1_response": round1_response,
				"round2_response": round2_response,
				"response": round3_response,
			}
			logging.info(f"DKG request result: {response}")
			return response

		for id1, data1 in round3_response.items():
			for id2, data2 in round3_response.items():
				# TODO: handle this assertion
				assert (
					data1["pubkey_package"]["verifying_key"] == data2["pubkey_package"]["verifying_key"]
				), f"The DKG key of node {id1} is not consistance with the DKG key of node {id2}"

		pubkey_data = list(round3_response.values())[0]
		public_key = pubkey_data["pubkey_package"]["verifying_key"]
		public_shares = pubkey_data["pubkey_package"]["verifying_shares"]
		validations = {}
		for id, data in round3_response.items():
			validations[id] = data["validation"]

		response = {
			"threshold": threshold,
			"pubkey_data": pubkey_data,
			"public_key": public_key,
			"public_shares": public_shares,
			"party": party,
			"validations": validations,
			"key_type": key_type,
			"result": "SUCCESSFUL",
		}
		logging.info(f"DKG response: {response}")
		return response
