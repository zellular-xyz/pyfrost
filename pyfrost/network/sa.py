from typing import List, Dict
from fastecdsa.encoding.sec1 import SEC1Encoder
from fastecdsa import curve
from .abstract import NodesInfo
from .dkg import post_request
import pyfrost
import logging
import json
import uuid
import asyncio
import aiohttp


async def sign_request(url: str, dkg_key: Dict, data: Dict, timeout: int = 10):
    async with aiohttp.ClientSession() as session:
        async with session.post(url, json=data, timeout=timeout) as response:
            try:
                result = await response.json()
                if result["status"] != "SUCCESSFUL":
                    return result
                sign = result["signature_data"]
                msg = result["hash"]
                nonces_dict = data["nonces_dict"]
                aggregated_public_nonce = SEC1Encoder.decode_public_key(
                    bytes.fromhex(
                        hex(sign["aggregated_public_nonce"]).replace("x", "")
                    ),
                    curve.secp256k1,
                )
                signature_data = {
                    "id": sign["id"],
                    "message": msg,
                    "nonces_dict": nonces_dict,
                    "aggregated_public_nonce": aggregated_public_nonce,
                    "public_key_share": sign["public_key"],
                    "single_signature": sign,
                    "group_key": dkg_key["public_key"],
                    "key_type": sign["key_type"],
                }
                res = pyfrost.verify_single_signature(signature_data)
                if not res:
                    result["status"] = "MALICIOUS"
                return result
            except asyncio.TimeoutError:
                return {
                    "status": "TIMEOUT",
                    "error": "Communication timed out",
                }
            except Exception as e:
                logging.error(
                    f"An exception occurred: {type(e).__name__}: {e}", exc_info=True
                )
                return {
                    "status": "ERROR",
                    "error": f"An exception occurred: {type(e).__name__}: {e}",
                }


class SA:
    def __init__(self, nodes_info: NodesInfo, default_timeout: int = 200) -> None:
        self.nodes_info: NodesInfo = nodes_info
        self.default_timeout = default_timeout

    async def request_nonces(self, party: List, number_of_nonces: int = 10):
        call_method = self.nodes_info.prefix + "/v1/generate-nonces"
        request_data = {
            "number_of_nonces": number_of_nonces,
        }
        node_info = [self.nodes_info.lookup_node(node_id) for node_id in party]
        urls = [
            f'http://{node["host"]}:{node["port"]}' + call_method for node in node_info
        ]
        request_tasks = [
            post_request(url, request_data, self.default_timeout) for url in urls
        ]
        responses = await asyncio.gather(*request_tasks)
        nonces_response = dict(zip(party, responses))

        logging.debug(
            f"Nonces dictionary response: \n{json.dumps(nonces_response, indent=4)}"
        )
        return nonces_response

    async def request_signature(
        self, dkg_key: Dict, nonces_dict: Dict, sa_data: Dict, sign_party: List
    ) -> Dict:
        call_method = self.nodes_info.prefix + "/v1/sign"
        if not set(sign_party).issubset(set(dkg_key["party"])):
            response = {"result": "FAILED", "signatures": None}
            return response
        request_id = str(uuid.uuid4())
        request_data = {
            "request_id": request_id,
            "dkg_public_key": dkg_key["public_key"],
            "nonces_dict": nonces_dict,
            "data": sa_data,
        }
        node_info = [self.nodes_info.lookup_node(node_id) for node_id in sign_party]
        urls = [
            f'http://{node["host"]}:{node["port"]}' + call_method for node in node_info
        ]
        request_tasks = [
            sign_request(url, dkg_key, request_data, self.default_timeout)
            for url in urls
        ]
        responses = await asyncio.gather(*request_tasks)
        signatures = dict(zip(sign_party, responses))

        logging.debug(
            f"Signatures dictionary response: \n{json.dumps(signatures, indent=4)}"
        )

        sample_result = []
        signature_data_from_nodes = {}
        signs = []
        aggregated_public_nonces = []
        str_message = None
        key_type = None
        for node_id, data in signatures.items():
            assert data["status"] != "ERROR", f"node_id: {node_id}, data: {data}"
            _hash = data.get("hash")
            _signature_data = data.get("signature_data")
            _aggregated_public_nonce = data.get("signature_data", {}).get(
                "aggregated_public_nonce"
            )
            sample_result.append(data)
            signature_data_from_nodes[node_id] = data.get('data', {})
            if _hash and str_message is None:
                str_message = _hash
            if _signature_data:
                signs.append(_signature_data)
            if _aggregated_public_nonce:
                aggregated_public_nonces.append(_aggregated_public_nonce)
            if key_type:
                assert key_type == _signature_data.get(
                    "key_type"
                ), f"node_id: {node_id}, key type is different: {data}"
            key_type = _signature_data.get("key_type")

        response = {"result": "SUCCESSFUL", "signatures": None}
        if not len(set(aggregated_public_nonces)) == 1:
            # TODO: Ask Mr. Shoara.
            aggregated_public_nonce = pyfrost.aggregate_nonce(str_message, nonces_dict)

            for data in signatures.values():
                if (
                    data["signature_data"]["aggregated_public_nonce"]
                    != aggregated_public_nonce
                ):
                    data["status"] = "MALICIOUS"
                    response["result"] = "FAILED"
        for data in signatures.values():
            if data["status"] == "MALICIOUS":
                response["result"] = "FAILED"
                break

        if response["result"] == "FAILED":
            response = {"result": "FAILED", "signatures": signatures}
            logging.info(f"Signature response: {response}")
            return response

        aggregated_public_nonce = SEC1Encoder.decode_public_key(
            bytes.fromhex(hex(aggregated_public_nonces[0]).replace("x", "")),
            curve.secp256k1,
        )

        aggregated_sign = pyfrost.aggregate_signatures(
            str_message,
            signs,
            aggregated_public_nonce,
            dkg_key["public_key"],
            key_type=key_type,
        )
        if pyfrost.frost.verify_group_signature(aggregated_sign):
            aggregated_sign["message_hash"] = str_message
            aggregated_sign["result"] = "SUCCESSFUL"
            aggregated_sign["request_id"] = request_id
            aggregated_sign["sa_data"] = sa_data
            aggregated_sign["signature_data_from_node"] = signature_data_from_nodes
            logging.info(f'Aggregated sign result: {aggregated_sign["result"]}')
        else:
            aggregated_sign["signature_data"] = sample_result
            aggregated_sign["result"] = "FAILED"
        return aggregated_sign
