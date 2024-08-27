import json
import sys

from bitcoinutils.keys import PublicKey
from bitcoinutils.setup import setup
from bitcoinutils.transactions import TxWitnessInput
from bitcoinutils.utils import to_satoshis
from flask import Flask, request, jsonify
from web3 import Web3

from pyfrost.btc_transaction_utils import (
    get_taproot_address,
    broadcast_tx,
    get_utxos,
    get_withdraw_tx,
    get_simple_withdraw_tx,
    get_deposit,
    get_burned,
)
from pyfrost.crypto_utils import bytes_from_int
from pyfrost.network.sa import SA
from abstracts import NodesInfo
import logging
import os
import asyncio

from pyfrost.zbtc.config import FEE_AMOUNT, BTC_NETWORK, ZBTC_ADDRESS

setup(BTC_NETWORK)

app = Flask(__name__)
rpc_url = "https://ethereum-holesky-rpc.publicnode.com"
web3 = Web3(Web3.HTTPProvider(rpc_url))

mpc_dkg_key = None
eth_dkg_key = None
mpc_address = None
mpc_public_key = None
eth_public_key = None
nonces = {}


async def initialization(total_node_number: int) -> None:
    global mpc_dkg_key
    global eth_dkg_key
    global mpc_address
    global mpc_public_key
    global eth_public_key
    global nonces

    nodes_info = NodesInfo()
    all_nodes = nodes_info.get_all_nodes(total_node_number)
    sa = SA(nodes_info, default_timeout=50)
    nonces = {}
    nonces_response = await sa.request_nonces(all_nodes)
    for node_id in all_nodes:
        nonces.setdefault(node_id, [])
        nonces[node_id] += nonces_response[node_id]["data"]

    # Retrieving DKGs:
    dkg_file_path = "pyfrost/zbtc/dkgs.json"
    with open(dkg_file_path, "r") as file:
        data = json.load(file)

    mpc_dkg_key = data["mpc_wallet"]
    eth_dkg_key = data["ethereum"]
    logging.info(f'The MPC Wallet DKG is loaded: DKG is {mpc_dkg_key["result"]}')
    logging.info(f'The Ethereum DKG is loaded: DKG is {eth_dkg_key["result"]}')

    mpc_public_key = mpc_dkg_key["public_key"]
    mpc_address = get_taproot_address(mpc_public_key).to_string()
    eth_public_key = eth_dkg_key["public_key"]
    logging.info(f"MPC Wallet: {mpc_address}")
    logging.info(f"Ethereum Public Key: {eth_public_key}")


@app.route("/mint", methods=["POST"])
def mint():
    try:
        # Extracting fee and tx_hash and public_key_hex from the request body
        data = request.json
        tx_hash = data["tx_hash"]
        public_key_hex = data["public_key_hex"]
        logging.info(f"Minting for {public_key_hex} with hash {tx_hash}")

        nodes_info = NodesInfo()
        sa = SA(nodes_info, default_timeout=50)

        dkg_party = eth_dkg_key["party"]
        nonces_dict = {}
        for node_id in dkg_party:
            nonce = nonces[node_id].pop()
            nonces_dict[node_id] = nonce

        deposit = get_deposit(tx_hash, public_key_hex)
        msg = Web3.solidity_keccak(
            ["uint256", "uint256", "address"],
            [
                int(deposit["tx"], 16),
                deposit["amount"],
                Web3.to_checksum_address(deposit["eth_address"]),
            ],
        )

        data = {
            "method": "mint",
            "data": {"tx_hash": tx_hash, "public_key_hex": public_key_hex, "hash": msg},
        }

        sig = asyncio.run(
            sa.request_signature(eth_dkg_key, nonces_dict, data, dkg_party)
        )
        logging.info(f"Minting siganture is: {sig}")
        return jsonify(sig)
    except Exception as e:
        logging.error(f"Error in burn process: {str(e)}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/send", methods=["POST"])
def send():
    try:
        # Extracting fee and tx_hash from the request body
        data = request.json
        to_address = data["to"]
        logging.info(f"Sending to {to_address}")

        nodes_info = NodesInfo()
        sa = SA(nodes_info, default_timeout=50)

        dkg_party = mpc_dkg_key["party"]
        nonces_dict = {}
        for node_id in dkg_party:
            nonce = nonces[node_id].pop()
            nonces_dict[node_id] = nonce

        send_amount = to_satoshis(0.00000001)

        utxos = get_utxos(mpc_address, FEE_AMOUNT + send_amount)
        logging.debug(f"UTxOs {utxos}")

        tx, tx_digests = get_simple_withdraw_tx(
            mpc_address, utxos, to_address, send_amount, FEE_AMOUNT
        )

        for tx_digest in tx_digests:
            data = {
                "method": "get_simple_withdraw_tx",
                "data": {
                    "from": mpc_address,
                    "fee": FEE_AMOUNT,
                    "send_amount": send_amount,
                    "to": to_address,
                    "hash": tx_digest.hex(),
                },
            }
            group_sign = asyncio.run(
                sa.request_signature(mpc_dkg_key, nonces_dict, data, dkg_party)
            )
            sig = bytes_from_int(
                int(group_sign["public_nonce"]["x"], 16)
            ) + bytes_from_int(group_sign["signature"])
            tx.witnesses.append(TxWitnessInput([sig.hex()]))

        logging.info(f"tx witnesses: {tx.witnesses}")

        raw_tx = tx.serialize()
        logging.info(f"Raw tx: {raw_tx}")
        response = broadcast_tx(raw_tx)
        logging.info(f"Transaction Info: {json.dumps(response.json(), indent=4)}")
        return jsonify(response.json())
    except Exception as e:
        logging.error(f"Error in burn process: {str(e)}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/burn", methods=["POST"])
def burn():
    try:
        # Extracting fee and tx_hash from the request body
        data = request.json
        tx_hash = data["tx_hash"]
        logging.info(f"Burning for hash {tx_hash}")

        nodes_info = NodesInfo()
        sa = SA(nodes_info, default_timeout=50)

        dkg_party = mpc_dkg_key["party"]
        nonces_dict = {}
        for node_id in dkg_party:
            nonce = nonces[node_id].pop()
            nonces_dict[node_id] = nonce

        burned = get_burned(tx_hash, web3, ZBTC_ADDRESS)
        logging.debug(f"Burn Info: {burned}")
        send_amount = burned["amount"]
        single_spend_txid = burned["singleSpendTx"]
        single_spend_vout = 0
        to_address = burned["bitcoinAddress"]
        to_address = PublicKey(to_address)
        to_address = to_address.get_segwit_address().to_string()

        utxos = get_utxos(mpc_address, FEE_AMOUNT + send_amount)
        logging.debug(f"UTxOs {utxos}")

        tx, tx_digests = get_withdraw_tx(
            mpc_address,
            utxos,
            to_address,
            send_amount,
            FEE_AMOUNT,
            single_spend_txid,
            single_spend_vout,
        )

        for tx_digest in tx_digests:
            data = {
                "method": "get_withdraw_tx",
                "data": {
                    "burn_tx_hash": tx_hash,
                    "hash": tx_digest.hex(),
                },
            }
            group_sign = asyncio.run(
                sa.request_signature(mpc_dkg_key, nonces_dict, data, dkg_party)
            )
            sig = bytes_from_int(
                int(group_sign["public_nonce"]["x"], 16)
            ) + bytes_from_int(group_sign["signature"])
            tx.witnesses.append(TxWitnessInput([sig.hex()]))

        logging.info(f"tx witnesses: {tx.witnesses}")

        # raw_tx = tx.serialize()
        # resp = broadcast_tx(raw_tx)
        # logging.info(f"Transaction Info: {json.dumps(resp.json(), indent=4)}")
        # return jsonify(resp.json())
        return jsonify({"status": "ok"})
    except Exception as e:
        logging.error(f"Error in burn process: {str(e)}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == "__main__":
    # Initialize logging
    file_path = "logs"
    file_name = "test.log"
    log_formatter = logging.Formatter(
        "%(asctime)s - %(message)s",
    )
    root_logger = logging.getLogger()
    if not os.path.exists(file_path):
        os.mkdir(file_path)
    with open(f"{file_path}/{file_name}", "w"):
        pass
    file_handler = logging.FileHandler(f"{file_path}/{file_name}")
    file_handler.setFormatter(log_formatter)
    root_logger.addHandler(file_handler)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_formatter)
    root_logger.addHandler(console_handler)
    root_logger.setLevel(logging.DEBUG)

    sys.set_int_max_str_digits(0)
    total_node_number = int(sys.argv[1])
    asyncio.run(initialization(total_node_number))
    logging.info("Initialization has been completed.")
    app.run(host="0.0.0.0", port=8000, debug=True)
