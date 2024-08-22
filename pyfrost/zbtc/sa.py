import json

from bitcoinutils.keys import PublicKey
from bitcoinutils.utils import to_satoshis

from pyfrost.btc_transaction_utils import (
    get_taproot_address,
)
from pyfrost.network.sa import SA
from pyfrost.network.dkg import Dkg
from typing import List
from abstracts import NodesInfo
import logging
import time
import timeit
import sys
import os
import random
import asyncio


# TODO: Merge examples with libp2p.


async def run_sample(
    total_node_number: int, threshold: int, n: int, num_signs: int
) -> None:
    nodes_info = NodesInfo()
    all_nodes = nodes_info.get_all_nodes(total_node_number)
    dkg = Dkg(nodes_info, default_timeout=50)
    sa = SA(nodes_info, default_timeout=50)
    nonces = {}
    nonces_response = await sa.request_nonces(all_nodes)
    for node_id in all_nodes:
        nonces.setdefault(node_id, [])
        nonces[node_id] += nonces_response[node_id]["data"]

    # Random party selection:
    seed = int(time.time())
    random.seed(seed)
    party = random.sample(all_nodes, n)

    # Requesting DKG:
    file_path = "dkg.json"
    now = timeit.default_timer()
    if os.path.exists(file_path):
        with open(file_path, "r") as file:
            dkg_key = json.load(file)
    else:
        dkg_key = await dkg.request_dkg(threshold, party, key_type="BTC")
        with open("pyfrost/zbtc/dkg.json", "w") as file:
            json.dump(dkg_key, file)
    then = timeit.default_timer()

    logging.info(f"Requesting DKG takes: {then - now} seconds.")
    logging.info(f'The DKG result is {dkg_key["result"]}')

    dkg_public_key = dkg_key["public_key"]
    logging.info(f"dkg key: {dkg_key}")

    for i in range(num_signs):
        logging.info(f"Get signature {i} with DKG public key {dkg_public_key}")

        dkg_party: List = dkg_key["party"]
        nonces_dict = {}

        for node_id in dkg_party:
            nonce = nonces[node_id].pop()
            nonces_dict[node_id] = nonce

        from_address = get_taproot_address(dkg_public_key).to_string()
        fee_amount = to_satoshis(0.00000010)
        send_amount = to_satoshis(0.00000020)
        to_address = PublicKey(
            "03ffac5f6f2f5723ee1ed1f42827cc5bef641f8b79cbddf768f031744748739972"
        )
        to_address = to_address.get_segwit_address().to_string()
        logging.info(
            f"Initiate transfer {send_amount} satoshi from {from_address} to {to_address}. fee: {fee_amount} satoshi"
        )

        sa_data = {"data": "hi"}
        # utxos = get_utxos(from_address, fee_amount + send_amount)
        # tx, tx_digest = get_withdraw_tx(
        #     from_address,
        #     utxos,
        #     to_address,
        #     send_amount,
        #     fee_amount,
        #     "f5ba44e5b6f6df3fd4d939184597938935814e7bf7cb75fe8efcf1274a5f70de",
        #     0,
        # )
        # tx_digest = tx_digest.hex()
        now = timeit.default_timer()

        group_sign = await sa.request_signature(
            dkg_key, nonces_dict, sa_data, dkg_key["party"]
        )
        then = timeit.default_timer()

        logging.info(f"Requesting signature {i} takes {then - now} seconds")
        logging.info(f"Signature data: {group_sign}")

        # sig = bytes_from_int(int(group_sign["public_nonce"]["x"], 16)) + bytes_from_int(
        #     group_sign["signature"]
        # )
        # tx.witnesses.append(TxWitnessInput([sig.hex()]))
        # raw_tx = tx.serialize()
        # resp = broadcast_tx(raw_tx)
        # logging.info(f"Transaction Info: {json.dumps(resp.json(), indent=4)}")


if __name__ == "__main__":
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
    dkg_threshold = int(sys.argv[2])
    num_parties = int(sys.argv[3])
    num_signs = int(sys.argv[4])

    try:
        asyncio.run(
            run_sample(total_node_number, dkg_threshold, num_parties, num_signs)
        )
    except KeyboardInterrupt:
        pass
