from pyfrost.network_http.sa import SA
from pyfrost.network_http.dkg import Dkg
from typing import Dict, List
from abstracts import NodesInfo
import logging
import time
import timeit
import sys
import os
import random
import asyncio
# TODO: Merge examples with libp2p.


async def run_sample(total_node_number: int, threshold: int, n: int, num_signs: int) -> None:
    nodes_info = NodesInfo()
    all_nodes = nodes_info.get_all_nodes(total_node_number)
    dkg = Dkg(nodes_info, default_timeout=50)
    sa = SA(nodes_info, default_timeout=50)
    nonces = {}
    nonces_response = await sa.request_nonces(all_nodes)
    for node_id in all_nodes:
        nonces.setdefault(node_id, [])
        nonces[node_id] += nonces_response[node_id]['data']

    # Random party selection:
    seed = int(time.time())
    random.seed(seed)
    party = random.sample(all_nodes, n)

    # Requesting DKG:
    now = timeit.default_timer()
    dkg_key = await dkg.request_dkg(threshold, party)
    then = timeit.default_timer()

    logging.info(f'Requesting DKG takes: {then - now} seconds.')
    logging.info(f'The DKG result is {dkg_key["result"]}')

    dkg_public_key = dkg_key['public_key']
    logging.info(f'dkg key: {dkg_key}')

    for i in range(num_signs):
        logging.info(
            f'Get signature {i} with DKG public key {dkg_public_key}')

        dkg_party: List = dkg_key['party']
        nonces_dict = {}

        for node_id in dkg_party:
            nonce = nonces[node_id].pop()
            nonces_dict[node_id] = nonce

        now = timeit.default_timer()
        sa_data = {
            'data': 'Hi there!'
        }

        signature = await sa.request_signature(dkg_key, nonces_dict, sa_data, dkg_key['party'])
        then = timeit.default_timer()

        logging.info(
            f'Requesting signature {i} takes {then - now} seconds')
        logging.info(f'Signature data: {signature}')


if __name__ == '__main__':

    file_path = 'logs'
    file_name = 'test.log'
    log_formatter = logging.Formatter('%(asctime)s - %(message)s', )
    root_logger = logging.getLogger()
    if not os.path.exists(file_path):
        os.mkdir(file_path)
    with open(f'{file_path}/{file_name}', 'w'):
        pass
    file_handler = logging.FileHandler(f'{file_path}/{file_name}')
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
        asyncio.run(run_sample(total_node_number,
                    dkg_threshold, num_parties, num_signs))
    except KeyboardInterrupt:
        pass
