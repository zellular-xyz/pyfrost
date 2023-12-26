from pyfrost.network.sa import SA
from pyfrost.network.dkg import Dkg
from config import PEER_INFO, PRIVATE
from typing import Dict
from abstracts import NodeInfo
import logging
import time
import timeit
import trio
import sys
import os
import random


async def run(total_node_number: int, threshold: int, n: int, num_signs: int) -> None:
    node_info = NodeInfo()

    all_nodes = node_info.get_all_nodes(total_node_number)
    selected_nodes = {}
    for node_id, peer_ids in all_nodes.items():
        selected_nodes[node_id] = peer_ids[0]
    dkg = Dkg(PEER_INFO, PRIVATE, node_info, max_workers=0, default_timeout=50)
    sa = SA(PEER_INFO, PRIVATE, node_info, max_workers=0,
            default_timeout=50, host=dkg.host)
    nonces = {}
    async with trio.open_nursery() as nursery:

        # Run libp2p instance
        nursery.start_soon(dkg.run)


        # Request nonces
        nonces_response = await sa.request_nonces(selected_nodes)
        for node_id, peer_id in selected_nodes.items():
            nonces.setdefault(node_id, [])
            nonces[node_id] += nonces_response[peer_id]['nonces']
            
        # Random party selection:
        seed = int(time.time())
        random.seed(seed)
        items = list(selected_nodes.items())
        random_subset = random.sample(items, n)
        party = dict(random_subset)
        
        # Requesting DKG:
        now = timeit.default_timer()
        dkg_key = await dkg.request_dkg(threshold, party, node_info)
        then = timeit.default_timer()

        logging.info(f'Requesting DKG takes: {then - now} seconds.')
        logging.info(f'The DKG result is {dkg_key["result"]}')

        dkg_id = dkg_key['dkg_id']
        logging.info(f'dkg key: {dkg_key}')

        for i in range(num_signs):
            logging.info(
                f'Get signature {i} with DKG id {dkg_id}')

            dkg_party: Dict = dkg_key['party']
            nonces_dict = {}

            for node_id in dkg_party.keys():
                nonce = nonces[node_id].pop()
                nonces_dict[node_id] = nonce

            now = timeit.default_timer()
            input_data = {
                'data': 'Hi there!'
            }

            signature = await sa.request_signature(dkg_key, nonces_dict, input_data, dkg_key['party'])
            then = timeit.default_timer()

            logging.info(
                f'Requesting signature {i} takes {then - now} seconds')
            logging.info(f'Signature data: {signature}')

        dkg.stop()
        nursery.cancel_scope.cancel()


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
    root_logger.setLevel(logging.INFO)

    sys.set_int_max_str_digits(0)

    total_node_number = int(sys.argv[1])
    dkg_threshold = int(sys.argv[2])
    num_parties = int(sys.argv[3])
    num_signs = int(sys.argv[4])

    try:
        trio.run(run, total_node_number, dkg_threshold, num_parties, num_signs)
    except KeyboardInterrupt:
        pass
