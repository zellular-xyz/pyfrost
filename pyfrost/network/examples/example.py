from pyfrost.network.sa import SA
from pyfrost.network.dkg import Dkg
from pyfrost.network.node import Node
from pyfrost.network.libp2p_base import RequestObject, PROTOCOLS_ID
from configs import PEER_INFO, PRIVATE
from typing import List, Dict
from utils import get_new_random_subset
from abstracts import NodeInfo
import logging
import time
import timeit
import trio
import uuid
import pprint
import sys
import os


async def run_random_party_dkg(dkg: Dkg, selected_nodes: Dict, threshold: int, n: int, node_info: NodeInfo) -> None:
    is_completed = False
    dkg_key = None
    while not is_completed:
        seed = int(time.time())
        party = get_new_random_subset(selected_nodes, seed, n)
        now = timeit.default_timer()
        dkg_key = await dkg.request_dkg(threshold, party, node_info)
        then = timeit.default_timer()
        if dkg_key['dkg_id'] == None:
            exit()
        result = dkg_key['result']
        logging.info(f'Requesting DKG takes: {then - now} seconds.')
        logging.info(f'The DKG result is {result}')
        if result == 'SUCCESSFUL':
            is_completed = True
    return dkg_key


async def maintain_nonces(sa: SA, party: Dict, nonces: Dict[str, List], node_info: NodeInfo, min_number_of_nonces: int = 10) -> None:
    call_method = 'generate_nonces'
    average_time = []
    for node_id, peer_id in party.items():
        nonces.setdefault(node_id, [])
        start_time = timeit.default_timer()
        req_id = str(uuid.uuid4())
        parameters = {
            'number_of_nonces': min_number_of_nonces * 10,
        }
        request_object = RequestObject(req_id, call_method, parameters)
        nonces_response = {}
        destination_address = node_info.lookup_node(peer_id)[0]
        await sa.send(destination_address, peer_id,
                      PROTOCOLS_ID[call_method], request_object.get(), nonces_response, 50, None)

        logging.debug(
            f'Nonces dictionary response: \n{pprint.pformat(nonces_response)}')
        nonces[node_id] += nonces_response[peer_id]['nonces']
        end_time = timeit.default_timer()
        logging.info(
            f'Getting nonces from peer ID {node_id} takes {end_time-start_time} seconds.')
        average_time.append(end_time-start_time)
    average_time = sum(average_time) / len(average_time)
    logging.info(f'Nonce generation average time: {average_time}')


async def get_commitments(party: Dict, nonces: Dict[str, List], timeout: int = 5) -> Dict:
    commitments_dict = {}
    peer_ids_with_timeout = {}
    for node_id, peer_id in party.items():
        with trio.move_on_after(timeout) as cancel_scope:
            while not nonces.get(node_id):
                await trio.sleep(0.1)
            commitment = nonces[node_id].pop()
            commitments_dict[node_id] = commitment
        if cancel_scope.cancelled_caught:
            timeout_response = {
                'status': 'TIMEOUT',
                'error': 'Communication timed out',
            }
            peer_ids_with_timeout[peer_id] = timeout_response

    if len(peer_ids_with_timeout) > 0:
        logging.error(
            f'get_commitments => Timeout error occurred. peer ids with timeout: {peer_ids_with_timeout}')
    return commitments_dict


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
        nursery.start_soon(dkg.run)
        await maintain_nonces(sa, selected_nodes, nonces, node_info)
        start_time = timeit.default_timer()
        dkg_key = await run_random_party_dkg(dkg, selected_nodes, threshold, n, node_info)
        end_time = timeit.default_timer()

        dkg_id = dkg_key['dkg_id']
        logging.info(f'dkg key: {dkg_key}')
        logging.info(
            f'Running DKG {dkg_id} takes {end_time - start_time} seconds')

        for i in range(num_signs):
            logging.info(
                f'Get signature {i} with DKG id {dkg_id}')
            commitments_dict = await get_commitments(dkg_key['party'], nonces)
            now = timeit.default_timer()
            input_data = {
                'data': 'Hi there!'
            }

            signature = await sa.request_signature(dkg_key, commitments_dict, input_data, dkg_key['party'])
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
    root_logger.setLevel(logging.DEBUG)

    sys.set_int_max_str_digits(0)

    total_node_number = int(sys.argv[1])
    dkg_threshold = int(sys.argv[2])
    num_parties = int(sys.argv[3])
    num_signs = int(sys.argv[4])

    try:
        trio.run(run, total_node_number, dkg_threshold, num_parties, num_signs)
    except KeyboardInterrupt:
        pass
