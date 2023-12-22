from pyfrost.network.node import Node
from abstracts import NodeInfo, NodeDataManager, NodeValidators
from configs import SECRETS

import os
import logging
import trio
import sys


async def run_node(node_number: int) -> None:
    data_manager = NodeDataManager()
    node_info = NodeInfo()
    node_peer_id = node_info.get_all_nodes()[str(node_number+1)][0]
    node = Node(data_manager, node_info.lookup_node(node_peer_id)[0], SECRETS[node_peer_id], node_info,
                NodeValidators.caller_validator, NodeValidators.data_validator)
    await node.run()

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
    node_number = int(sys.argv[1])
    try:
        trio.run(run_node, node_number)
    except KeyboardInterrupt:
        pass
