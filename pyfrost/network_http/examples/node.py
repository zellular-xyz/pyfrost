from pyfrost.network_http.node import Node
from abstracts import NodeInfo, NodeDataManager, NodeValidators
from config import generate_privates_and_node_info
import os
import logging
import sys


def run_node(node_number: int) -> None:
    data_manager = NodeDataManager()
    node_info = NodeInfo()
    privates, _ = generate_privates_and_node_info()
    node = Node(data_manager, str(node_number), privates[node_number-1], node_info,
                NodeValidators.caller_validator, NodeValidators.data_validator)
    node.run_app()

if __name__ == '__main__':

    node_number = int(sys.argv[1])
    file_path = 'logs'
    file_name = f'node{node_number}.log'
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
    
    try:
        run_node(node_number)
    except KeyboardInterrupt:
        pass