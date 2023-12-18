from typing import Dict , List
from fastecdsa.point import Point
from fastecdsa import keys
from utils import Utils
from web3 import Web3
import json


def single_sign(id: str, share: int, nonce_d: int, nonce_e: int, message: str,
                        commitments_dict: Dict[str,Dict[str ,int]], group_key: Point) -> Dict[str, int]:

    # commitment = {id: {id , D(i) , E(i)}}
    party = []
    index = 0
    my_row = 0
    aggregated_public_nonce = None
    is_first = True
    
    commitments_list = list(commitments_dict.values())
    commitments_hash = Web3.keccak(text=json.dumps(commitments_list))
    message_hash = Web3.keccak(text=message)

    for commitment in commitments_list:
        nonce_d_public = Utils.code_to_pub(commitment['public_nonce_d'])
        nonce_e_public = Utils.code_to_pub(commitment['public_nonce_e'])
        assert Utils.ecurve.is_point_on_curve(
            (nonce_d_public.x, nonce_d_public.y)
            ), f'Nonce D from Node {commitment["id"]} Not on Curve'
        assert Utils.ecurve.is_point_on_curve(
            (nonce_e_public.x, nonce_e_public.y)
            ), f'Nonce E from Node {commitment["id"]} Not on Curve'

        party.append(commitment['id'])

        row = Web3.solidity_keccak(
            ['string', 'bytes', 'bytes'],
            [hex(commitment['id']),  message_hash,  commitments_hash]
        )

        public_nonce = nonce_d_public + (int.from_bytes(row, 'big') * nonce_e_public)
        if is_first:
            aggregated_public_nonce = public_nonce
            is_first = False
        else:
            aggregated_public_nonce = aggregated_public_nonce + public_nonce

        if (id == commitment['id']):
            my_row = row
            index = commitments_list.index(commitment)

    challenge = Web3.solidity_keccak(
        [
            'uint256',
            'uint8',
            'uint256',
            'address'
        ],
        [
            Web3.to_int(hexstr= Utils.pub_compress(Utils.code_to_pub(group_key))['x']),
            Utils.pub_compress(Utils.code_to_pub(group_key))['y_parity'],
            Web3.to_int(message_hash),
            Utils.pub_to_addr(aggregated_public_nonce)
        ]
    )

    coef = Utils.langrange_coef(index, len(party), commitments_list, 0)
    signature_share = (nonce_d + nonce_e * int.from_bytes(my_row, 'big') -
                        coef * share * int.from_bytes(challenge, 'big')) % Utils.N
    return {
        'id': id, 
        'signature': signature_share, 
        'public_key': Utils.pub_to_code(keys.get_public_key(share , Utils.ecurve)),
        'aggregated_public_nonce': Utils.pub_to_code(aggregated_public_nonce)
        }

def verify_single_signature(id: int, message: str, commitments_dict: Dict[str, Dict[str, int]], aggregated_public_nonce: Point,
                                    public_key_share: int, single_signature: Dict[str, int], group_key: Point) -> bool:

    index = 0
    public_nonce = None
    commitments_list = list(commitments_dict.values())
    commitments_hash = Web3.keccak(text=json.dumps(commitments_list))
    message_hash = Web3.keccak(text=message)

    for commitment in commitments_list:
        if commitment['id'] == id:
            nonce_d_public = Utils.code_to_pub(commitment['public_nonce_d'])
            nonce_e_public = Utils.code_to_pub(commitment['public_nonce_e'])
            row = Web3.solidity_keccak(
                ['string', 'bytes', 'bytes'],
                [hex(commitment['id']),  message_hash,  commitments_hash]
            )
            public_nonce = nonce_d_public + (int.from_bytes(row, 'big') * nonce_e_public)
            index = commitments_list.index(commitment)

    challenge = Web3.solidity_keccak(
        [
            'uint256',
            'uint8',
            'uint256',
            'address'
        ],
        [
            Web3.to_int(hexstr=Utils.pub_compress(Utils.code_to_pub(group_key))['x']),
            Utils.pub_compress(Utils.code_to_pub(group_key))['y_parity'],
            Web3.to_int(message_hash),
            Utils.pub_to_addr(aggregated_public_nonce)
        ]
    )

    coef = Utils.langrange_coef(index, len(commitments_list), commitments_list, 0)

    point1 = public_nonce - (int.from_bytes(challenge, 'big')* coef * Utils.code_to_pub(public_key_share))
    point2 = single_signature['signature'] * Utils.ecurve.G

    return point1 == point2

def aggregate_nonce(message: str, commitments_dict: Dict[str, Dict[str, int]], group_key: Point):
    aggregated_public_nonce = None
    is_first = True
    commitments_list = list(commitments_dict.values())
    commitments_hash = Web3.keccak(text=json.dumps(commitments_list))
    message_hash = Web3.keccak(text=message)

    for commitment in commitments_list:
        nonce_d_public = Utils.code_to_pub(commitment['public_nonce_d'])
        nonce_e_public = Utils.code_to_pub(commitment['public_nonce_e'])

        row = Web3.solidity_keccak(
            ['string', 'bytes', 'bytes'],
            [hex(commitment['id']),  message_hash,  commitments_hash]
        )

        public_nonce = nonce_d_public + (int.from_bytes(row, 'big') * nonce_e_public)
        if is_first:
            aggregated_public_nonce = public_nonce
            is_first = False
        else:
            aggregated_public_nonce = aggregated_public_nonce + public_nonce
    return aggregated_public_nonce

def aggregate_signatures(message: str, single_signatures: List[Dict[str, int]], aggregated_public_nonce : Point, group_key: Point) -> Dict:
    message_hash = Web3.keccak(text=message)
    aggregated_signature = 0
    for sign in single_signatures:
        aggregated_signature = aggregated_signature + sign['signature']
    aggregated_signature = aggregated_signature % Utils.N
    return {'nonce': Utils.pub_to_addr(aggregated_public_nonce), 'public_key': Utils.pub_compress(Utils.code_to_pub(group_key)),
            'signature': aggregated_signature, 'message_hash': message_hash}

def verify_group_signature(aggregated_signature: Dict) -> bool:

    challenge = Web3.solidity_keccak(
        [
            'uint256',
            'uint8',
            'uint256',
            'address'
        ],
        [
            Web3.to_int(hexstr= aggregated_signature['public_key']['x']),
            aggregated_signature['public_key']['y_parity'],
            Web3.to_int(aggregated_signature['message_hash']),
            aggregated_signature['nonce']
        ]
    )

    point = (aggregated_signature['signature'] * Utils.ecurve.G) + (
        int.from_bytes(challenge, 'big') * Utils.pub_decompress(aggregated_signature['public_key']))
    return aggregated_signature['nonce'] == Utils.pub_to_addr(point)

def nonce_preprocess(node_id: int, number_of_nonces=10) -> List[List]:
    nonce_publics = []
    save_data = []
    for _ in range(number_of_nonces):
        nonce_d = Utils.generate_random_private()
        nonce_e = Utils.generate_random_private()
        public_nonce_d = Utils.pub_to_code(keys.get_public_key(nonce_d , Utils.ecurve))
        public_nonce_e = Utils.pub_to_code(keys.get_public_key(nonce_e , Utils.ecurve))

        save_data.append({
            'nonce_d_pair': {public_nonce_d: nonce_d},
            'nonce_e_pair': {public_nonce_e: nonce_e}
        })

        nonce_publics.append({
            'id': node_id,
            'public_nonce_d': public_nonce_d,
            'public_nonce_e': public_nonce_e,
        })

    return nonce_publics , save_data

def complain(node_id : str, secret_key : int, partner_id : str, partner_public : Point) -> Dict:
    encryption_joint_key = Utils.pub_to_code(secret_key * partner_public)
    public_key = keys.get_public_key(secret_key , Utils.ecurve)
    random_nonce, public_nonce = keys.gen_keypair()
    commitment  = random_nonce * partner_public
    complaint_pop_hash = Web3.solidity_keccak(
        [
            'uint8', 
            'uint8', 
            'uint8', 
            'uint8',
            'uint8'
            ],
        [
            Utils.pub_to_code(public_key),
            Utils.pub_to_code(partner_public),
            encryption_joint_key,
            Utils.pub_to_code(public_nonce),
            Utils.pub_to_code(commitment)
            ],
    )
    complaint_pop_sign = Utils.complaint_sign(
        secret_key, 
        random_nonce,  
        int.from_bytes(complaint_pop_hash, 'big')
    )
    complaint_pop = {
        'public_nonce' : Utils.pub_to_code(public_nonce), 
        'commitment' : Utils.pub_to_code(commitment), 
        'signature' : complaint_pop_sign
    }

    return {
        'complaintant' : node_id, 
        'malicious' : partner_id, 
        'encryption_key' : encryption_joint_key, 
        'proof' : complaint_pop
    }

#TODO : exclude complaint

