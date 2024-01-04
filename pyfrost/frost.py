from fastecdsa import keys
from web3 import Web3
from .crypto_utils import *
from typing import List, Dict, Tuple
import json
from fastecdsa.point import Point


class KeyGen:
    def __init__(self, dkg_id: str, threshold: int, n: int, node_id: str, partners: List[str], coefficient0: str = None) -> None:
        self.threshold: int = threshold
        self.n: int = n
        self.dkg_id: str = dkg_id
        self.node_id: str = node_id
        self.partners: List[str] = partners
        self.coefficient0 = coefficient0
        self.malicious: List = []
        self.status = 'STARTED'

    def round1(self) -> List[Dict]:
        self.secret_key, public_key = keys.gen_keypair(ecurve)
        secret_nonce, public_nonce = keys.gen_keypair(ecurve)
        secret_pop_hash = Web3.solidity_keccak(
            [
                'string',
                'string',
                'uint8',
                'uint8'
            ],
            [
                self.node_id,
                self.dkg_id,
                pub_to_code(public_key),
                pub_to_code(public_nonce)
            ],
        )

        secret_pop_sign = schnorr_sign(
            self.secret_key, secret_nonce, public_nonce, int.from_bytes(
                secret_pop_hash, 'big')
        )

        secret_signature = {
            'nonce': pub_to_code(public_nonce),
            'signature': stringify_signature(secret_pop_sign),
        }

        # Generate DKG polynomial
        self.fx = Polynomial(
            self.threshold, ecurve, self.coefficient0)
        self.public_fx = self.fx.coef_pub_keys()

        coef0_nonce, public_coef0_nonce = keys.gen_keypair(ecurve)
        coef0_pop_hash = Web3.solidity_keccak(
            [
                'string',
                'string',
                'uint8',
                'uint8'
            ],
            [
                self.node_id,
                self.dkg_id,
                pub_to_code(self.public_fx[0]),
                pub_to_code(public_coef0_nonce)
            ],
        )
        coef0_pop_sign = schnorr_sign(
            self.fx.coefficients[0], coef0_nonce, public_coef0_nonce, int.from_bytes(
                coef0_pop_hash, 'big')
        )

        self.coef0_signature = {
            'nonce': pub_to_code(public_coef0_nonce),
            'signature': stringify_signature(coef0_pop_sign),
        }

        self.status = 'ROUND1'
        return {
            'sender_id': self.node_id,
            'public_fx': [pub_to_code(s) for s in self.public_fx],
            'coefficient0_signature': self.coef0_signature,
            'public_key': pub_to_code(public_key),
            'secret_signature': secret_signature
        }

    def round2(self, round1_broadcasted_data) -> List[Dict]:
        self.round1_broadcasted_data = round1_broadcasted_data

        fx: Polynomial = self.fx
        self.partners_public_keys = {}
        secret_key = self.secret_key
        for data in round1_broadcasted_data:
            sender_id = data['sender_id']

            if sender_id == self.node_id:
                continue

            sender_public_fx = data['public_fx']
            sender_coef0_nonce = data['coefficient0_signature']['nonce']
            sender_coef0_signature = data['coefficient0_signature']['signature']

            coef0_pop_hash = Web3.solidity_keccak(
                ['string',  'string',       'uint8',                'uint8'],
                [sender_id, self.dkg_id,    sender_public_fx[0],    sender_coef0_nonce]
            )

            coef0_verification = schnorr_verify(
                code_to_pub(sender_public_fx[0]),
                int.from_bytes(coef0_pop_hash, 'big'),
                sender_coef0_signature
            )

            sender_public_key = data['public_key']
            sender_secret_nonce = data['secret_signature']['nonce']
            sender_secret_signature = data['secret_signature']['signature']

            secret_pop_hash = Web3.solidity_keccak(
                ['string',  'string',   'uint8',            'uint8'],
                [sender_id, self.dkg_id, sender_public_key, sender_secret_nonce]
            )

            secret_verification = schnorr_verify(
                code_to_pub(sender_public_key),
                int.from_bytes(secret_pop_hash, 'big'),
                sender_secret_signature
            )

            # TODO: add these checking in gateway in addition to nodes
            if not secret_verification or not coef0_verification:
                # TODO: how to handle complaint
                self.malicious.append({'id': sender_id, 'complaint': data})
            self.partners_public_keys[sender_id] = sender_public_key

        qualified = self.partners
        for node in self.malicious:
            try:
                qualified.remove(node['id'])
            except:
                pass
        result_data = []
        for id in qualified:
            encryption_joint_key = pub_to_code(
                secret_key * code_to_pub(self.partners_public_keys[id]))
            encryption_key = generate_hkdf_key(encryption_joint_key)
            id_as_int = int(id)
            data = {
                'receiver_id': id,
                'sender_id': self.node_id,
                'data': encrypt(
                    {'receiver_id': id, 'f': fx.evaluate(id_as_int)},
                    encryption_key
                )
            }
            result_data.append(data)

        self.status = 'ROUND2'
        return result_data

    def round3(self, round2_encrypted_data) -> Dict:
        secret_key = self.secret_key
        partners_public_keys = self.partners_public_keys
        round2_data = []
        complaints = []
        for message in round2_encrypted_data:
            sender_id = message['sender_id']
            receiver_id = message['receiver_id']
            encrypted_data = message['data']
            encryption_joint_key = pub_to_code(
                secret_key * code_to_pub(partners_public_keys[sender_id]))
            encryption_key = generate_hkdf_key(encryption_joint_key)

            assert receiver_id == self.node_id, 'ERROR: receiver_id does not match.'
            data = json.loads(decrypt(encrypted_data, encryption_key))
            round2_data.append(data)
            for round1_data in self.round1_broadcasted_data:
                if round1_data['sender_id'] == sender_id:
                    public_fx = round1_data['public_fx']

                    point1 = calc_poly_point(
                        list(map(code_to_pub, public_fx)),
                        int(self.node_id)
                    )

                    point2 = data['f'] * ecurve.G

                    if point1 != point2:
                        complaints.append(
                            self.complain(
                                secret_key,
                                sender_id,
                                partners_public_keys[sender_id]
                            )
                        )

        if len(complaints) > 0:
            self.status = 'COMPLAINT'
            return {'status': 'COMPLAINT', 'data': complaints}

        fx: Polynomial = self.fx
        my_fragment = fx.evaluate(int(self.node_id))
        share_fragments = [my_fragment]
        for data in round2_data:
            share_fragments.append(data['f'])

        public_fx = [self.public_fx[0]]
        for data in self.round1_broadcasted_data:
            if data['sender_id'] in self.partners:
                public_fx.append(code_to_pub(data['public_fx'][0]))

        dkg_public_key = public_fx[0]
        for i in range(1, len(public_fx)):
            dkg_public_key = dkg_public_key + public_fx[i]

        share = sum(share_fragments)
        self.dkg_key_pair = {'share': share, 'dkg_public_key': pub_to_code(dkg_public_key)}

        result = {
            'data': {
                'dkg_public_key': pub_to_code(dkg_public_key),
                'public_share': pub_to_code(keys.get_public_key(share, ecurve)),
            },
            'dkg_key_pair': self.dkg_key_pair,
            'status': 'SUCCESSFUL'
        }
        self.status = 'COMPLETED'
        return result


class Key:
    def __init__(self, dkg_key: Dict, node_id: str) -> None:
        self.dkg_key_pair = dkg_key
        self.dkg_key_pair['dkg_public_key'] = code_to_pub(self.dkg_key_pair['dkg_public_key'])
        self.node_id = node_id

    def sign(self, commitments_dict: Dict, message: str, nonces: List[Dict]) -> Tuple[Dict, Dict]:
        assert isinstance(message, str), 'Message should be of string type.'

        nonce_d, nonce_e = 0, 0
        signature, used_nonce = None, None
        my_nonce = commitments_dict[self.node_id]

        for pair in nonces:
            nonce_d = pair['nonce_d_pair'].get(my_nonce['public_nonce_d'])
            nonce_e = pair['nonce_e_pair'].get(my_nonce['public_nonce_e'])

            if nonce_d is not None and nonce_e is not None:
                signature = single_sign(
                    int(self.node_id),
                    self.dkg_key_pair['share'],
                    nonce_d,
                    nonce_e,
                    message,
                    commitments_dict,
                    pub_to_code(self.dkg_key_pair['dkg_public_key'])
                )
                used_nonce = {
                    'nonce_d_pair': {my_nonce['public_nonce_d']: nonce_d},
                    'nonce_e_pair': {my_nonce['public_nonce_e']: nonce_e}
                }
                break

        return signature, used_nonce


def create_nonces(node_id: int, number_of_nonces: int = 10) -> Tuple[List[Dict], List[Dict]]:
    nonce_publics, nonce_privates = [], []

    for _ in range(number_of_nonces):
        # Generate nonce pairs (private and public)
        nonce_d, nonce_e = generate_random_private(), generate_random_private()
        public_nonce_d = pub_to_code(keys.get_public_key(nonce_d, ecurve))
        public_nonce_e = pub_to_code(keys.get_public_key(nonce_e, ecurve))

        # Append private nonce pairs
        nonce_privates.append({
            'nonce_d_pair': {public_nonce_d: nonce_d},
            'nonce_e_pair': {public_nonce_e: nonce_e}
        })

        # Append public nonce pairs
        nonce_publics.append({
            'id': node_id,
            'public_nonce_d': public_nonce_d,
            'public_nonce_e': public_nonce_e
        })

    return nonce_publics, nonce_privates


def verify_single_signature(id: int, message: str, commitments_dict: Dict[str, Dict[str, int]], aggregated_public_nonce: Point,
                            public_key_share: int, single_signature: Dict[str, int], group_key: Point) -> bool:
    # Prepare hashes and list
    commitments_list = list(commitments_dict.values())
    commitments_hash = Web3.keccak(text=json.dumps(commitments_list))
    message_hash = Web3.keccak(text=message)

    # Find the relevant commitment and calculate the public nonce
    public_nonce, index = None, 0
    for idx, commitment in enumerate(commitments_list):
        if commitment['id'] == id:
            nonce_d_public = code_to_pub(commitment['public_nonce_d'])
            nonce_e_public = code_to_pub(commitment['public_nonce_e'])
            row = Web3.solidity_keccak(['string', 'bytes', 'bytes'],
                                       [hex(commitment['id']), message_hash, commitments_hash])
            public_nonce = nonce_d_public + \
                (int.from_bytes(row, 'big') * nonce_e_public)
            index = idx
            break

    # Calculate challenge
    group_key_pub = pub_compress(code_to_pub(group_key))
    challenge = Web3.solidity_keccak(
        ['uint256', 'uint8', 'uint256', 'address'],
        [Web3.to_int(hexstr=group_key_pub['x']), group_key_pub['y_parity'],
         Web3.to_int(message_hash), pub_to_addr(aggregated_public_nonce)]
    )

    # Calculate coefficients and points
    coef = langrange_coef(index, len(commitments_list), commitments_list, 0)
    point1 = public_nonce - \
        (int.from_bytes(challenge, 'big') * coef * code_to_pub(public_key_share))
    point2 = single_signature['signature'] * ecurve.G

    # Verify the points
    return point1 == point2


def aggregate_nonce(message: str, commitments_dict: Dict[str, Dict[str, int]], group_key: Point):
    # Convert commitments to a list and calculate hashes
    commitments_list = list(commitments_dict.values())
    commitments_hash = Web3.keccak(text=json.dumps(commitments_list))
    message_hash = Web3.keccak(text=message)

    # Initialize aggregated public nonce
    aggregated_public_nonce = None

    for commitment in commitments_list:
        # Convert codes to public nonces
        nonce_d_public = code_to_pub(commitment['public_nonce_d'])
        nonce_e_public = code_to_pub(commitment['public_nonce_e'])

        # Calculate row hash
        row_hash = Web3.solidity_keccak(
            ['string', 'bytes', 'bytes'],
            [hex(commitment['id']), message_hash, commitments_hash]
        )

        # Calculate public nonce
        public_nonce = nonce_d_public + \
            (int.from_bytes(row_hash, 'big') * nonce_e_public)

        # Aggregate public nonces
        if aggregated_public_nonce is None:
            aggregated_public_nonce = public_nonce
        else:
            aggregated_public_nonce += public_nonce

    return aggregated_public_nonce


def aggregate_signatures(message: str, single_signatures: List[Dict[str, int]], aggregated_public_nonce: Point, group_key: int) -> Dict:
    # Calculate message hash
    message_hash = Web3.keccak(text=message)

    # Aggregate signatures
    aggregated_signature = sum(sign['signature']
                               for sign in single_signatures) % N

    return {
        'nonce': pub_to_addr(aggregated_public_nonce),
        'public_key': pub_compress(code_to_pub(group_key)),
        'signature': aggregated_signature,
        'message_hash': message_hash
    }


def verify_group_signature(aggregated_signature: Dict) -> bool:
    # Calculate the challenge
    challenge = Web3.solidity_keccak(
        ['uint256', 'uint8', 'uint256', 'address'],
        [
            Web3.to_int(hexstr=aggregated_signature['public_key']['x']),
            aggregated_signature['public_key']['y_parity'],
            Web3.to_int(aggregated_signature['message_hash']),
            aggregated_signature['nonce']
        ]
    )

    # Calculate the point
    challenge_int = int.from_bytes(challenge, 'big')
    point = (aggregated_signature['signature'] * ecurve.G) + \
        (challenge_int * pub_decompress(aggregated_signature['public_key']))

    # Verify the nonce
    return aggregated_signature['nonce'] == pub_to_addr(point)

# TODO : exclude complaint

# =======================================================================================
# ================================== Private Functions ==================================
# =======================================================================================


def single_sign(id: str, share: int, nonce_d: int, nonce_e: int, message: str,
                commitments_dict: Dict[str, Dict[str, int]], group_key: Point) -> Dict[str, int]:
    # Prepare hashes and list
    commitments_list = list(commitments_dict.values())
    commitments_hash = Web3.keccak(text=json.dumps(commitments_list))
    message_hash = Web3.keccak(text=message)

    # Aggregate public nonces and find the relevant row and index
    aggregated_public_nonce = None
    my_row, index = 0, 0
    for idx, commitment in enumerate(commitments_list):
        # Convert codes to public nonces and validate
        nonce_d_public = code_to_pub(commitment['public_nonce_d'])
        nonce_e_public = code_to_pub(commitment['public_nonce_e'])
        for nonce_public, nonce_name in [(nonce_d_public, 'D'), (nonce_e_public, 'E')]:
            assert ecurve.is_point_on_curve((nonce_public.x, nonce_public.y)), \
                f'Nonce {nonce_name} from Node {commitment["id"]} Not on Curve'

        # Compute public nonce
        row = Web3.solidity_keccak(['string', 'bytes', 'bytes'],
                                   [hex(commitment['id']), message_hash, commitments_hash])
        public_nonce = nonce_d_public + \
            (int.from_bytes(row, 'big') * nonce_e_public)
        aggregated_public_nonce = public_nonce if aggregated_public_nonce is None else aggregated_public_nonce + public_nonce

        # Check for the current party's commitment
        if id == commitment['id']:
            my_row, index = row, idx

    # Calculate challenge
    group_key_pub = pub_compress(code_to_pub(group_key))
    challenge = Web3.solidity_keccak(
        ['uint256', 'uint8', 'uint256', 'address'],
        [Web3.to_int(hexstr=group_key_pub['x']), group_key_pub['y_parity'],
         Web3.to_int(message_hash), pub_to_addr(aggregated_public_nonce)]
    )

    # Calculate signature share
    coef = langrange_coef(index, len(commitments_list), commitments_list, 0)
    signature_share = (nonce_d + nonce_e * int.from_bytes(my_row, 'big') -
                       coef * share * int.from_bytes(challenge, 'big')) % N

    return {
        'id': id,
        'signature': signature_share,
        'public_key': pub_to_code(keys.get_public_key(share, ecurve)),
        'aggregated_public_nonce': pub_to_code(aggregated_public_nonce)
    }


def create_complaint(node_id: str, secret_key: int, partner_id: str, partner_public: Point) -> Dict:
    # Calculate joint encryption key and public key
    encryption_joint_key = pub_to_code(secret_key * partner_public)
    public_key = keys.get_public_key(secret_key, ecurve)

    # Generate keypair
    random_nonce, public_nonce = keys.gen_keypair()

    # Calculate commitment
    commitment = random_nonce * partner_public

    # Create the hash for the Proof of Complaint (PoC)
    complaint_pop_hash = Web3.solidity_keccak(
        [
            'uint8',
            'uint8',
            'uint8',
            'uint8',
            'uint8'
        ],
        [
            pub_to_code(public_key),
            pub_to_code(partner_public),
            encryption_joint_key,
            pub_to_code(public_nonce),
            pub_to_code(commitment)
        ]
    )

    # Sign the PoC
    complaint_pop_sign = complaint_sign(
        secret_key,
        random_nonce,
        int.from_bytes(complaint_pop_hash, 'big')
    )

    # Assemble the Proof of Complaint
    complaint_pop = {
        'public_nonce': pub_to_code(public_nonce),
        'commitment': pub_to_code(commitment),
        'signature': complaint_pop_sign
    }

    # Return the complete complaint structure
    return {
        'complaintant': node_id,
        'malicious': partner_id,
        'encryption_key': encryption_joint_key,
        'proof': complaint_pop
    }
