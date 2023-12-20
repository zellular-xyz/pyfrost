from fastecdsa import keys
from web3 import Web3
import crypto_utils as __utils
from typing import List, Dict
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
        self.round1_local_data = None
        self.round1_broadcasted_data = None
        self.round2_local_data = None
        self.dkg_key_pair = None
        self.status = 'STARTED'

    def round1(self) -> List[Dict]:
        secret_key, public_key = keys.gen_keypair(__utils.ecurve)
        secret_nonce, public_nonce = keys.gen_keypair(__utils.ecurve)
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
                __utils.pub_to_code(public_key),
                __utils.pub_to_code(public_nonce)
            ],
        )

        secret_pop_sign = __utils.schnorr_sign(
            secret_key, secret_nonce, public_nonce, int.from_bytes(
                secret_pop_hash, 'big')
        )

        secret_signature = {
            'nonce': __utils.pub_to_code(public_nonce),
            'signature': __utils.stringify_signature(secret_pop_sign),
        }

        # Generate DKG polynomial
        fx = __utils.Polynomial(
            self.threshold, __utils.ecurve, self.coefficient0)
        public_fx = fx.__coef_pub_keys()

        coef0_nonce, public_coef0_nonce = keys.gen_keypair(__utils.ecurve)
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
                __utils.pub_to_code(public_fx[0]),
                __utils.pub_to_code(public_coef0_nonce)
            ],
        )
        coef0_pop_sign = __utils.schnorr_sign(
            fx.coefficients[0], coef0_nonce, public_coef0_nonce, int.from_bytes(
                coef0_pop_hash, 'big')
        )

        coef0_signature = {
            'nonce': __utils.pub_to_code(public_coef0_nonce),
            'signature': __utils.stringify_signature(coef0_pop_sign),
        }

        self.round1_local_data = {
            'dkg_id': self.dkg_id,
            'secret_key': secret_key,
            'fx': fx,
            'public_fx': public_fx,
            'coef0_signature': coef0_signature
        }

        self.status = 'ROUND1'

        return {
            'sender_id': self.node_id,
            'public_fx': [__utils.pub_to_code(s) for s in public_fx],
            'coefficient0_signature': coef0_signature,
            'public_key': __utils.pub_to_code(public_key),
            'secret_signature': secret_signature
        }

    def round2(self, round1_broadcasted_data) -> List[Dict]:
        self.round1_broadcasted_data = round1_broadcasted_data

        fx: __utils.Polynomial = self.round1_local_data['fx']
        partners_public_keys = {}
        secret_key = self.round1_local_data['secret_key']
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

            coef0_verification = __utils.schnorr_verify(
                __utils.code_to_pub(sender_public_fx[0]),
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

            secret_verification = __utils.schnorr_verify(
                __utils.code_to_pub(sender_public_key),
                int.from_bytes(secret_pop_hash, 'big'),
                sender_secret_signature
            )

            # TODO: add these checking in gateway in addition to nodes
            if not secret_verification or not coef0_verification:
                # TODO: how to handle complaint
                self.malicious.append({'id': sender_id, 'complaint': data})
            partners_public_keys[sender_id] = sender_public_key

        qualified = self.partners
        for node in self.malicious:
            try:
                qualified.remove(node['id'])
            except:
                pass
        result_data = []
        for id in qualified:
            encryption_joint_key = __utils.pub_to_code(
                secret_key * __utils.code_to_pub(partners_public_keys[id]))
            encryption_key = __utils.generate_hkdf_key(encryption_joint_key)
            id_as_int = int(id)
            data = {
                'receiver_id': id,
                'sender_id': self.node_id,
                'data': __utils.encrypt(
                    {'receiver_id': id, 'f': fx.__utils.evaluate(id_as_int)},
                    encryption_key
                )
            }
            result_data.append(data)

        self.round2_local_data = {
            'dkg_id': self.dkg_id,
            'partners_public_keys': partners_public_keys
        }
        self.status = 'ROUND2'
        return result_data

    def round3(self, round2_encrypted_data) -> Dict:
        secret_key = self.round1_local_data['secret_key']
        partners_public_keys = self.round2_local_data['partners_public_keys']
        round2_data = []
        complaints = []
        for message in round2_encrypted_data:
            sender_id = message['sender_id']
            receiver_id = message['receiver_id']
            encrypted_data = message['data']
            encryption_joint_key = __utils.pub_to_code(
                secret_key * __utils.code_to_pub(partners_public_keys[sender_id]))
            encryption_key = __utils.generate_hkdf_key(encryption_joint_key)

            assert receiver_id == self.node_id, 'ERROR: receiver_id does not match.'
            data = json.loads(__utils.decrypt(encrypted_data, encryption_key))
            round2_data.append(data)
            for round1_data in self.round1_broadcasted_data:
                if round1_data['sender_id'] == sender_id:
                    public_fx = round1_data['public_fx']

                    point1 = __utils.calc_poly_point(
                        list(map(__utils.code_to_pub, public_fx)),
                        int(self.node_id)
                    )

                    point2 = data['f'] * __utils.ecurve.G

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

        fx: __utils.Polynomial = self.round1_local_data['fx']
        my_fragment = fx.__utils.evaluate(int(self.node_id))
        share_fragments = [my_fragment]
        for data in round2_data:
            share_fragments.append(data['f'])

        public_fx = [self.round1_local_data['public_fx'][0]]
        for data in self.round1_broadcasted_data:
            if data['sender_id'] in self.partners:
                public_fx.append(__utils.code_to_pub(data['public_fx'][0]))

        dkg_public_key = public_fx[0]
        for i in range(1, len(public_fx)):
            dkg_public_key = dkg_public_key + public_fx[i]

        share = sum(share_fragments)
        self.dkg_key_pair = {'share': share, 'dkg_public_key': dkg_public_key}

        result = {
            'data': {
                'dkg_public_key': __utils.pub_to_code(dkg_public_key),
                'public_share': __utils.pub_to_code(keys.get_public_key(share, __utils.ecurve)),
            },
            'status': 'SUCCESSFUL'
        }
        self.status = 'COMPLETED'
        return result


class Key:
    def __init__(self, dkg_key) -> None:
        self.__dkg_key_pair = dkg_key

    def sign(self, commitments_dict, message: str, nonces: Dict) -> List:
        assert type(message) == str, 'Message should be from string type.'
        nonce_d = 0
        nonce_e = 0
        signature = None
        nonce = commitments_dict[self.node_id]
        for pair in nonces:
            nonce_d = pair['nonce_d_pair'].get(nonce['public_nonce_d'])
            nonce_e = pair['nonce_e_pair'].get(nonce['public_nonce_e'])
            if nonce_d is None and nonce_e is None:
                continue

            signature = __utils.single_sign(
                int(self.node_id),
                self.dkg_key_pair['share'],
                nonce_d,
                nonce_e,
                message,
                commitments_dict,
                __utils.pub_to_code(self.dkg_key_pair['dkg_public_key'])
            )
            remove_data = {
                'nonce_d_pair': {nonce['public_nonce_d']: nonce_d},
                'nonce_e_pair': {nonce['public_nonce_e']: nonce_e}
            }

        return signature, remove_data


def create_nonces(node_id: int, number_of_nonces=10) -> List[List]:
    nonce_publics = []
    private_data = []
    for _ in range(number_of_nonces):
        nonce_d = __utils.generate_random_private()
        nonce_e = __utils.generate_random_private()
        public_nonce_d = __utils.pub_to_code(
            keys.get_public_key(nonce_d, __utils.ecurve))
        public_nonce_e = __utils.pub_to_code(
            keys.get_public_key(nonce_e, __utils.ecurve))

        private_data.append({
            'nonce_d_pair': {public_nonce_d: nonce_d},
            'nonce_e_pair': {public_nonce_e: nonce_e}
        })

        nonce_publics.append({
            'id': node_id,
            'public_nonce_d': public_nonce_d,
            'public_nonce_e': public_nonce_e,
        })

    return nonce_publics, private_data


def verify_single_signature(id: int, message: str, commitments_dict: Dict[str, Dict[str, int]], aggregated_public_nonce: Point,
                            public_key_share: int, single_signature: Dict[str, int], group_key: Point) -> bool:

    index = 0
    public_nonce = None
    commitments_list = list(commitments_dict.values())
    commitments_hash = Web3.keccak(text=json.dumps(commitments_list))
    message_hash = Web3.keccak(text=message)

    for commitment in commitments_list:
        if commitment['id'] == id:
            nonce_d_public = __utils.code_to_pub(commitment['public_nonce_d'])
            nonce_e_public = __utils.code_to_pub(commitment['public_nonce_e'])
            row = Web3.solidity_keccak(
                ['string', 'bytes', 'bytes'],
                [hex(commitment['id']),  message_hash,  commitments_hash]
            )
            public_nonce = nonce_d_public + \
                (int.from_bytes(row, 'big') * nonce_e_public)
            index = commitments_list.index(commitment)

    challenge = Web3.solidity_keccak(
        [
            'uint256',
            'uint8',
            'uint256',
            'address'
        ],
        [
            Web3.to_int(hexstr=__utils.pub_compress(
                __utils.code_to_pub(group_key))['x']),
            __pub_compress(__utils.code_to_pub(group_key))['y_parity'],
            Web3.to_int(message_hash),
            __utils.pub_to_addr(aggregated_public_nonce)
        ]
    )

    coef = __utils.langrange_coef(index, len(
        commitments_list), commitments_list, 0)

    point1 = public_nonce - \
        (int.from_bytes(challenge, 'big') *
         coef * __utils.code_to_pub(public_key_share))
    point2 = single_signature['signature'] * __utils.ecurve.G

    return point1 == point2


def aggregate_nonce(message: str, commitments_dict: Dict[str, Dict[str, int]], group_key: Point):
    aggregated_public_nonce = None
    is_first = True
    commitments_list = list(commitments_dict.values())
    commitments_hash = Web3.keccak(text=json.dumps(commitments_list))
    message_hash = Web3.keccak(text=message)

    for commitment in commitments_list:
        nonce_d_public = __utils.code_to_pub(commitment['public_nonce_d'])
        nonce_e_public = __utils.code_to_pub(commitment['public_nonce_e'])

        row = Web3.solidity_keccak(
            ['string', 'bytes', 'bytes'],
            [hex(commitment['id']),  message_hash,  commitments_hash]
        )

        public_nonce = nonce_d_public + \
            (int.from_bytes(row, 'big') * nonce_e_public)
        if is_first:
            aggregated_public_nonce = public_nonce
            is_first = False
        else:
            aggregated_public_nonce = aggregated_public_nonce + public_nonce
    return aggregated_public_nonce


def aggregate_signatures(message: str, single_signatures: List[Dict[str, int]], aggregated_public_nonce: Point, group_key: int) -> Dict:
    message_hash = Web3.keccak(text=message)
    aggregated_signature = 0
    for sign in single_signatures:
        aggregated_signature = aggregated_signature + sign['signature']
    aggregated_signature = aggregated_signature % __utils.N
    return {'nonce': __utils.pub_to_addr(aggregated_public_nonce), 'public_key': __utils.pub_compress(__utils.code_to_pub(group_key)),
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
            Web3.to_int(hexstr=aggregated_signature['public_key']['x']),
            aggregated_signature['public_key']['y_parity'],
            Web3.to_int(aggregated_signature['message_hash']),
            aggregated_signature['nonce']
        ]
    )

    point = (aggregated_signature['signature'] * __utils.ecurve.G) + (
        int.from_bytes(challenge, 'big') * __utils.pub_decompress(aggregated_signature['public_key']))
    return aggregated_signature['nonce'] == __utils.pub_to_addr(point)

# TODO : exclude complaint

# =======================================================================================
# ================================== Private Functions ==================================
# =======================================================================================


def __single_sign(id: str, share: int, nonce_d: int, nonce_e: int, message: str,
                  commitments_dict: Dict[str, Dict[str, int]], group_key: Point) -> Dict[str, int]:

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
        nonce_d_public = __utils.code_to_pub(commitment['public_nonce_d'])
        nonce_e_public = __utils.code_to_pub(commitment['public_nonce_e'])
        assert __utils.ecurve.is_point_on_curve(
            (nonce_d_public.x, nonce_d_public.y)
        ), f'Nonce D from Node {commitment["id"]} Not on Curve'
        assert __utils.ecurve.is_point_on_curve(
            (nonce_e_public.x, nonce_e_public.y)
        ), f'Nonce E from Node {commitment["id"]} Not on Curve'

        party.append(commitment['id'])

        row = Web3.solidity_keccak(
            ['string', 'bytes', 'bytes'],
            [hex(commitment['id']),  message_hash,  commitments_hash]
        )

        public_nonce = nonce_d_public + \
            (int.from_bytes(row, 'big') * nonce_e_public)
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
            Web3.to_int(hexstr=__utils.pub_compress(
                __utils.code_to_pub(group_key))['x']),
            __utils.pub_compress(__utils.code_to_pub(group_key))['y_parity'],
            Web3.to_int(message_hash),
            __utils.pub_to_addr(aggregated_public_nonce)
        ]
    )

    coef = __utils.langrange_coef(index, len(party), commitments_list, 0)
    signature_share = (nonce_d + nonce_e * int.from_bytes(my_row, 'big') -
                       coef * share * int.from_bytes(challenge, 'big')) % __utils.N
    return {
        'id': id,
        'signature': signature_share,
        'public_key': __utils.pub_to_code(keys.get_public_key(share, __utils.ecurve)),
        'aggregated_public_nonce': __utils.pub_to_code(aggregated_public_nonce)
    }


def __create_complaint(node_id: str, secret_key: int, partner_id: str, partner_public: Point) -> Dict:
    encryption_joint_key = __utils.pub_to_code(secret_key * partner_public)
    public_key = keys.get_public_key(secret_key, __utils.ecurve)
    random_nonce, public_nonce = keys.gen_keypair()
    commitment = random_nonce * partner_public
    complaint_pop_hash = Web3.solidity_keccak(
        [
            'uint8',
            'uint8',
            'uint8',
            'uint8',
            'uint8'
        ],
        [
            __utils.pub_to_code(public_key),
            __utils.pub_to_code(partner_public),
            encryption_joint_key,
            __utils.pub_to_code(public_nonce),
            __utils.pub_to_code(commitment)
        ],
    )
    complaint_pop_sign = __utils.complaint_sign(
        secret_key,
        random_nonce,
        int.from_bytes(complaint_pop_hash, 'big')
    )
    complaint_pop = {
        'public_nonce': __utils.pub_to_code(public_nonce),
        'commitment': __utils.pub_to_code(commitment),
        'signature': complaint_pop_sign
    }

    return {
        'complaintant': node_id,
        'malicious': partner_id,
        'encryption_key': encryption_joint_key,
        'proof': complaint_pop
    }
