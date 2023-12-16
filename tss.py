from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

from fastecdsa.encoding.sec1 import SEC1Encoder
from fastecdsa import keys , curve
from fastecdsa.curve import Curve
from fastecdsa.point import Point
from typing import List, Dict
from web3 import Web3

import math
import json
import base64


class TSS:

    ecurve: Curve = curve.secp256k1
    N: int = ecurve.q
    Half_N: int = ((N >> 1) % N + 1) % N

    @staticmethod
    def mod_inverse(number: int, modulus: int) -> int:
        original_modulus = modulus
        inverse = 1
        intermediate = 0
        number = number % modulus

        if modulus == 1:
            return 0

        while number > 1:
            quotient = number // modulus
            temp = modulus
            modulus = number % modulus
            number = temp
            temp = intermediate
            intermediate = inverse - quotient * intermediate
            inverse = temp

        if inverse < 0:
            inverse += original_modulus

        return inverse

    @staticmethod
    def pub_to_addr(public_key: Point) -> str:
        pub_key_hex = str(hex(public_key.x))[
            2:] + str(hex(public_key.y))[2:]
        pub_hash = Web3.keccak(int(pub_key_hex, 16))
        return Web3.to_checksum_address('0x'+str(pub_hash.hex())[-40:])

    @staticmethod
    def pub_to_code(public_key: Point) -> int:
        comp_pub = SEC1Encoder.encode_public_key(public_key , True)
        return int(comp_pub.hex(), 16)

    @staticmethod
    def code_to_pub(key: int) -> Point:
        key_byte = bytes.fromhex(hex(key).replace('x', ''))
        return SEC1Encoder.decode_public_key(key_byte , TSS.ecurve)

    @staticmethod
    def private_to_point(private_key: int) -> Point:
        return keys.get_public_key(private_key, TSS.ecurve)

    @staticmethod
    def pub_compress(public_key: Point) -> Dict:
        coded = SEC1Encoder.encode_public_key(public_key , True)
        x = '0x' + coded.hex()[2:]
        y = int(coded.hex()[1]) - 2 
        return {'x': x, 'y_parity': y}

    @staticmethod
    def pub_decompress(pub_dict: Dict) -> Point:
        x = pub_dict['x']
        y = pub_dict['y_parity'] + 2
        coded = '0' + str(y) + x[2:]
        publicKey = SEC1Encoder.decode_public_key(bytes.fromhex(coded) , TSS.ecurve)
        return publicKey

    @staticmethod
    def calc_poly_point(polynomial: List[Point], x: int) -> Point:
        x = int(x)
        coefs = []
        for i in range(len(polynomial)):
            coefs.append(pow(x, i) % TSS.N)
        result = coefs[0] * polynomial[0]
        for i in range(1, len(polynomial)):
            result = result + coefs[i] * polynomial[i]
        return result

    @staticmethod
    def generate_random_private() -> int:
        return keys.gen_private_key(TSS.ecurve)

    @staticmethod
    def langrange_coef(index: int, threshold: int, shares: List[Dict], x: int) -> int:
        x_j = int(shares[index]['id'])
        nums = []
        denums = []
        for k in list(filter(lambda i: i != index, range(0, threshold))):
            x_k = int(shares[k]['id'])
            nums.append(x - x_k)
            denums.append(x_j - x_k)
        num = math.prod(nums)
        denum = math.prod(denums)
        return TSS.mod_inverse(denum, TSS.N) * num

    @staticmethod
    def reconstruct_share(shares: List[Dict], threshold: int, x: int) -> int:
        assert len(shares) == threshold, 'Number of shares must be t.'
        sum = 0
        for j in range(threshold):
            coef = TSS.langrange_coef(j, threshold, shares, x)
            key = shares[j]['key']
            sum = (sum + (key * coef % TSS.N)) % TSS.N
        return sum % TSS.N

    @staticmethod
    def schnorr_hash(public_key: Point, message: int) -> str:
        address = TSS.pub_to_addr(public_key)
        addressBuff = str(address)[2:]
        msgBuff = str(hex(message))[2:]
        totalBuff = addressBuff + msgBuff
        return Web3.keccak(int(totalBuff, 16))

    @staticmethod
    def schnorr_sign(shared_private_key: int, nounce_private: int, nounce_public: Point, message: int) -> Dict[str, int]:
        e = int.from_bytes(TSS.schnorr_hash(nounce_public, message), 'big')
        s = (nounce_private - e * shared_private_key) % TSS.N
        return {'s': s, 'e': e}

    @staticmethod
    def stringify_signature(signature: Dict[str, int]) -> str:
        S = f'{hex(signature["s"])[2:]:0>64}'
        E = f'{hex(signature["e"])[2:]:0>64}'
        return '0x' + E + S

    @staticmethod
    def split_signature(string_signature: str) -> Dict[str, int]:
        raw_bytes = string_signature[2:]
        assert len(raw_bytes) == 128, 'Invalid schnorr signature string'
        e = '0x' + raw_bytes[0:64]
        s = '0x' + raw_bytes[64:]
        return {'s': int(s, 16), 'e': int(e, 16)}

    @staticmethod
    def schnorr_verify(public_key: Point, message: str, signature: str) -> bool:
        if type(signature) == str:
            signature = TSS.split_signature(signature)
        if type(message) != int:
            message = int(message)
        assert signature['s'] < TSS.N, 'Signature must be reduced modulo N'
        r_v = (signature['s']* TSS.ecurve.G) + (signature['e'] * public_key)
        e_v = TSS.schnorr_hash(r_v, message)
        return int.from_bytes(e_v, 'big') == signature['e']

    @staticmethod
    def schnorr_aggregate_signatures(threshold: int, signatures: List[Dict[str, int]], party: List[str]) -> Dict[str, int]:
        assert len(signatures) >= threshold, 'At least t signatures are needed'
        aggregated_signature = 0

        for j in range(threshold):
            coef = TSS.langrange_coef(
                j, threshold, [{'id': i} for i in party], 0)
            aggregated_signature += signatures[j]['s'] * coef
        s = aggregated_signature % TSS.N
        e = signatures[0]['e']
        return {'s': s, 'e': e}

    @staticmethod
    def frost_single_sign(id: str, share: int, nonce_d: int, nonce_e: int, message: str,
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
            nonce_d_public = TSS.code_to_pub(commitment['public_nonce_d'])
            nonce_e_public = TSS.code_to_pub(commitment['public_nonce_e'])
            assert TSS.ecurve.is_point_on_curve(
                (nonce_d_public.x, nonce_d_public.y)
                ), f'Nonce D from Node {commitment["id"]} Not on Curve'
            assert TSS.ecurve.is_point_on_curve(
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
                Web3.to_int(hexstr= TSS.pub_compress(TSS.code_to_pub(group_key))['x']),
                TSS.pub_compress(TSS.code_to_pub(group_key))['y_parity'],
                Web3.to_int(message_hash),
                TSS.pub_to_addr(aggregated_public_nonce)
            ]
        )

        coef = TSS.langrange_coef(index, len(party), commitments_list, 0)
        signature_share = (nonce_d + nonce_e * int.from_bytes(my_row, 'big') -
                           coef * share * int.from_bytes(challenge, 'big')) % TSS.N
        return {
            'id': id, 
            'signature': signature_share, 
            'public_key': TSS.pub_to_code(keys.get_public_key(share , TSS.ecurve)),
            'aggregated_public_nonce': TSS.pub_to_code(aggregated_public_nonce)
            }

    @staticmethod
    def frost_verify_single_signature(id: int, message: str, commitments_dict: Dict[str, Dict[str, int]], aggregated_public_nonce: Point,
                                      public_key_share: int, single_signature: Dict[str, int], group_key: Point) -> bool:

        index = 0
        public_nonce = None
        commitments_list = list(commitments_dict.values())
        commitments_hash = Web3.keccak(text=json.dumps(commitments_list))
        message_hash = Web3.keccak(text=message)

        for commitment in commitments_list:
            if commitment['id'] == id:
                nonce_d_public = TSS.code_to_pub(commitment['public_nonce_d'])
                nonce_e_public = TSS.code_to_pub(commitment['public_nonce_e'])
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
                Web3.to_int(hexstr=TSS.pub_compress(TSS.code_to_pub(group_key))['x']),
                TSS.pub_compress(TSS.code_to_pub(group_key))['y_parity'],
                Web3.to_int(message_hash),
                TSS.pub_to_addr(aggregated_public_nonce)
            ]
        )

        coef = TSS.langrange_coef(index, len(commitments_list), commitments_list, 0)

        point1 = public_nonce - (int.from_bytes(challenge, 'big')* coef * TSS.code_to_pub(public_key_share))
        point2 = single_signature['signature'] * TSS.ecurve.G

        return point1 == point2

    @staticmethod
    def frost_aggregate_nonce(message: str, commitments_dict: Dict[str, Dict[str, int]], group_key: Point):
        aggregated_public_nonce = None
        is_first = True
        commitments_list = list(commitments_dict.values())
        commitments_hash = Web3.keccak(text=json.dumps(commitments_list))
        message_hash = Web3.keccak(text=message)

        for commitment in commitments_list:
            nonce_d_public = TSS.code_to_pub(commitment['public_nonce_d'])
            nonce_e_public = TSS.code_to_pub(commitment['public_nonce_e'])

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
    
    @staticmethod
    def frost_aggregate_signatures(message: str, single_signatures: List[Dict[str, int]], aggregated_public_nonce : Point, group_key: Point) -> Dict:
        message_hash = Web3.keccak(text=message)
        aggregated_signature = 0
        for sign in single_signatures:
            aggregated_signature = aggregated_signature + sign['signature']
        aggregated_signature = aggregated_signature % TSS.N
        return {'nonce': TSS.pub_to_addr(aggregated_public_nonce), 'public_key': TSS.pub_compress(TSS.code_to_pub(group_key)),
                'signature': aggregated_signature, 'message_hash': message_hash}

    @staticmethod
    def frost_verify_group_signature(aggregated_signature: Dict) -> bool:

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

        point = (aggregated_signature['signature'] * TSS.ecurve.G) + (
            int.from_bytes(challenge, 'big') * TSS.pub_decompress(aggregated_signature['public_key']))
        return aggregated_signature['nonce'] == TSS.pub_to_addr(point)
    @staticmethod
    def complaint_sign(private_key : int , nonce : int , hash : int):
        return (nonce + private_key * hash) % TSS.N 
    
    @staticmethod
    def complaint_verify(public_complaintant : Point, public_malicious : Point , encryption_key : Point , proof , hash : int):
        public_nonce = proof['public_nonce']
        public_commitment = proof['commitment']
        signature = proof['signature']
        
        point1 = public_nonce + (hash * public_complaintant)
        point2 = signature * TSS.ecurve.G
        verification1 = (point1 == point2)
        
        point1 = public_commitment + (hash * encryption_key)
        point2 = signature * public_malicious
        verification2 = (point1 == point2)
        
        return verification1 and verification2
    

    @staticmethod
    def generate_hkdf_key(key: int) -> bytes:
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32,
                    salt=b'', info=b'', backend=default_backend())
        return hkdf.derive(bytes.fromhex(str(key)))

    @staticmethod
    def encrypt(data: str, key: bytes) -> str:
        if type(data) != str:
            data = json.dumps(data)
        key = base64.b64encode(key)
        fernet = Fernet(key)
        return fernet.encrypt(data.encode()).decode(encoding='utf-8')

    @staticmethod
    def decrypt(data: str, key: bytes) -> str:
        data = bytes(data, encoding='utf-8')
        key = base64.b64encode(key)
        fernet = Fernet(key)
        return fernet.decrypt(data).decode()
