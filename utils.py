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


class Utils:

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
        return SEC1Encoder.decode_public_key(key_byte , Utils.ecurve)

    @staticmethod
    def private_to_point(private_key: int) -> Point:
        return keys.get_public_key(private_key, Utils.ecurve)

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
        publicKey = SEC1Encoder.decode_public_key(bytes.fromhex(coded) , Utils.ecurve)
        return publicKey

    @staticmethod
    def calc_poly_point(polynomial: List[Point], x: int) -> Point:
        x = int(x)
        coefs = []
        for i in range(len(polynomial)):
            coefs.append(pow(x, i) % Utils.N)
        result = coefs[0] * polynomial[0]
        for i in range(1, len(polynomial)):
            result = result + coefs[i] * polynomial[i]
        return result

    @staticmethod
    def generate_random_private() -> int:
        return keys.gen_private_key(Utils.ecurve)

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
        return Utils.mod_inverse(denum, Utils.N) * num

    @staticmethod
    def reconstruct_share(shares: List[Dict], threshold: int, x: int) -> int:
        assert len(shares) == threshold, 'Number of shares must be t.'
        sum = 0
        for j in range(threshold):
            coef = Utils.langrange_coef(j, threshold, shares, x)
            key = shares[j]['key']
            sum = (sum + (key * coef % Utils.N)) % Utils.N
        return sum % Utils.N

    @staticmethod
    def schnorr_hash(public_key: Point, message: int) -> str:
        address = Utils.pub_to_addr(public_key)
        addressBuff = str(address)[2:]
        msgBuff = str(hex(message))[2:]
        totalBuff = addressBuff + msgBuff
        return Web3.keccak(int(totalBuff, 16))

    @staticmethod
    def schnorr_sign(shared_private_key: int, nounce_private: int, nounce_public: Point, message: int) -> Dict[str, int]:
        e = int.from_bytes(Utils.schnorr_hash(nounce_public, message), 'big')
        s = (nounce_private - e * shared_private_key) % Utils.N
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
            signature = Utils.split_signature(signature)
        if type(message) != int:
            message = int(message)
        assert signature['s'] < Utils.N, 'Signature must be reduced modulo N'
        r_v = (signature['s']* Utils.ecurve.G) + (signature['e'] * public_key)
        e_v = Utils.schnorr_hash(r_v, message)
        return int.from_bytes(e_v, 'big') == signature['e']

    @staticmethod
    def schnorr_aggregate_signatures(threshold: int, signatures: List[Dict[str, int]], party: List[str]) -> Dict[str, int]:
        assert len(signatures) >= threshold, 'At least t signatures are needed'
        aggregated_signature = 0

        for j in range(threshold):
            coef = Utils.langrange_coef(
                j, threshold, [{'id': i} for i in party], 0)
            aggregated_signature += signatures[j]['s'] * coef
        s = aggregated_signature % Utils.N
        e = signatures[0]['e']
        return {'s': s, 'e': e}

    
    @staticmethod
    def complaint_sign(private_key : int , nonce : int , hash : int):
        return (nonce + private_key * hash) % Utils.N 
    
    @staticmethod
    def complaint_verify(public_complaintant : Point, public_malicious : Point , encryption_key : Point , proof , hash : int):
        public_nonce = proof['public_nonce']
        public_commitment = proof['commitment']
        signature = proof['signature']
        
        point1 = public_nonce + (hash * public_complaintant)
        point2 = signature * Utils.ecurve.G
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
