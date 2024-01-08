from fastecdsa import keys, curve
from pyfrost.crypto_utils import pub_to_code
import hashlib

VALIDATED_IPS = {
    '127.0.0.1': ['/v1/dkg/round1', '/v1/dkg/round2', '/v1/dkg/round3', '/v1/sign', '/v1/generate-nonces']
}


def generate_privates_and_nodes_info(number: int = 100):
    first_private = 71940701385098721223324549130922930535689437869965850741649618196713151413648
    nodes_info_dict = {}
    privates_list = []
    previous_key = first_private
    for i in range(number):
        key_bytes = previous_key.to_bytes(32, 'big')
        hashed = hashlib.sha256(key_bytes).digest()
        new_private = int.from_bytes(
            hashed, byteorder='big') % curve.secp256k1.q
        previous_key = new_private
        nodes_info_dict[str(i+1)] = {
            'public_key': pub_to_code(keys.get_public_key(new_private, curve.secp256k1)),
            'host': '127.0.0.1',
            'port': str(5000+i)
        }
        privates_list.append(new_private)
    return privates_list, nodes_info_dict