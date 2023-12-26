from pyfrost.network.libp2p_base import PROTOCOLS_ID
from libp2p.crypto.secp256k1 import create_new_key_pair
from libp2p.peer.id import ID as PeerID
import random


# SA and Dkg configuration:
PRIVATE = 'c915ec16580f7217e24e06cbff8a6b92ceea0cffae3ce74e8e797f57e0f3f66d'
PEER_INFO = {
    "ip": "0.0.0.0",
    "port": "7000",
    'public_key': '080212210338fede176f44704dc4fdcdace7c35108a126d8b77ad33ee7af09c0e18d56376a'
}


# Node configuration:
VALIDATED_CALLERS = {
    '16Uiu2HAmGVUb3nZ3yaKNpt5kH7KZccKrPaHmG1qTB48QvLdr7igH': [PROTOCOLS_ID['round1'], PROTOCOLS_ID['round2'], PROTOCOLS_ID['round3'], PROTOCOLS_ID['generate_nonces'], PROTOCOLS_ID['sign']]
}


def generate_secrets_and_node_info():
    first_secret = b'\x91\x82\xc5\xa1\xcaK\xf1\xf3\xa2"{!\x93%#\x91\xd1`k|\xa8\xa2\r\xc7\xb9.\xb2\xaa>\xf3}\xa3'
    node_info_dict = {}
    secrets_dict = {}
    last_peer_id = ''
    for i in range(1, 100):
        if len(node_info_dict) == 0:
            row_hash = first_secret
        else:
            row_hash = secrets_dict[last_peer_id].encode()
        random.seed(int.from_bytes(row_hash, 'big'))
        secret_number = random.getrandbits(32 * 8)
        new_secret = secret_number.to_bytes(length=32, byteorder="big")

        key_pair = create_new_key_pair(new_secret)
        peer_id: PeerID = PeerID.from_pubkey(key_pair.public_key)
        last_peer_id = peer_id.to_base58()
        node_info_dict[str(i)] = {
            last_peer_id: {'public_key': key_pair.public_key.serialize().hex(),
                           'ip': '127.0.0.1',
                           'port': str(5000+i)}
        }
        secrets_dict[last_peer_id] = new_secret.hex()
    return node_info_dict, secrets_dict
