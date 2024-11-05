from hashlib import sha256
from typing import Dict

from eth_abi.packed import encode_packed
from fastecdsa.point import Point

from pyfrost.crypto_utils import (
    pub_to_addr,
    N,
    code_to_pub,
    ecurve,
    pub_decompress,
)


def eth_challenge(
    group_pub_key: Dict, message_hex: str, aggregated_nonce: str | Point
) -> bytes:
    if isinstance(aggregated_nonce, Point):
        aggregated_nonce = pub_to_addr(aggregated_nonce)
    packed_data = encode_packed(
        ["bytes32", "uint8", "bytes32", "address"],
        [
            bytes.fromhex(group_pub_key["x"].replace("0x", "")),
            group_pub_key["y_parity"],
            bytes.fromhex(message_hex),
            aggregated_nonce,
        ],
    )
    return sha256(packed_data).digest()


def eth_generate_signature_share(share, coef, challenge, nonce_d, nonce_e, row):
    signature_share = (
        nonce_d
        + nonce_e * int.from_bytes(row, "big")
        - coef * share * int.from_bytes(challenge, "big")
    ) % N
    return signature_share


def eth_verify_single_sign(coef, challenge, public_nonce, signature_data):
    challenge_int = int.from_bytes(challenge, "big")
    point1 = public_nonce - (
        challenge_int * coef * code_to_pub(signature_data["public_key_share"])
    )
    point2 = signature_data["single_signature"]["signature"] * ecurve.G
    return point1 == point2


def eth_verify_group_sign(group_pub_key, message, aggregated_signature):
    challenge = eth_challenge(
        group_pub_key, message, aggregated_signature["nonce"]
    )
    challenge_int = int.from_bytes(challenge, "big")
    # Calculate the point
    point = (aggregated_signature["signature"] * ecurve.G) + (
        challenge_int * pub_decompress(aggregated_signature["public_key"])
    )
    return aggregated_signature["nonce"] == pub_to_addr(point)
