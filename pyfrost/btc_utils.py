from hashlib import sha256
from typing import Dict

from bitcoinutils.schnorr import has_even_y
from eth_abi.packed import encode_packed
from fastecdsa.point import Point

from pyfrost.crypto_utils import pub_to_addr, lagrange_coef, N, code_to_pub, ecurve, pub_decompress, int_from_bytes, \
    tagged_hash, bytes_from_int, calculate_tweak, taproot_tweak_pubkey, lift_x


def btc_challenge(public_key_bytes, message_hex: str, aggregated_public_nonce: Point) -> bytes:
    R = aggregated_public_nonce
    challenge = (
            int_from_bytes(
                tagged_hash(
                    "BIP0340/challenge",
                    bytes_from_int(R.x) + public_key_bytes + bytes.fromhex(message_hex),
                )
            )
            % ecurve.q
    )
    return challenge

def calculate_tweaked(share, group_key_pub):
    byte_pub_x = bytes.fromhex(group_key_pub["x"].replace("0x", ""))
    tweak_int = calculate_tweak(byte_pub_x)
    tweaked_share = share + tweak_int
    Q, tweaked_pubkey = taproot_tweak_pubkey(byte_pub_x, b"")
    if not Q.y % 2 == 0:
        tweaked_share = ecurve.q - tweaked_share

    return tweaked_share, tweaked_pubkey


def btc_generate_signature_share(tweaked_share, coef, challenge, aggregated_public_nonce, nonce_d, nonce_e, row):
    k0 = (nonce_d + nonce_e * int.from_bytes(row, "big")) % ecurve.q
    k = ecurve.q - k0 if aggregated_public_nonce.y % 2 == 1 else k0
    signature_share = (k + coef * tweaked_share * challenge) % ecurve.q
    return signature_share


def btc_verify_single_sign(coef, challenge, public_nonce, signature_data):
    point1 = public_nonce + \
             (challenge * coef * code_to_pub(signature_data["public_key_share"]))

    point2 = signature_data["single_signature"]["signature"] * ecurve.G
    return point1 == point2


def _schnorr_verify(msg: bytes, pubkey: bytes, sig: bytes) -> bool:
    if len(msg) != 32:
        raise ValueError("The message must be a 32-byte array.")
    if len(pubkey) != 32:
        raise ValueError("The public key must be a 32-byte array.")
    if len(sig) != 64:
        raise ValueError("The signature must be a 64-byte array.")
    P = lift_x(int_from_bytes(pubkey))
    r = int_from_bytes(sig[0:32])
    s = int_from_bytes(sig[32:64])
    if (P is None) or (r >= ecurve.p) or (s >= ecurve.q):
        return False
    e = int_from_bytes(tagged_hash("BIP0340/challenge", sig[0:32] + pubkey + msg)) % ecurve.q
    R = ecurve.G * s - P * e

    if (R is None) or (not has_even_y(R)) or (R.x != r):
        return False
    return True

def btc_verify_group_signature(aggregated_signature: Dict) -> bool:
    Q, tweaked_pubkey = taproot_tweak_pubkey(aggregated_signature["public_key"], b"")

    return _schnorr_verify(
        aggregated_signature["message_hash"],
        tweaked_pubkey,
        bytes_from_int(aggregated_signature["public_nonce"].x) + bytes_from_int(aggregated_signature["signature"]))
