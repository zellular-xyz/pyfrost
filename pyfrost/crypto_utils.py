from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from fastecdsa.encoding.sec1 import SEC1Encoder
from fastecdsa import keys, curve
from fastecdsa.curve import Curve
from fastecdsa.point import Point
from typing import Dict
import frost_lib
import json, base64

ecurve: Curve = curve.secp256k1

def get_frost(curve: frost_lib.types.CurveType) -> frost_lib.CryptoModule:
	return getattr(frost_lib, curve)

def pub_to_code(public_key: Point) -> int:
    comp_pub = SEC1Encoder.encode_public_key(public_key, True)
    return int(comp_pub.hex(), 16)


def code_to_pub(key: int) -> Point:
    key_byte = bytes.fromhex(hex(key).replace("x", ""))
    return SEC1Encoder.decode_public_key(key_byte, ecurve)


def private_to_point(private_key: int) -> Point:
    return keys.get_public_key(private_key, ecurve)


def pub_compress(public_key: Point) -> Dict:
    coded = SEC1Encoder.encode_public_key(public_key, True)
    x = "0x" + coded.hex()[2:]
    y = int(coded.hex()[1]) - 2
    return {"x": x, "y_parity": y}

def pub_decompress(pub_dict: Dict) -> Point:
    x = pub_dict["x"]
    y = pub_dict["y_parity"] + 2
    coded = "0" + str(y) + x[2:]
    publicKey = SEC1Encoder.decode_public_key(bytes.fromhex(coded), ecurve)
    return publicKey

def generate_random_private() -> int:
    return keys.gen_private_key(ecurve)

def generate_hkdf_key(key: int) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"",
        info=b"",
        backend=default_backend(),
    )
    return hkdf.derive(bytes.fromhex(str(key)))

def encrypt(data: str, key: bytes) -> str:
    if not isinstance(data, str):
        data = json.dumps(data)
    key = base64.b64encode(key)
    fernet = Fernet(key)
    return fernet.encrypt(data.encode()).decode(encoding="utf-8")

def decrypt(data: str, key: bytes) -> str:
    data = bytes(data, encoding="utf-8")
    key = base64.b64encode(key)
    fernet = Fernet(key)
    return fernet.decrypt(data).decode()

def encrypt_with_joint_key(data: str, secret: int, receiver_pubkey: str) -> str:
	encryption_joint_key = pub_to_code(
		secret * code_to_pub(receiver_pubkey)
	)
	encryption_key = generate_hkdf_key(encryption_joint_key)
	return encrypt(data, encryption_key)

def decrypt_with_joint_key(data: str, secret: int, sender_pubkey: str) -> str:
	encryption_joint_key = pub_to_code(
		secret * code_to_pub(sender_pubkey)
	)
	encryption_key = generate_hkdf_key(encryption_joint_key)
	return decrypt(data, encryption_key)
