from fastecdsa import keys
from hashlib import sha256
import frost_lib;
from . import crypto_utils
from typing import List, Dict, Tuple, Literal
import json, copy

KeyType = Literal ["ed25519", "secp256k1"]

def get_module(name):
	return getattr(frost_lib, name)

class KeyGen:
	dkg_id: str
	key_type: KeyType
	threshold: int
	node_id: str
	node_secret: int
	# convert partners to an object with {id, pubkey, ...}
	partners: list[str]
	partners_pub_keys: dict[str, int]
	malicious: List[str]
	status: str
	 
	round1_result: frost_lib.types.Part1ResultT
	round1_rec_packages: dict[str, frost_lib.types.Part1PackageT]
	round2_result: frost_lib.types.Part2ResultT
	round3_result: frost_lib.types.Part3ResultT
	
	def __init__(
		self,
		dkg_id: str,
		threshold: int,
		node_id: str,
		node_secret: int,
		partners: List[str],
		partners_pub_keys: dict[str, int],
		key_type: KeyType = "secp256k1",
	) -> None:
		self.dkg_id = dkg_id
		self.key_type = key_type
		self.threshold = threshold
		self.node_id = node_id
		self.node_secret = node_secret
		self.partners = partners
		self.partners_pub_keys = partners_pub_keys
		self.malicious = []
		self.status = "STARTED"

	def round1(self) -> Dict:
		f_module = get_module(self.key_type)
		self.round1_result = f_module.dkg_part1(
			self.node_id,
			len(self.partners),
			self.threshold,
		)

		# # TODO: just for dkg malicious detection test. remove it =========
		# if self.node_id == "3":
		# 	print("========================= Malignant Behaviour ===============================")
		# 	self.round1_result["package"]["proof_of_knowledge"] = self.round1_result["package"]["proof_of_knowledge"][:-1] + "0"
		# # ================================================================

		self.status = "ROUND1"
		return self.round1_result["package"]

	def round2(self, round1_packages: dict[str, frost_lib.types.Part1PackageT]) -> list[dict]:
		f_module = get_module(self.key_type);
		
		# store for later use
		self.round1_rec_packages = round1_packages;

		# convert normal id into frost ID
		rec_pkgs = {}
		for id in self.partners:
			if id == self.node_id:
				continue;
			rec_pkgs[id] = round1_packages[id]

		# call round 2
		self.round2_result = get_module(self.key_type).dkg_part2(self.round1_result["secret_package"], rec_pkgs)
		result_data = {};
		for id in self.partners:
			if id == self.node_id:
				continue;
			
			# # TODO: just for dkg malicious detection test. remove it =========
			# if self.node_id == "3" and id == "1":
			# 	print("========================= Malignant Behaviour ===============================")
			# 	self.round2_result["packages"][id]["signing_share"] = self.round2_result["packages"][id]["signing_share"][:-1] + "0"
			# # ================================================================

			result_data[id] = crypto_utils.encrypt_with_joint_key(
				json.dumps(self.round2_result["packages"][id], sort_keys=True),
				self.node_secret,
				self.partners_pub_keys[id]
			)
		self.status = "ROUND2"
		return result_data

	def round3(self, round2_packages) -> Dict:				
		# call native DKG part3
		self.round3_result = get_module(self.key_type).dkg_part3(
			   self.round2_result["secret_package"],
			   self.round1_rec_packages,
			   round2_packages
		)
		
		result = {
			"key_package": self.round3_result["key_package"],
			"pubkey_package": self.round3_result["pubkey_package"],
			"key_type": self.key_type,
			"status": "SUCCESSFUL",
		}
		self.status = "COMPLETED"
		return result
	

def verify_proof_of_knowledge(key_type: KeyType, id, commitments, signature):
	return get_module(key_type).verify_proof_of_knowledge(
		id, 
		commitments, 
		signature
	)

def verify_dkg_secret_share(key_type: KeyType, id, secret_share, commitment):
	return get_module(key_type).dkg_verify_secret_share(
		id, 
		secret_share, 
		commitment
	);

def make_signature_share(
		key_type: KeyType,
		message: str,
		nonces_commitments: dict,
		nonce,
		key_package
):
	frost_module = get_module(key_type)
	
	signing_package = frost_module.signing_package_new(nonces_commitments, message);

	return frost_module.round2_sign(
			signing_package,
			nonce,
			key_package
		)

def verify_signature_share(
	key_type: KeyType, 
	node_id: str, 
	message: bytes, 
	signature_share: str, 
	commitments_map: dict[int, str], 
	pubkey_package
) -> bool:
	module = get_module(key_type)

	signing_package = module.signing_package_new(commitments_map, message);

	return module.verify_share(
		node_id, 
		pubkey_package["verifying_shares"][node_id], 
		signature_share, 
		signing_package, 
		pubkey_package["verifying_key"]
	)

def create_nonces(
	key_type: KeyType,
	dkg_signing_share: str, 
	number_of_nonces: int = 10
) -> Tuple[List[Dict], List[Dict]]:
	module = get_module(key_type);

	nonces, commitments = [], []

	for _ in range(number_of_nonces):
		result = module.round1_commit(dkg_signing_share)
		nonces.append(result["nonces"])
		commitments.append(result["commitments"])

	return nonces, commitments

def aggregate(key_type, message, commitments_map: dict, signature_shares: dict, pubkey_package: dict):
	module = get_module(key_type)
	
	signing_package = module.signing_package_new(
		commitments_map, 
		message
	);
	
	return module.aggregate(
		signing_package, 
		signature_shares, 
		pubkey_package
	)

def verify_group_signature(key_type, group_signature, message, pubkey_package):
	return get_module(key_type).verify_group_signature(group_signature, message, pubkey_package)
