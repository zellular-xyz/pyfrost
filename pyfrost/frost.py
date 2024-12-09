from fastecdsa import keys
from hashlib import sha256
import frost_lib;
from . import crypto_utils
from typing import List, Dict, Tuple, Literal
import json, copy

KeyType = Literal ["ed25519", "secp256k1"]

def get_module(name):
	return getattr(frost_lib, name)

def id_to_frost(key_type: KeyType, id: str):
	return get_module(key_type).num_to_id(int(id));

def ids_to_frost(key_type: KeyType, ids: list[str]):
	module = get_module(key_type)
	return [module.num_to_id(int(id)) for id in ids]

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
			f_module.num_to_id(int(self.node_id)),
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
			rec_pkgs[f_module.num_to_id(int(id))] = round1_packages[id]

		# call round 2
		self.round2_result = get_module(self.key_type).dkg_part2(self.round1_result["secret_package"], rec_pkgs)
		result_data = {};
		for id in self.partners:
			if id == self.node_id:
				continue;

			frost_id = id_to_frost(self.key_type, id)
			
			# # TODO: just for dkg malicious detection test. remove it =========
			# if self.node_id == "3" and id == "1":
			# 	print("========================= Malignant Behaviour ===============================")
			# 	self.round2_result["packages"][frost_id]["signing_share"] = self.round2_result["packages"][frost_id]["signing_share"][:-1] + "0"
			# # ================================================================

			result_data[id] = crypto_utils.encrypt_with_joint_key(
				json.dumps(self.round2_result["packages"][frost_id], sort_keys=True),
				self.node_secret,
				self.partners_pub_keys[id]
			)
		self.status = "ROUND2"
		return result_data

	def round3(self, round2_packages) -> Dict:
		# convert node id into frost ID
		r2pkgs = {}
		for sender, data in round2_packages.items():
			frost_id = get_module(self.key_type).num_to_id(int(sender));
			r2pkgs[frost_id] = data;
		
		r1_pkgs = copy.deepcopy(self.round1_rec_packages)
		r1_pkgs = keys_to_frost(r1_pkgs, self.key_type)
		
		# call native DKG part3
		self.round3_result = get_module(self.key_type).dkg_part3(
			   self.round2_result["secret_package"],
			   r1_pkgs,
			   r2pkgs
		)

		pubkey_package = {
			"header": self.round3_result["pubkey_package"]["header"],
			"verifying_key": self.round3_result["pubkey_package"]["verifying_key"],
			"verifying_shares": {}
		}
		# convert frost ID to normal id
		for id in self.partners:
			frost_id = id_to_frost(self.key_type, id)
			pubkey_package["verifying_shares"][id] = self.round3_result["pubkey_package"]["verifying_shares"][frost_id]
		
		result = {
			"key_package": self.round3_result["key_package"],
			"pubkey_package": pubkey_package,
			"key_type": self.key_type,
			"status": "SUCCESSFUL",
		}
		self.status = "COMPLETED"
		return result


def keys_to_frost(data: dict, crypto_module_type: KeyType) -> dict:
	result = {}
	for id in list(data.keys()):
		result[id_to_frost(crypto_module_type, id)] = copy.deepcopy(data[id])
	return result;

def verify_proof_of_knowledge(key_type: KeyType, id, commitments, signature):
	return get_module(key_type).verify_proof_of_knowledge(
		id_to_frost(key_type, id), 
		commitments, 
		signature
	)

def verify_dkg_secret_share(key_type: KeyType, id, secret_share, commitment):
	return get_module(key_type).dkg_verify_secret_share(
		id_to_frost(key_type, id), 
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
	# convert normal ID into FrostID
	party = list(nonces_commitments.keys())
	commitments_map = {}
	for id in party:
		frost_id = id_to_frost(key_type, id);
		commitments_map[frost_id] = nonces_commitments[id];
	
	signing_package = frost_module.signing_package_new(commitments_map, message);

	return frost_module.round2_sign(
			signing_package,
			nonce,
			key_package
		)

def verify_signature_share(
	key_type: KeyType, 
	node_id: int, 
	message: bytes, 
	signature_share: str, 
	nonces_commitments: dict[int, str], 
	pubkey_package
) -> bool:
	module = get_module(key_type)
	identifier = id_to_frost(key_type, node_id)

	commitments_map = {}
	for id in list(nonces_commitments.keys()):
		commitments_map[id_to_frost(key_type, id)] = nonces_commitments[id];

	signing_package = module.signing_package_new(commitments_map, message);

	return module.verify_share(
		identifier, 
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
		keys_to_frost(commitments_map, key_type), 
		message
	);

	signature_shares = keys_to_frost(signature_shares, key_type)

	pubkey_package = copy.deepcopy(pubkey_package)
	pubkey_package["verifying_shares"] = keys_to_frost(pubkey_package["verifying_shares"], key_type)
	
	return module.aggregate(
		signing_package, 
		signature_shares, 
		pubkey_package
	)

def verify_group_signature(key_type, group_signature, message, pubkey_package):
	pubkey_package = copy.deepcopy(pubkey_package);
	pubkey_package["verifying_shares"] = keys_to_frost(pubkey_package["verifying_shares"], key_type);
	return get_module(key_type).verify_group_signature(group_signature, message, pubkey_package)
