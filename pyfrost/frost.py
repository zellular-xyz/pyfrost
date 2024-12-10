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


