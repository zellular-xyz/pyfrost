import logging
from fastecdsa import keys
from web3 import Web3
from polynomial import Polynomial
from utils import Utils, Point
from typing import List, Dict
import __init__
import json


class DistributedKey:
    def __init__(self, dkg_id: str, threshold: int, n: int, node_id: str, partners: List[str], coefficient0: str = None) -> None:
        self.threshold: int = threshold
        self.n: int = n
        self.dkg_id: str = dkg_id
        self.node_id: str = node_id
        self.partners: List[str] = partners
        self.coefficient0 = coefficient0
        self.malicious: List = []
        self.status = 'STARTED'
    
    def round1(self) -> List[Dict]:
        secret_key, public_key =  keys.gen_keypair(Utils.ecurve)
        secret_nonce, public_nonce =  keys.gen_keypair(Utils.ecurve)
        secret_pop_hash = Web3.solidity_keccak(
            [
                'string',
                'string',
                'uint8',
                'uint8'
            ],
            [
                self.node_id,
                self.dkg_id,
                Utils.pub_to_code(public_key),
                Utils.pub_to_code(public_nonce)
            ],
        )

        secret_pop_sign = Utils.schnorr_sign(
            secret_key, secret_nonce, public_nonce, int.from_bytes(
                secret_pop_hash, 'big')
        )

        secret_signature = {
            'nonce': Utils.pub_to_code(public_nonce),
            'signature': Utils.stringify_signature(secret_pop_sign),
        }

        # Generate DKG polynomial
        fx = Polynomial(self.threshold, Utils.ecurve, self.coefficient0)
        public_fx = fx.coef_pub_keys()
        
        coef0_nonce, public_coef0_nonce = keys.gen_keypair(Utils.ecurve)
        coef0_pop_hash = Web3.solidity_keccak(
            [
                'string', 
                'string', 
                'uint8', 
                'uint8'
                ],
            [
                self.node_id, 
                self.dkg_id, 
                Utils.pub_to_code(public_fx[0]), 
                Utils.pub_to_code(public_coef0_nonce)
                ],
        )
        coef0_pop_sign = Utils.schnorr_sign(
            fx.coefficients[0], coef0_nonce, public_coef0_nonce, int.from_bytes(coef0_pop_hash, 'big')
        )

        coef0_signature = {
            'nonce': Utils.pub_to_code(public_coef0_nonce),
            'signature': Utils.stringify_signature(coef0_pop_sign),
        }

        broadcast = {
            'sender_id': self.node_id,
            'public_fx': [Utils.pub_to_code(s) for s in public_fx],
            'coefficient0_signature': coef0_signature,
            'public_key': Utils.pub_to_code(public_key),
            'secret_signature': secret_signature
        }

        save_data = {
            'dkg_id' : self.dkg_id,
            'data' : {
                'secret_key' : secret_key,
                'fx' : fx,
                'public_fx' : public_fx,
                'coef0_signature' : coef0_signature
            }
        }
        
        return broadcast , save_data

    def round2(self, round1_broadcasted_data , dkg_saved_data) -> List[Dict]:
        
        fx: Polynomial = dkg_saved_data['fx']
        partners_public_keys = {}
        secret_key = dkg_saved_data['secret_key']
        for data in round1_broadcasted_data:
            sender_id = data['sender_id']

            if sender_id == self.node_id:
                continue

            sender_public_fx = data['public_fx']
            sender_coef0_nonce = data['coefficient0_signature']['nonce']
            sender_coef0_signature = data['coefficient0_signature']['signature']

            coef0_pop_hash = Web3.solidity_keccak(
                ['string',  'string',       'uint8',                'uint8'],
                [sender_id, self.dkg_id,    sender_public_fx[0],    sender_coef0_nonce]
            )

            coef0_verification = Utils.schnorr_verify(
                Utils.code_to_pub(sender_public_fx[0]), 
                int.from_bytes(coef0_pop_hash, 'big'), 
                sender_coef0_signature
            )
        
            sender_public_key = data['public_key']
            sender_secret_nonce = data['secret_signature']['nonce']
            sender_secret_signature = data['secret_signature']['signature']

            secret_pop_hash = Web3.solidity_keccak(
                ['string',  'string',   'uint8',            'uint8'],
                [sender_id, self.dkg_id, sender_public_key, sender_secret_nonce]
            )

            secret_verification = Utils.schnorr_verify(
                Utils.code_to_pub(sender_public_key), 
                int.from_bytes(secret_pop_hash, 'big'), 
                sender_secret_signature
            )

            # TODO: add these checking in gateway in addition to nodes
            if not secret_verification or not coef0_verification:
                # TODO: how to handle complaint
                self.malicious.append({'id': sender_id, 'complaint': data})
            partners_public_keys[sender_id] = sender_public_key
          
        qualified = self.partners
        for node in self.malicious:
            try:
                qualified.remove(node['id'])
            except:
                pass
        send = []
        for id in qualified:
            encryption_joint_key = Utils.pub_to_code(
                secret_key * Utils.code_to_pub(partners_public_keys[id]))
            encryption_key = Utils.generate_hkdf_key(encryption_joint_key)
            id_as_int = int(id)
            data = {
                'receiver_id': id,
                'sender_id': self.node_id,
                'data': Utils.encrypt(
                    {'receiver_id': id, 'f': fx.evaluate(id_as_int)},
                    encryption_key
                )
            }
            send.append(data)
        
        save_data = {
            'dkg_id' : self.dkg_id,
            'data' : {
                'partners_public_keys' : partners_public_keys
            }
        }
        
        return send , save_data

    def round3(self, round1_broadcasted_data, round2_encrypted_data , dkg_saved_data) -> Dict:
        secret_key = dkg_saved_data['secret_key']
        partners_public_keys = dkg_saved_data['partners_public_keys']
        round2_data = []
        complaints = []
        for message in round2_encrypted_data:
            sender_id = message['sender_id']
            receiver_id = message['receiver_id']
            encrypted_data = message['data']
            encryption_joint_key = Utils.pub_to_code(
                secret_key * Utils.code_to_pub(partners_public_keys[sender_id]))
            encryption_key = Utils.generate_hkdf_key(encryption_joint_key)
            
            assert receiver_id == self.node_id, 'ERROR: receiver_id does not match.'
            data = json.loads(Utils.decrypt(encrypted_data, encryption_key))
            round2_data.append(data)
            for round1_data in round1_broadcasted_data:
                if round1_data['sender_id'] == sender_id:
                    public_fx = round1_data['public_fx']

                    point1 = Utils.calc_poly_point(
                        list(map(Utils.code_to_pub, public_fx)),
                        int(self.node_id)
                    )
                    
                    point2 = data['f'] * Utils.ecurve.G
               
                    if point1 != point2:
                        complaints.append(
                            self.complain(
                                secret_key, 
                                sender_id, 
                                partners_public_keys[sender_id]
                                )
                            )
                        
        if len(complaints) > 0:
            return {'status' : 'COMPLAINT' , 'data' : complaints}
                
        fx: Polynomial = dkg_saved_data['fx']
        my_fragment = fx.evaluate(int(self.node_id))
        share_fragments = [my_fragment]
        for data in round2_data:
            share_fragments.append(data['f'])

        public_fx = [dkg_saved_data['public_fx'][0]]
        for data in round1_broadcasted_data:
            if data['sender_id'] in self.partners:
                public_fx.append(Utils.code_to_pub(data['public_fx'][0]))

        dkg_public_key = public_fx[0]
        for i in range(1, len(public_fx)):
            dkg_public_key = dkg_public_key + public_fx[i]

        share = sum(share_fragments)
        self.dkg_key_pair = {'share': share, 'dkg_public_key': dkg_public_key}

        result = {
            'data': {
                'dkg_public_key': Utils.pub_to_code(dkg_public_key),
                'public_share' : Utils.pub_to_code(keys.get_public_key(share , Utils.ecurve)),
            },
            'status': 'SUCCESSFUL'
        }
        return result

    def sign(self, commitments_dict, message: str, nonces : Dict) -> List:
        assert type(message) == str, 'Message should be from string type.'
        nonce_d = 0
        nonce_e = 0
        signature = None
        nonce = commitments_dict[self.node_id]
        for pair in nonces:
            nonce_d = pair['nonce_d_pair'].get(nonce['public_nonce_d'])
            nonce_e = pair['nonce_e_pair'].get(nonce['public_nonce_e'])
            if nonce_d is None and nonce_e is None:
                continue

            signature = __init__.single_sign(
                int(self.node_id),
                self.dkg_key_pair['share'],
                nonce_d,
                nonce_e,
                message,
                commitments_dict,
                Utils.pub_to_code(self.dkg_key_pair['dkg_public_key'])
            )
            remove_data = {
                'nonce_d_pair': {nonce['public_nonce_d']: nonce_d}, 
                'nonce_e_pair': {nonce['public_nonce_e']: nonce_e}
            }
            
        return signature, remove_data
    
    