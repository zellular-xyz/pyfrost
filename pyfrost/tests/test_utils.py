from pyfrost.crypto_utils import Polynomial
from fastecdsa import keys
from pyfrost import frost
from web3 import Web3

import pyfrost.crypto_utils as Utils
import random
import json
import unittest

# filling with [1 , 2, .... , 50 , N-50 , N- 49 , ... , N-1]
test_list = [i for i in range(1, 51)] + [Utils.N-i for i in range(1, 51)]
nodes = [str(i) for i in range(1, 6)]
threshold = 3


def polyval(x, polynomial):
    result = 0
    for i in range(len(polynomial)):
        result = result + polynomial[i] * pow(x, i)
    return result % Utils.N


def share_keys(private_key, threshold, n, party, polynomial):
    if party:
        assert len(party) == n, "Party's number must be n."
    else:
        party = list(range(1, n+1))
    if polynomial:
        assert len(polynomial) == threshold, "Polynomial's degree must be t."
    else:
        polynomial = [private_key]
        for i in range(threshold-1):
            polynomial.append(Utils.generate_random_private())
    shares = []
    for i in party:
        shares.append({'id': i, 'key': polyval(i, polynomial)})
    return {'polynomial': polynomial, 'shares': shares}


def key_generate(nodes, threshold, private_key=None):
    functions = []
    f_share = {}
    public_keys = []
    for node in nodes:
        fx = Polynomial(threshold, Utils.ecurve, private_key)
        functions.append(fx)
        public_keys.append(fx.coef_pub_keys()[0])
        f_share[node] = []
    for node in nodes:
        for fx in functions:
            f_share[node].append(fx.evaluate(node))
    key_shares = []
    public_fx = public_keys[0]
    for i in range(1, len(public_keys)):
        public_fx = public_fx + public_keys[i]
    n_inverse = Utils.mod_inverse(len(nodes), Utils.N)
    aggregated_public_key = n_inverse * public_fx
    for node in nodes:
        key_shares.append({'id': node, 'key': sum(
            f_share[node]) * n_inverse, 'public_key': aggregated_public_key})  # , 'publicKey' : total_Fx
    return key_shares


class Test(unittest.TestCase):

    def test_interpolation(self):
        number_errors = 0
        for private in test_list:
            threshold = 3
            number_of_nodes = 5
            share_key = share_keys(private, threshold, number_of_nodes, [], [])
            f = share_key['polynomial']
            shares = share_key['shares']
            threshold_shares1 = random.sample(shares, threshold)
            generated_key1 = Utils.reconstruct_share(
                threshold_shares1, threshold, 0)
            if (generated_key1 != private):
                number_errors = number_errors + 1
        self.assertEqual(
            number_errors, 0, f'Testing Interpolation Functions : {number_errors} errors from {len(test_list)}')

    def test_key_gen_logic(self):
        number_of_errors = 0
        for test in test_list:
            key_shares = key_generate(nodes, threshold, test)
            threshold_shares1 = random.sample(key_shares, threshold)
            generated_key1 = Utils.reconstruct_share(
                threshold_shares1, threshold, 0)
            threshold_shares2 = random.sample(key_shares, threshold)
            generated_key2 = Utils.reconstruct_share(
                threshold_shares2, threshold, 0)
            assert generated_key1 == generated_key2, "ERROR: reconstruct key is mismatched"
            if (generated_key1 != test):
                number_of_errors = number_of_errors + 1
        self.assertEqual(number_of_errors, 0, f'Testing Key Generation Logic : {number_of_errors} errors from {len(test_list)}')\


    def test_stinson_sign_logic(self):
        key_shares = key_generate(nodes, threshold)
        key_nonces = key_generate(nodes, threshold)

        message_hash = int.from_bytes(Web3.solidity_keccak(
            ['string'], ["Hello every body"]), 'big')

        signatures = []
        for key_share in key_shares:
            share = key_share['key']
            nonce = key_nonces[key_shares.index(key_share)]['key']
            public_nonce = key_nonces[key_shares.index(
                key_share)]['public_key']
            signatures.append({'index': key_share['id'], 'sign': Utils.schnorr_sign(
                share, nonce, public_nonce, message_hash)})

        public_key = key_shares[0]['public_key']

        for id in range(5):
            signates_subset = random.sample(signatures, threshold)
            aggregated_signature = Utils.schnorr_aggregate_signatures(
                threshold, [s['sign'] for s in signates_subset], [s['index'] for s in signates_subset])
            self.assertTrue(
                Utils.schnorr_verify(
                    public_key, message_hash, aggregated_signature),
                f"FAILED SIGNATURE by selected nodes : {[s['index'] for s in signates_subset]}"
            )

    def test_frost_sign_logic(self):
        key_shares = key_generate(nodes, threshold)
        for _ in range(5):
            key_shares_subset = random.sample(key_shares, threshold)
            nodes_subset = []
            for k in key_shares_subset:
                nodes_subset.append(k['id'])
            commitments_dict = {}
            private_nonces = []
            for id in nodes_subset:
                nonce_d, public_nonce_d = keys.gen_keypair(Utils.ecurve)
                nonce_e, public_nonce_e = keys.gen_keypair(Utils.ecurve)
                private_nonces.append(
                    {'id': int(id), 'public_nonce_d': nonce_d, 'public_nonce_e': nonce_e})
                commitments_dict[id] = {
                    'id': int(id),
                    'public_nonce_d': Utils.pub_to_code(public_nonce_d),
                    'public_nonce_e': Utils.pub_to_code(public_nonce_e)
                }
            message = 'Hello every body'
            signatures = []
            share_public_keys = {}
            for key_share in key_shares_subset:
                id = int(key_share['id'])
                share = key_share['key']
                group_key = Utils.pub_to_code(key_share['public_key'])
                for nonce in private_nonces:
                    if nonce['id'] == id:
                        nonce_d = nonce['public_nonce_d']
                        nonce_e = nonce['public_nonce_e']
                single_signature = frost.single_sign(
                    id, share, nonce_d, nonce_e, message, commitments_dict, group_key)
                share_public_keys[id] = Utils.pub_to_code(
                    keys.get_public_key(share, Utils.ecurve))
                signatures.append(single_signature)
            group_nonce = frost.aggregate_nonce(
                message, commitments_dict, group_key)
            for single_signature in signatures:
                self.assertTrue(frost.verify_single_signature(single_signature['id'], message, commitments_dict, group_nonce, share_public_keys[single_signature['id']], single_signature, group_key),
                                f"FROST logic failed to verify single signature by node : {single_signature['id']}")

            group_sign = frost.aggregate_signatures(
                message, signatures, group_nonce, group_key)
            self.assertTrue(frost.verify_group_signature(group_sign),
                            f"FROST logic failed to verify group signature by selected nodes : {nodes_subset}")

    def test_encryption_logic(self):
        for _ in range(10):
            private1, public1 = keys.gen_keypair(Utils.ecurve)
            private2, public2 = keys.gen_keypair(Utils.ecurve)
            joint_key = Utils.pub_to_code(private1 * public2)
            encryption_key = Utils.generate_hkdf_key(joint_key)
            original_data = {'signature': Utils.generate_random_private()}
            encrypted_data = Utils.encrypt(original_data, encryption_key)
            joint_key = Utils.pub_to_code(private2 * public1)
            decryption_key = Utils.generate_hkdf_key(joint_key)
            decrypted_data = Utils.decrypt(encrypted_data, decryption_key)
            self.assertEqual(json.loads(decrypted_data), original_data,
                             f"Original data : {original_data} \n Encrypted data : {encrypted_data} \n Decrypted data : {decrypted_data}")


if __name__ == '__main__':
    unittest.main()
