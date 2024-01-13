from pyfrost.crypto_utils import keys as crypto
from pyfrost import KeyGen, Key
from typing import List

import pyfrost.crypto_utils as Utils
import pyfrost
import random
import unittest


# initial parameters
DKG_ID = str(random.randint(0, 100000))
N = 5
T = 3
PARTY = [str(random.randint(0, 2**63)) for i in range(N)]
COEF0 = 1


class TestCaseKey(unittest.TestCase):

    def test_key(self):

        keys: List[KeyGen] = []
        sign_keys: List[Key] = []
        saved_data = {}

        for node_id in PARTY:
            partners = PARTY.copy()
            partners.remove(node_id)
            keys.append(KeyGen(DKG_ID, T, node_id, partners, COEF0))

        round1_received_data = []
        for key in keys:
            round1_send_data = key.round1()
            round1_received_data.append(round1_send_data)
            self.assertEqual(round1_send_data['public_fx'][0],
                             286650441496909734516720688912544350032790572785058722254415355376215376009112,
                             f"DKG-ROUND1 FAILED"
                             )
        round2_received_data = {}
        for node_id in PARTY:
            round2_received_data[node_id]: List = []
        for key in keys:
            round2_send_data = key.round2(round1_received_data)
            for message in round2_send_data:
                round2_received_data[message['receiver_id']].append(message)
        dkg_keys = set()
        for key in keys:
            result = key.round3(round2_received_data[key.node_id])
            dkg_keys.add(result['data']['dkg_public_key'])
            sign_keys.append(Key(key.dkg_key_pair, key.node_id))
        self.assertEqual(len(dkg_keys), 1, "DKG-ROUND3 FAILED")

        saved_data['common_data'] = {}
        saved_data['private_data'] = {}
        for key in keys:
            nonces_common_data, nonces_private_data = pyfrost.create_nonces(
                int(key.node_id))
            saved_data['common_data'].update({key.node_id: nonces_common_data})
            saved_data['private_data'].update(
                {key.node_id: {'nonces': nonces_private_data}})

        msg = 'Hello Frost'
        sign_subset = random.sample(sign_keys, T)
        nonces_data = {}
        for key in sign_subset:
            nonce = saved_data['common_data'][key.node_id].pop()
            nonces_data[key.node_id] = nonce
        signs = []
        agregated_nonces = []

        for key in sign_subset:
            nonce_public_pair = nonces_data[key.node_id]
            my_nonce_d_public = nonce_public_pair['public_nonce_d']
            my_nonce_e_public = nonce_public_pair['public_nonce_e']
            nonce_d_private, nonce_e_private = 0, 0
            for nonces in saved_data['private_data'][key.node_id].values():
                for nonce in nonces:
                    nonce_e_public, nonce_e_private = nonce['nonce_e_pair'].popitem(
                    )
                    nonce_d_public, nonce_d_private = nonce['nonce_d_pair'].popitem(
                    )
                    if my_nonce_d_public == nonce_d_public and my_nonce_e_public == nonce_e_public:
                        break
            nonce = {
                'nonce_d': nonce_d_private,
                'nonce_e': nonce_e_private
            }
            single_sign = key.sign(
                nonces_data, msg, nonce)
            signature_data = {
                'id': int(key.node_id),
                'message': msg,
                'nonces_dict': nonces_data,
                'aggregated_public_nonce': Utils.code_to_pub(single_sign['aggregated_public_nonce']),
                'public_key_share': Utils.pub_to_code(crypto.get_public_key(key.dkg_key_pair['share'], Utils.ecurve)),
                'single_signature': single_sign,
                'group_key': Utils.pub_to_code(key.dkg_key_pair['dkg_public_key'])
            }
            self.assertTrue(pyfrost.verify_single_signature(signature_data),
                            f"SINGLE SIGNATURE FAILED BY NODE {key.node_id}"
                            )
            signs.append(single_sign)
            # TODO: Add remove data.
            agregated_nonces.append(single_sign['aggregated_public_nonce'])
        self.assertEqual(len(set(agregated_nonces)),
                         1, 'AGREGATED NONCES FAILED')

        group_sign = pyfrost.aggregate_signatures(msg, signs, Utils.code_to_pub(
            agregated_nonces[0]), result['data']['dkg_public_key'])
        self.assertTrue(pyfrost.frost.verify_group_signature(group_sign),
                        'GROUP SIGNATURE FAILED'
                        )


if __name__ == '__main__':
    unittest.main()
