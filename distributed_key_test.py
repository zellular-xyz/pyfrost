from distributed_key import DistributedKey
from typing import List
import random
import __init__
import unittest
from utils import Utils 
from utils import keys as crypto
############## initial parameters  
dkg_id = str(random.randint(0 , 100))
n = 5
t = 3
party = [str(random.randint(0 , 100)) for i in range(n)]
coef0 = 1

keys : List[DistributedKey] = []
for node_id in party:
    partners = party.copy()
    partners.remove(node_id)
    keys.append(DistributedKey(dkg_id , t , n , node_id , partners , coef0))

saved_data = {}
# assert round1_send_data['public_fx'][0] == 286650441496909734516720688912544350032790572785058722254415355376215376009112 , 'error'
# assert round1_save_data['dkg_id'] == dkg_id
# assert round1_save_data['data']['fx'].coefficients[0] == 1
round1_received_data = []
for key in keys:
    round1_send_data , round1_save_data = key.round1()
    round1_received_data.append(round1_send_data)    
    node_saved_data = {dkg_id : round1_save_data['data']}
    saved_data[key.node_id] = node_saved_data

round2_received_data = {}
for node_id in party:
    round2_received_data[node_id] : List = []
for key in keys:
    round2_send_data , round2_save_data = key.round2(round1_received_data , saved_data[key.node_id][dkg_id])
    for message in round2_send_data:
        round2_received_data[message['receiver_id']].append(message)
    saved_data[key.node_id][dkg_id].update(round2_save_data['data'])

for key in keys:
    result = key.round3(round1_received_data ,round2_received_data[key.node_id] , saved_data[key.node_id][dkg_id])

saved_data['common_data'] = {}
saved_data['private_data'] = {}
for key in keys:
    nonces_common_data , nonces_private_data = __init__.nonce_preprocess(int(key.node_id))
    saved_data['common_data'].update({key.node_id : nonces_common_data})
    saved_data['private_data'].update({key.node_id : {'nonces' : nonces_private_data}})

msg = 'Hello Frost'
sign_subset = random.sample(keys , t)
commitments_data = {}
for key in sign_subset:
    commitment = saved_data['common_data'][key.node_id].pop()
    commitments_data[key.node_id] = commitment
signs = []
agregated_nonces = []
for key in sign_subset:
    single_sign , remove_data = key.sign(commitments_data , msg , saved_data['private_data'][key.node_id]['nonces'])
    if __init__.verify_single_signature(int(key.node_id) , msg , commitments_data , Utils.code_to_pub(single_sign['aggregated_public_nonce']) , Utils.pub_to_code(crypto.get_public_key(key.dkg_key_pair['share'],Utils.ecurve)) , single_sign ,Utils.pub_to_code(key.dkg_key_pair['dkg_public_key'] )):
        signs.append(single_sign)
    else:
        print('Failed at verify single signatue')
        exit()
    saved_data['private_data'][key.node_id]['nonces'].remove(remove_data)  
    agregated_nonces.append(single_sign['aggregated_public_nonce'])
if len(set(agregated_nonces)) == 1:
    print('Test1 Passed')
else:
    print('Failed at verify nonces')
group_sign = __init__.aggregate_signatures(msg ,signs,Utils.code_to_pub(agregated_nonces[0]),result['data']['dkg_public_key'])
if __init__.verify_group_signature(group_sign):
    print('Test2 passed')
else:
    print('Failed at verify group signatue')
# class TestCase(unittest.TestCase):
    
#     def test_function_name(self):
#         result = frost.dkg_round1()

