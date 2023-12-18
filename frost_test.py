from key import DistributedKey
from typing import List
import random
import __init__
import unittest

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

agregated_nonces = []
for key in sign_subset:
    single_sign , remove_data = key.sign(commitments_data , msg , saved_data['private_data'][key.node_id]['nonces'])
    saved_data['private_data'][key.node_id]['nonces'].remove(remove_data)  
    agregated_nonces.append(single_sign['aggregated_public_nonce'])
if len(set(agregated_nonces)) == 1:
    print('True')
else:
    print('False')
# class TestCase(unittest.TestCase):
    
#     def test_function_name(self):
#         result = frost.dkg_round1()

