from frost import FROST
from typing import List
import random
import unittest

############## initial parameters  
dkg_id = str(random.randint(0 , 100))
n = 5
t = 3
party = [str(random.randint(0 , 100)) for i in range(n)]
coef0 = 1

frost_nodes : List[FROST] = []
for node_id in party:
    partners = party.copy()
    partners.remove(node_id)
    frost_nodes.append(FROST(dkg_id , t , n , node_id , partners , coef0))

saved_data = {}
# assert round1_send_data['public_fx'][0] == 286650441496909734516720688912544350032790572785058722254415355376215376009112 , 'error'
# assert round1_save_data['dkg_id'] == dkg_id
# assert round1_save_data['data']['fx'].coefficients[0] == 1
round1_received_data = []
for frost_node in frost_nodes:
    round1_send_data , round1_save_data = frost_node.dkg_round1()
    round1_received_data.append(round1_send_data)    
    node_saved_data = {dkg_id : round1_save_data['data']}
    saved_data[frost_node.node_id] = node_saved_data

round2_received_data = {}
for node_id in party:
    round2_received_data[node_id] : List = []
for frost_node in frost_nodes:
    round2_send_data , round2_save_data = frost_node.dkg_round2(round1_received_data , saved_data[frost_node.node_id][dkg_id])
    for message in round2_send_data:
        round2_received_data[message['receiver_id']].append(message)
    saved_data[frost_node.node_id][dkg_id].update(round2_save_data['data'])

for frost_node in frost_nodes:
    result = frost_node.dkg_round3(round1_received_data ,round2_received_data[frost_node.node_id] , saved_data[frost_node.node_id][dkg_id])

saved_data['common_data'] = {}
saved_data['private_data'] = {}
for frost_node in frost_nodes:
    nonces_common_data , nonces_private_data = FROST.nonce_preprocess(int(frost_node.node_id))
    saved_data['common_data'].update({frost_node.node_id : nonces_common_data})
    saved_data['private_data'].update({frost_node.node_id : {'nonces' : nonces_private_data}})

msg = 'Hello Frost'
sign_subset = random.sample(frost_nodes , t)
commitments_data = {}
for frost_node in sign_subset:
    commitment = saved_data['common_data'][frost_node.node_id].pop()
    commitments_data[frost_node.node_id] = commitment

agregated_nonces = []
for frost_node in sign_subset:
    single_sign , remove_data = frost_node.sign(commitments_data , msg , saved_data['private_data'][frost_node.node_id])
    saved_data['private_data'][frost_node.node_id]['nonces'].remove(remove_data)  
    agregated_nonces.append(single_sign['aggregated_public_nonce'])
if len(set(agregated_nonces)) == 1:
    print('True')
else:
    print('False')
# class TestCase(unittest.TestCase):
    
#     def test_function_name(self):
#         result = frost.dkg_round1()

