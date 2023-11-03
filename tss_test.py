from ecpy.keys import ECPublicKey, ECPrivateKey
from web3 import Web3
from polynomial import Polynomial

import random
from tss import TSS
import secrets
import json

# In this code we will test the functionality of TSS
# Cryptography Module.
# In this phase we just check the logic of Key Generation
# and Multi-Signature Generation and Verification,but we
# dont have a distributed implementation in this phase.

################# Test ShareKey & ReconstructKey Functions #################


def polyval(x, polynomial):
    result = 0
    for i in range(len(polynomial)):
        result = result + polynomial[i].d * pow(x, i)
    return ECPrivateKey(result % TSS.N, TSS.curve)


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
            polynomial.append(TSS.generate_random_private())
    shares = []
    for i in party:
        shares.append({'i': i, 'key': polyval(i, polynomial)})
    return {'polynomial': polynomial, 'shares': shares}


print('Testing Interpolation Functions ...')
test_list = []  # filling with [0 , 1 , 2, .... , 49 , N-49 , N- 48 , ... , N-1]
number_errors = 0
for i in range(0, 50):
    test_list.append(i)
    if i != 0:
        test_list.append(TSS.N-i)
for test in test_list:
    private = ECPrivateKey(test, TSS.curve)
    threshold = 3
    number_of_nodes = 5
    share_key = share_keys(private, threshold, number_of_nodes, [], [])
    f = share_key['polynomial']
    shares = share_key['shares']
    threshold_shares1 = random.sample(shares, threshold)
    generated_key1 = TSS.reconstruct_share(threshold_shares1, threshold, 0)
    if (generated_key1 != test):
        number_errors = number_errors + 1
        print('Error at Test ShareKey & ReconstructKey Functions by PrivateKey:')
        print(test)
print(f'Find {number_errors} errors from {len(test_list)} tests')

################# Test Key Generation Logic #################


def key_generate(nodes, threshold, private_key=None):
    functions = []
    f_share = {}
    public_keys = []
    for node in nodes:
        fx = Polynomial(threshold, TSS.curve, private_key)
        functions.append(fx)

        public_keys.append(fx.coef_pub_keys()[0])
        f_share[node] = []
    for node in nodes:
        for fx in functions:
            f_share[node].append(fx.evaluate(node).d)
    key_shares = []
    public_fx = public_keys[0].W
    for i in range(1, len(public_keys)):
        public_fx = TSS.curve.add_point(public_fx, public_keys[i].W)
    n_inverse = TSS.mod_inverse(len(nodes), TSS.N)
    aggregated_public_key = ECPublicKey(
        TSS.curve.mul_point(n_inverse, public_fx))
    for node in nodes:
        key_shares.append({'i': node, 'key': ECPrivateKey(sum(
            f_share[node]) * n_inverse, TSS.curve), 'public_key': aggregated_public_key})  # , 'publicKey' : total_Fx
    return key_shares


nodes = [str(i) for i in range(1, 6)]
threshold = 3
number_of_errors = 0
print('\nTesting Key Generation Logic ...')
for test in test_list:
    key_shares = key_generate(nodes, threshold, test)
    threshold_shares1 = random.sample(key_shares, threshold)
    generated_key1 = TSS.reconstruct_share(threshold_shares1, threshold, 0)
    threshold_shares2 = random.sample(key_shares, threshold)
    generated_key2 = TSS.reconstruct_share(threshold_shares2, threshold, 0)
    assert generated_key1 == generated_key2, "ERROR: reconstruct key is mismatched"
    if (generated_key1 != test):
        number_of_errors = number_of_errors + 1
        print('Error at Test Key Generation Logic by PrivateKey:')
        print(test)
        print(generated_key1)
print(f'Find {number_of_errors} errors from {len(test_list)} tests')

################# Test Signing Logic #################

key_shares = key_generate(nodes, threshold)
key_nonces = key_generate(nodes, threshold)

message_hash = int.from_bytes(Web3.solidity_keccak(
    ['string'], ["Hello every body"]), 'big')

signatures = []
for key_share in key_shares:
    share = key_share['key']
    nonce = key_nonces[key_shares.index(key_share)]['key']
    public_nonce = key_nonces[key_shares.index(key_share)]['public_key']
    signatures.append({'index': key_share['i'], 'sign': TSS.schnorr_sign(
        share, nonce, public_nonce, message_hash)})

public_key = key_shares[0]['public_key']
print('\nTesting Stinson Schnorr Sign Algorithm ...')
for i in range(5):
    signates_subset = random.sample(signatures, threshold)
    aggregated_signature = TSS.schnorr_aggregate_signatures(
        threshold, [s['sign'] for s in signates_subset], [s['index'] for s in signates_subset])
    verified = TSS.schnorr_verify(
        public_key, message_hash, aggregated_signature)
    print(
        f"Selected Nodes : {[s['index'] for s in signates_subset]} , verified : {verified}")

################# Test FROST signing Logic #################
print('\nTesting FROST Sign Algorithm ...')
key_shares = key_generate(nodes, threshold)
for _ in range(5):
    key_shares_subset = random.sample(key_shares, threshold)
    nodes_subset = []
    for k in key_shares_subset:
        nodes_subset.append(k['i'])
    commitments_list = []
    private_nonces = []
    for i in nodes_subset:
        nonce_d = ECPrivateKey(secrets.randbits(32*8), TSS.curve)
        nonce_e = ECPrivateKey(secrets.randbits(32*8), TSS.curve)
        private_nonces.append({'i': i, 'd': nonce_d, 'e': nonce_e})
        commitments_list.append({
            'i': i,
            'D': TSS.pub_to_code(nonce_d.get_public_key()),
            'E': TSS.pub_to_code(nonce_e.get_public_key())
        })
    message = 'Hello every body'
    signatures = []
    share_public_keys = {}
    for key_share in key_shares_subset:
        id = key_share['i']
        share = key_share['key']
        group_key = TSS.pub_to_code(key_share['public_key'])
        for nonce in private_nonces:
            if nonce['i'] == id:
                nonce_d = nonce['d']
                nonce_e = nonce['e']
        single_signature = TSS.frost_single_sign(
            id, share, nonce_d, nonce_e, message, commitments_list, group_key)
        share_public_keys[id] = TSS.pub_to_code(share.get_public_key())
        signatures.append(single_signature)

    group_sign = TSS.frost_aggregate_signatures(
        signatures, share_public_keys, message, commitments_list, group_key)
    verification = TSS.frost_verify_group_signature(group_sign)
    print(f"Selected Nodes : {nodes_subset} , verified : {verification}")

################### Test Encryption Logic ###################
number_errors = 0
print('\nTesting Encryption Methods ...')
for _ in range(10):
    private1 = TSS.generate_random_private()
    private2 = TSS.generate_random_private()
    public1 = private1.get_public_key()
    public2 = private2.get_public_key()
    encryption_key = TSS.generate_hkdf_key(private1, public2)
    original_data = {'signature': TSS.generate_random_private().d}
    encrypted_data = TSS.encrypt(original_data, encryption_key)
    decryption_key = TSS.generate_hkdf_key(private2, public1)
    decrypted_data = TSS.decrypt(encrypted_data, decryption_key)
    if json.loads(decrypted_data) != original_data:
        number_errors = number_errors + 1
        print('Original data : ', original_data)
        print('Encrypted data : ', encrypted_data)
        print('Decrypted data : ', decrypted_data)
print(f"Find {number_errors} errors of 10 tests.")
