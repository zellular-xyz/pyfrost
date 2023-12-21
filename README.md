# PyFrost

PyFROST is an implementation of the [FROST](https://eprint.iacr.org/2020/852.pdf) protocol in Python. FROST is a Flexible Round-Optimized Schnorr Threshold Signatures protocol that is superior to other threshold signature protocols due to its efficient single-round signing procedure.

This module implements the cryptography functions of the FROST protocol as well as a network package that includes libp2p clients for node, signature aggregator and distributed key generator.

## Cryptography functions

### Three Rounds During DKG

1. `KeyGen.round1()`: Initiates the DKG by generating a key pair (securing communication against eavesdropping) and a $t$-degree polynomial for the distributed key.
2. `KeyGen.round2(round1_broadcasted_data)`: Processes the second round of DKG by handling `round1_broadcasted_data` from other party nodes. It generates data to be shared between node pairs, encrypting it with the sender's private key and the receiver's public key.
3. `KeyGen.round3(round1_broadcasted_data, round2_encrypted_data)`: Calculates the node's share of the distributed key, reporting the share and corresponding key, signed with the node's permanent secret for verification. In case of failure due to other nodes' dishonesty, it reports malicious activity.

### Issuing Signature

1. `create_nonces(node_id: int, number_of_nonces=10)`: This function is `staticmethod` that generate a batch of public-private keys as nonce. This nonces, then use when a client (i.e. signature aggregator (SA)) request signature.
2. `Key.sign(self, commitments_dict, message: str, nonces: Dict)`:
   
### Aggregation & Verification

- `aggregate_signatures(message: str, single_signatures: List[Dict[str, int]], aggregated_public_nonce: Point, group_key: int) -> Dict`
- `aggregate_nonce(message: str, commitments_dict: Dict[str, Dict[str, int]], group_key: Point)`

- `verify_single_signature(id: int, message: str, commitments_dict: Dict[str, Dict[str, int]], aggregated_public_nonce: Point,
                            public_key_share: int, single_signature: Dict[str, int], group_key: Point) -> bool`
- `verify_group_signature(aggregated_signature: Dict) -> bool`


## Network package

The network package includes the implementation of the following:

### Node
A Libp2p client that serves the three rounds of DKG and nonce creation and signing methods.

### Distributed Key Generator
A Libp2p client that calls the DKG three rounds on the node.

### Signature Aggregator
A Libp2p client that queries nonces and signatures from the nodes and then aggregates and verifies them.

To use PyFrost to run your TSS network, the following interface classes used by the above clients should be implemented:
- Data Manager: Functions to store and retrieve the private nonces and keys 
- Node Info: Provides a list of network nodes and their information
- Validators: Verifies the roles of signature aggregators and distributed key generators.

## How to Run Test
{Clone - Setup venv and install dependencies - run tests}


## Benchmarks
