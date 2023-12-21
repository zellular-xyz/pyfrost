# PyFrost

PyFROST is an implementation of the [FROST](https://eprint.iacr.org/2020/852.pdf) protocol in Python. FROST is a Flexible Round-Optimized Schnorr Threshold Signatures protocol that is superior to other threshold signature protocols due to its efficient single-round signing procedure.

This module implements the cryptography functions of the FROST protocol as well as a network package that includes libp2p clients for node, signature aggregator and distributed key generator.

## Cryptography functions

```
pyfrost.KeyGen.round1(self)
pyfrost.KeyGen.round2(self, round1_broadcasted_data)
pyfrost.KeyGen.round3(self, round2_encrypted_data)
pyfrost.Key.sign(self, commitments_dict, message, nonces)
pyfrost.create_nonces(node_id, number_of_nonces)
pyfrost.aggregate_nonce(message, commitments_dict, group_key)
pyfrost.aggregate_signatures(message, single_signatures, aggregated_public_nonce, group_key)
pyfrost.verify_group_signature(aggregated_signature)
pyfrost.verify_single_signature(id, message, commitments, aggregated_nonce, public_key, signature, group_key)
```

## Network package

The network package includes the implementation of the following:

#### Node
A Libp2p client that serves the three rounds of DKG and nonce creation and signing methods.

#### Distributed Key Generator
A Libp2p client that calls the DKG three rounds on the node.

#### Signature Aggregator
A Libp2p client that queries nonces and signatures from the nodes and then aggregates and verifies them.

To use PyFrost to run your TSS network, the following interface classes used by the above clients should be implemented:
- Data Manager: Functions to store and retrieve the private nonces and keys 
- Node Info: Provides a list of network nodes and their information
- Validators: Verifies the roles of signature aggregators and distributed key generators.

## How to Setup

```bash
$ git clone https://github.com/SAYaghoubnejad/pyfrost.git
$ cd pyfrost
$ virtualenv -p python3.10 venv
$ source venv/bin/activate
(venv) $ pip install .
```

**Note:** The required Python version is `3.10`.

## How to Run Example

To run an example network, open `m` additional terminals for `m` nodes and activate the `venv` in these terminals. Note that `m` is an arbitrary positive number, but it must be less than or equal to 99 due to the predefined nodes for testing. Then change the directory to the `tests` folder:

```bash
(venv) $ cd network/examples/
```

First, run the nodes. Type the following command in `m` terminals to initiate them:

```bash
(venv) $ python node/main.py [0-m]
```

**Note:** To run multiple nodes and stop them using a single command, you can run the `run_nodes.sh` and `stop_nodes.sh` scripts. First, add execute permission to them by running the following commands:

```bash
(venv) $ chmod +x run_nodes.sh
(venv) $ chmod +x stop_nodes.sh
```

Run multiple nodes using this command:

```bash
(venv) $ ./run_nodes.sh [number of nodes]
```

After executing either of the above commands, wait until the node setup is complete. The setup is finished when the node API is printed along with a message indicating **Waiting for incoming connections...**

Finally, run `test.py` script in the last terminal:

```bash
(venv) $ python test.py [number of nodes you ran] [threshold] [n] [number of signatures]
```

Note that `test.py` implements the functionality for distributed key generation and signature aggregation.

The script takes 4 parameters as input:

1. `number of nodes you ran`: The number of active nodes.
2. `threshold`: The threshold of the FROST algorithm, which is an integer ($t \leq n$).
3. `n`: The number of nodes cooperating with the DKG to generate a distributed key ($n \leq m$).
4. `number of signatures`: The number of signatures requested by the signature aggregator upon completion of the Distributed Key Generation (DKG).

If you want to stop all the nodes, type the following command:

```bash
(venv) $ ./stop_nodes.sh
```

**Note:** Logs for each node and the signature aggregator are stored in the `./logs` directory.

## Benchmarking

This evaluation is done on the Intel i7-6700HQ with 8 cores and 16GB RAM. (All times are in seconds)

| Benchmark                     | DKG Time | Nonce Generation Avg. Time per Node | Signing Time |
|-------------------------------|----------|-------------------------------------|--------------|
|  7 of 10                      | 0.840 sec| 0.352 sec                           | 0.135 sec    | 
| 15 of 20                      | 5.435 sec| 0.344 sec                           | 0.380 sec    |
| 25 of 30                      |14.183 sec| 0.345 sec                           | 0.601 sec    |

---

For the non-local evaluation, we incorporated 30 node containers across three distinct countries and four different cities. Additionally, we employed a Signature Aggregator featuring dual vCPUs and an eight-gigabyte RAM configuration.

| Benchmark                     | DKG Time | Nonce Generation Avg. Time per Node | Signing Time |
|-------------------------------|----------|-------------------------------------|--------------|
| 25 of 30                      | 7.400 sec| 1.594 sec                           | 0.725 sec    |

---
