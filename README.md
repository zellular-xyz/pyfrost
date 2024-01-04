# PyFrost

PyFrost is a Python implementation of the [FROST](https://eprint.iacr.org/2020/852.pdf) protocol. FROST stands for Flexible Round-Optimized Schnorr Threshold Signatures, a protocol that surpasses other threshold signature protocols with its efficient single-round signing procedure. PyFrost utilizes the standard FROST protocol for single-round signing operations. Additionally, it incorporates the [Identifiable Cheating Entity FROST Signature Protocol](https://eprint.iacr.org/2021/1658.pdf) within the *distributed key generation (DKG)* framework. This approach is designed to detect and mitigate potential malicious behavior, such as when cheating entities selectively share secrets during the DKG process to exclude honest participants.

[This tutorial](https://github.com/SAYaghoubnejad/pyfrost/wiki/PyFrost-TSS-Protocol) provides an introduction to cryptographic concepts integral to PyFrost, including Threshold Signatures, Distributed Key Generation, Cheating Identification, Standard Schnorr Signatures, and Single-Round Schnorr Threshold Signatures.

PyFrost implements the cryptographic functions of the FROST protocol and includes a networking package that features libp2p clients for nodes, signature aggregators, and distributed key generators.

## Network Package

The network package includes the implementation of the following components:

#### Node
A Libp2p client that facilitates the three rounds of the Distributed Key Generation (DKG) process, as well as nonce creation and signing methods.

#### Distributed Key Generator
A Libp2p client responsible for initiating the DKG process through the node.

#### Signature Aggregator
A Libp2p client that collects nonces, requests signatures from nodes, and then aggregates and verifies them.

To effectively utilize PyFrost in your Threshold Signature Scheme (TSS) network, the following interface classes, used by the above clients, should be implemented:
- **Data Manager**: Functions for storing and retrieving private nonces and keys.
- **Node Info**: Provides a list of network nodes along with their information.
- **Validators**: Verifies the roles of signature aggregators and distributed key generators.

**Note:** Examples of how to implement these abstract interfaces can be found in `pyfrost/network/examples/abstracts.py`.

## How to Setup

```bash
$ git clone https://github.com/SAYaghoubnejad/pyfrost.git
$ cd pyfrost
$ virtualenv -p python3.10 venv
$ source venv/bin/activate
(venv) $ pip install .
```

**Note:** Python version `3.10` is required.

## How to Run Tests

To run tests, navigate to the root directory and run the fallowing command:

```bash
(venv) $ python run_tests.py 
```

## How to Run an Example

To run an example network, open `m` additional terminals for `m` nodes and activate the `venv` in these terminals. Note that `m` is an arbitrary positive number, but it must not exceed 99 due to predefined nodes in the example setup. Then navigate to the `pyfrost/network/examples/` directory:

```bash
(venv) $ cd pyfrost/network/examples/
```

First, initialize the nodes by typing the following command in `m` terminals:

```bash
(venv) $ python node.py [0-m]
```

Wait for the node setup to complete, which is indicated by the node API being printed and a message stating **Waiting for incoming connections...**

Finally, run the `example.py` script in the last terminal:

```bash
(venv) $ python example.py [number of nodes you ran] [threshold] [n] [number of signatures]
```

The `example.py` script manages distributed key generation and signature aggregation.

The script requires 4 parameters:

1. `number of nodes you ran`: The count of active nodes.
2. `threshold`: The FROST algorithm threshold, an integer ($t \leq n$).
3. `n`: The number of nodes collaborating in the DKG to generate a distributed key ($n \leq m$).
4. `number of signatures`: The count of signatures requested by the signature aggregator after the DKG.

**Note:** Logs for each node and the signature aggregator are stored in the `./logs` directory.

## Benchmarking

The following benchmarks were conducted on an Intel i7-6700HQ with 8 cores and 16GB RAM. (All times are in seconds)

| Benchmark | DKG Time   | Avg. Time per Node for Nonce Generation | Signing Time |
| --------- | ---------- | --------------------------------------- | ------------ |
| 7 of 10   | 0.840 sec  | 0.352 sec                               | 0.135 sec    |
| 15 of 20  | 5.435 sec  | 0.344 sec                               | 0.380 sec    |
| 25 of 30  | 14.183 sec | 0.345 sec                               | 0.601 sec    |

For the non-local evaluation, we utilized 30 node containers spread across three countries and four cities. Additionally, the Signature Aggregator was configured with dual vCPUs and 8GB of RAM.

| Benchmark | DKG Time  | Avg. Time per Node for Nonce Generation | Signing Time |
| --------- | --------- | --------------------------------------- | ------------ |
| 25 of 30  | 7.400 sec | 1.594 sec                               | 0.725 sec    |
