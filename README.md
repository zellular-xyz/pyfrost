# PyFrost

PyFrost is a Python implementation of the [FROST](https://eprint.iacr.org/2020/852.pdf) protocol. FROST stands for Flexible Round-Optimized Schnorr Threshold Signatures, a protocol that surpasses other threshold signature protocols with its efficient single-round signing procedure. PyFrost utilizes the standard FROST protocol for single-round signing operations. Additionally, it incorporates the [Identifiable Cheating Entity FROST Signature Protocol](https://eprint.iacr.org/2021/1658.pdf) within the *distributed key generation (DKG)* framework. This approach is designed to detect and mitigate potential malicious behavior, such as when cheating entities selectively share secrets during the DKG process to exclude honest participants.

[This tutorial](https://github.com/SAYaghoubnejad/pyfrost/wiki/PyFrost-TSS-Protocl) provides an introduction to cryptographic concepts integral to PyFrost, including Threshold Signatures, Distributed Key Generation, Cheating Identification, Standard Schnorr Signatures, and Single-Round Schnorr Threshold Signatures.

PyFrost implements the cryptographic functions of the FROST protocol and includes a networking package that features libp2p clients for nodes, signature aggregators, and distributed key generators.


## Cryptography Classes & Functions

```python
pyfrost.KeyGen(self, dkg_id, threshold, n, node_id, partners, coefficient0=None)
```
- **Description:** This class is responsible for generating a distributed key based on the FROST algorithm. After key generation, `KeyGen.dkg_key_pair` should be saved, and this object can be deleted.
- **Inputs:**
  - `dkg_id` **str**: The ID corresponding to the key that will be generated.
  - `threshold` **int**: The threshold of the key (i.e., $t$).
  - `n` **int**: The total number of nodes contributing to the generation of this key.
  - `node_id` **str**: The ID of the current node.
  - `partners` **List[str]**: The list of all nodes' IDs contributing to the generation of this key.
  - `coefficient0` **int**, **default=None**: The coefficient of $x^0$ (i.e., $a_0$) of the polynomial generated in `round1()`.
- **Example:**
  ```python
  >>> key_gen = KeyGen(dkg_id, threshold, n, node_id, partners)
  ```

- **Functions:**
  ```python
  pyfrost.KeyGen.round1(self)
  ```
  - **Description:** Initiates the *distributed key generation (DKG)* by generating a key pair (used for securing communication in subsequent rounds against eavesdropping) and a $t$-degree polynomial for the distributed key. Then, it returns the data that needs to be broadcast to other nodes in the network for the following round of DKG.
  - **Inputs:** `None`
  - **Outputs:** 
    - Returns the data (as a dictionary) that needs to be broadcast to all nodes in the party.
  - **Example:**
    ```python
    >>> key_gen.round1()
    {'sender_id': '1', 'public_fx': [296640523581457280785321718557273115703301708752107592117643511688805891761985, 319296799114006137153383306229340950225807211995602402243547077190257497474828], 'coefficient0_signature': {'nonce': 368942311427213970711406313762610833921296939621501937670638697118598845895953, 'signature': '0x52ca633d6e48489339ebe80bf1489d36c99c68ed1f5c61b8db09ecfc917557007812ebeee6dece5c0e1aded3ea573c8e6af7eaad4cd96113668da6ffa0736a22'}, 'public_key': 307729343603318599981084289508680930914727331224976629990450023311552521321408, 'secret_signature': {'nonce': 367543012542554800983038202897799609990958678036817100887904340714911085163518, 'signature': '0x22b4921be19840bc3c944498f15bca02ad491795b4e55fa4eb3429b6ecca66b55526dc8425f6d49b72ee5370332368251f776d85f49f7cd89a1cda7000c25821'}}
    ```

  ```python
  pyfrost.KeyGen.round2(self, round1_broadcasted_data)
  ```
  - **Description:** Processes the second round of DKG by handling `round1_broadcasted_data` from other party nodes. It generates data to be shared between node pairs, encrypting it with the sender's private key and the receiver's public key (generated at the beginning of `round1`).
  - **Inputs:**
    - `round1_broadcasted_data` **dict**: Data broadcasted in `round1` by all other party nodes.
  - **Outputs:** 
    - Returns the data (as a dictionary) to be sent to each node.
  - **Example:**
    ```python
    >>> broadcasted_data = [{'sender_id': '1', 'public_fx': [296640523581457280785321718557273115703301708752107592117643511688805891761985, 319296799114006137153383306229340950225807211995602402243547077190257497474828], 'coefficient0_signature': {'nonce': 368942311427213970711406313762610833921296939621501937670638697118598845895953, 'signature': '0x52ca633d6e48489339ebe80bf1489d36c99c68ed1f5c61b8db09ecfc917557007812ebeee6dece5c0e1aded3ea573c8e6af7eaad4cd96113668da6ffa0736a22'}, 'public_key': 307729343603318599981084289508680930914727331224976629990450023311552521321408, 'secret_signature': {'nonce': 367543012542554800983038202897799609990958678036817100887904340714911085163518, 'signature': '0x22b4921be19840bc3c944498f15bca02ad491795b4e55fa4eb3429b6ecca66b55526dc8425f6d49b72ee5370332368251f776d85f49f7cd89a1cda7000c25821'}}, {'sender_id': '2', 'public_fx': [315333036490095729854689446035420143622165005650260428363337601379831192199151, 380936697578552696715385406651703109495058306480643748360338356258272131197597], 'coefficient0_signature': {'nonce': 359282259074835379588366874028459345193077877777157055998768953650753776127657, 'signature': '0x949dcaa392ed3b5eaace5bc0eca84149e377886bcfe70044e773d2b22b44e827c9f48274de0393f2a5160eb34f47bc71b53126559ee49aa3aaa47a5fe1e6f81a'}, 'public_key': 402675427562676615467995045686975527154837997106518064654470189954486747681481, 'secret_signature': {'nonce': 383615891867749631411403307342088317807707823769149008762193706230308867138628, 'signature': '0xf531cdf1e708fa8b8d3887eb8698230e99062ad59d204793b84aa4b82678e035399d0205ba340c6457ffe0552bd42f101a553e7082ee6043b31110bdc40bbe6c'}}]
    >>> key_gen.round2(broadcasted_data)
    [{'receiver_id': '2', 'sender_id': '1', 'data': 'gAAAAABliu7Eb9BTXwCmwWD3lX6el4ubygJ0SmyZpWNAMHR3-GEedQ5GuZshqy6VyuuRBrAfnET1iN1y9qeqK21NW-GuIEeNn5YQwVrf4_CTmZdxYjQXXpPAFHkRhJQk4nCCeOj5nRF5mllvpKp88-h_sGCQbaGERBiPjQUfmZNYX93puo1T6h3Yve7__uSuElgyU_WNsEWsKNR04utLEpQI0fCrAUy70A=='}]
    ```

  ```python
  pyfrost.KeyGen.round3(self, round2_encrypted_data)
  ```
  - **Description:** Calculates the node's share of the distributed key, reporting the share and corresponding key, signed with the node's permanent secret for verification (to set the new key on contract). In case of failure due to other nodes' dishonesty, it reports malicious activity.
  - **Inputs:**
    - `round2_encrypted_data` **dict**: Data received in `round2` where this node is the receiver.
  - **Outputs:** 
    - Returns a dictionary containing `status` and `data`. If `status` is `SUCCESSFUL`, `data` includes the distributed key, the node's share of this key, and a signature. If `status` is `COMPLAINT`, it contains evidence of another node's dishonesty.
  - **Example:**
    ```python
    >>> secret_data = [{'receiver_id': '1', 'sender_id': '2', 'data': 'gAAAAABliu7E9tMtv2EQeobFyDqXfnP024HnQLzWr_NeGKXB0aQhAiuyGOI490sZ031vMYm0yjRYOFcWvcxMXTPEDC9vMzB426NwzIGFWcfdB4KlC2KXctDqltF22v7N1ZbhpXNUpZqHc-iUL0_i7sOx5KYOoTO72Z_v08WzAPI7D6S8hAo2W_WD9l0ThrDqKUjTk1D1Lb1OXJ9XUOxYva9VDMFM67tWcw=='}]
    >>> key_gen.round3(secret_data)
    {'data': {'dkg_public_key': 254503007646527296878921173802219136565731252590780601714649547124390052407428, 'public_share': 434857518911403231281957735014346859455075805194991608153904732048854704562605}, 'dkg_key_pair': {'share': 188845194665176481294923561223805344235489278818067835766967751779434009802288, 'dkg_public_key': 254503007646527296878921173802219136565731252590780601714649547124390052407428}, 'status': 'SUCCESSFUL'}
    ```

```python
pyfrost.Key(self, dkg_key, node_id)
```
- **Description:** This class represents the FROST key that can be used for signing.
- **Inputs:**
  - `dkg_key` **Dict**: A dictionary containing the share of the key owned by this node and the corresponding distributed public key.
  - `node_id` **str**: The ID of the current node.
- **Example:**
  ```python
  >>> key = Key(key_pair, self.peer_id)
  ```

- **Functions:**
  ```python
  pyfrost.Key.sign(self, commitments_dict, message, nonces)
  ```
  - **Description:** This function generates a part of the signature using the respective share of the distributed key it owns.  
  - **Inputs:**
    - `commitments_dict` **Dict**: A dictionary containing nonces from all nodes contributing to signature generation (which should be ≥ $t$

).
    - `message` **str**: The message to be signed.
    - `nonces` **Dict**: A dictionary containing all the nonces that this node has generated.
  - **Outputs:** 
    - Returns a pair of `(signature, used_nonce)`. `signature` is a dictionary containing the part of the signature that this node is responsible for generating. `used_nonce` indicates the nonce that was used in this signature and should be deleted.
  - **Example:**
    ```python
    >>> nonces_list = {'1': {'id': 1, 'public_nonce_d': 349042186269687657903918029097021035946240790024363563457247123869466727724904, 'public_nonce_e': 248237425400201679908511118467475923008578021798639515998329304887202095480425}, '2': {'id': 2, 'public_nonce_d': 232003305522782618192381500560408473570697895814518143723528305421500512412148, 'public_nonce_e': 317715046800072131083613892686194614787279733126861218939601214450999918821174}}
    >>> message_hash = '651ecdfb1cbc7917644f5c3e16f014ac416470b990793e0ed5c2d2eb892d8c7f'
    >>> nonces = [{'nonce_d_pair': {300218555050360092639063393209864207073501829680650048817838305094710368296737: 50204928300747094776366629272534245963307256198160244371740708017884005477910}, 'nonce_e_pair': {409714228498631570327782540584825593750693294519645628405851081581014656246735: 40463726040983254619472478804244838052786844837455652103326243989755717359788}}, {'nonce_d_pair': {349042186269687657903918029097021035946240790024363563457247123869466727724904: 16993156636626924328333038649772197657544489298745516775023187369640192487374}, 'nonce_e_pair': {248237425400201679908511118467475923008578021798639515998329304887202095480425: 100635936258925530229391130527915553787668889110040645976804851747656014449457}}]
    >>> key.sign(nonces_list, message_hash, nonces)
    ({'id': 1, 'signature': 102694053038190246370608485838590127748578269475777603993528845385451820908381, 'public_key': 434857518911403231281957735014346859455075805194991608153904732048854704562605, 'aggregated_public_nonce': 402344336404068161625970842224046931385487524799112280264088906225521846642963},
    {'nonce_d_pair': {349042186269687657903918029097021035946240790024363563457247123869466727724904: 16993156636626924328333038649772197657544489298745516775023187369640192487374}, 'nonce_e_pair': {248237425400201679908511118467475923008578021798639515998329304887202095480425: 100635936258925530229391130527915553787668889110040645976804851747656014449457}})
    ```

```python
pyfrost.create_nonces(node_id, number_of_nonces)
```
- **Description:** This function generates a batch of nonces used when issuing signatures.  
- **Inputs:**
  - `node_id` **int**: The ID of the current node.
  - `number_of_nonces` **int**, **default=10**: The number of nonces requested to be generated.
- **Outputs:** 
  - Returns a pair of `(nonce_publics, nonce_privates)`. `nonce_publics` is a dictionary containing the public part of the nonce that should be sent to the Signature Aggregator (`SA`). `nonce_privates` indicates the private part of the nonce that should be stored in the `Node`.
- **Example:**
  ```python
  >>> node_id = 1 
  >>> number_of_nonces = 2
  >>> pyfrost.create_nonces(node_id, number_of_nonces)
  ([{'id': 1, 'public_nonce_d': 300218555050360092639063393209864207073501829680650048817838305094710368296737, 'public_nonce_e': 409714228498631570327782540584825593750693294519645628405851081581014656246735}, {'id': 1, 'public_nonce_d': 349042186269687657903918029097021035946240790024363563457247123869466727724904, 'public_nonce_e': 248237425400201679908511118467475923008578021798639515998329304887202095480425}],
  [{'nonce_d_pair': {300218555050360092639063393209864207073501829680650048817838305094710368296737: 50204928300747094776366629272534245963307256198160244371740708017884005477910}, 'nonce_e_pair': {409714228498631570327782540584825593750693294519645628405851081581014656246735: 40463726040983254619472478804244838052786844837455652103326243989755717359788}}, {'nonce_d_pair': {349042186269687657903918029097021035946240790024363563457247123869466727724904: 16993156636626924328333038649772197657544489298745516775023187369640192487374}, 'nonce_e_pair': {248237425400201679908511118467475923008578021798639515998329304887202095480425: 100635936258925530229391130527915553787668889110040645976804851747656014449457}}])
  ```

```python
pyfrost.aggregate_nonce(message, commitments_dict, group_key)
```
- **Description:** This function is used to aggregate nonces and calculate an aggregated nonce used for verifying the aggregated signature.
- **Inputs:**
  - `message` **str**: The message that was signed.
  - `commitments_dict` **Dict**: A dictionary containing nonces from all nodes contributing to the signature to be aggregated.
  - `group_key` **Point**: A point indicating the distributed key generated using `KeyGen`.
- **Outputs:** 
  - Returns a **Point** indicating the aggregated nonce.
- **Example:**
  ```python
  >>> str_message = '651ecdfb1cbc7917644f5c3e16f014ac416470b990793e0ed5c2d2eb892d8c7f'
  >>> nonces_list = {'1': {'id': 1, 'public_nonce_d': 349042186269687657903918029097021035946240790024363563457247123869466727724904, 'public_nonce_e': 248237425400201679908511118467475923008578021798639515998329304887202095480425}, '2': {'id': 2, 'public_nonce_d': 232003305522782618192381500560408473570697895814518143723528305421500512412148, 'public_nonce_e': 317715046800072131083613892686194614787279733126861218939601214450999918821174}}
  >>> dkg_public_key = 254503007646527296878921173802219136565731252590780601714649547124390052407428
  >>> pyfrost.aggregate_nonce(str_message, nonces_list, dkg_public_key)
  X: 0x7986d308d799825889680f6424a9e82141c2c70433ff832466425032036fe913
  Y: 0xfd598e318ca0a073f2a067a51aaca79b13264be5b9c23c8132a5e3f7d16ab71d
  (On curve <secp256k1>)
  ```

```python
pyfrost.aggregate_signatures(message, single_signatures, aggregated_public_nonce, group_key)
```
- **Description:** This function is used to aggregate signatures and calculate an aggregated signature that is verifiable by anyone.
- **Inputs:**
  - `message` **str**: The message that was signed.
  - `single_signatures` **List[Dict[str, int]]**: A list containing shares of the signature that each node generates.
  - `aggregated_public_nonce` **Point**: The aggregated nonce.
  - `group_key` **int**: An integer indicating the distributed key generated using `KeyGen`.
- **Outputs:** 
  - Returns a dictionary containing all data needed to verify the aggregated signature (i.e., `nonce`, `public_key`, `aggregated_signature`, `message_hash`).
- **Example:**
  ```python
  >>> str_message = '651ecdfb1cbc7917644f5c3e16f014ac416470b990793e0ed5c2d2eb892d8c7f'
  >>> signs = [{'id': 1, 'signature': 102694053038190246370608485838590127748578269475777603993528845385451820908381, 'public_key': 434857518911403231281957735014346859455075805194991608153904732048854704562605, 'aggregated_public_nonce': 402344336404068161625970842224046931385487524799112280264088906225521846642963}, {'id': 2, 'signature': 46567393939448326584842681154363617834812892542107946395797044035032337911003, 'public_key': 245652561208681254624868566825006163495824337574238825910552301225881840535843, 'aggregated_public_nonce': 402344336404068161625970842224046931385487524799112280264088906225521846642963}]
  >>> aggregated_public_nonce = X: 0x7986d308d799825889680f6424a9e82141c2c70433ff832466425032036fe913
  Y: 0xfd598e318ca0a073f2a067a51aaca79b13264be5b9c23c8132a5e3f7d16ab71d
  (On curve <secp256k1>)
  >>> dkg_public_key = 254503007646527296878921173802219136565731252590780601714649547124390052407428
  >>> pyfrost.aggregate_signatures(str_message, signs, aggregated_public_nonce, dkg_public_key)
  {'nonce': '0x4002743DBbB944415e22F987B1B0c1b57F3F01c5', 'public_key': {'x': '0x32ab98fd4f3959e532d73d93a9611edaf60ea456166ef8f333fe7c6784caa884', 'y_parity': 0}, 'signature': 33469357740322377531880181984265837730553597738810646006720726278965997325047, 'message_hash': HexBytes('0x260f59626b383fe31873d9bef3f6a5262af6206e8eb50088da9e41fb9e87dc41')}

  ```

```python
pyfrost.verify_group_signature(aggregated_signature)
```
- **Description:** This function verifies the aggregated signature.
- **Inputs:**
  - `aggregated_signature` **Dict**: A dictionary containing `nonce`, `public_key`, `aggregated_signature`, `message_hash`.
- **Outputs:** 
  - Returns a boolean indicating whether the signature is verified or not.
- **Example:**
  ```python
  >>> aggregated_sign = {'nonce': '0x4002743DBbB944415e22F987B1B0c1b57F3F01c5', 'public_key': {'x': '0x32ab98fd4f3959e532d73d93a9611edaf60ea456166ef8f333fe7c6784caa884', 'y_parity': 0}, 'signature': 33469357740322377531880181984265837730553597738810646006720726278965997325047, 'message_hash': HexBytes('0x260f59626b383fe31873d9bef3f6a5262af6206e8eb50088da9e41fb9e87dc41')}
  >>> pyfrost.frost.verify_group_signature(aggregated_sign)
  True
  ```

```python
pyfrost.verify_single_signature(id, message, commitments, aggregated_nonce, public_key_share, signature, group_key)
```
- **Description:** This function verifies the share of the signature generated by each node.
- **Inputs:**
  - `id` **int**: The ID of the current node.
  - `message` **str**: The message that was signed.
  - `commitments` **Dict**: A dictionary containing nonces from all nodes contributing to signature generation.
  - `aggregated_nonce` **Point**: The aggregated nonce.
  - `public_key_share` **int**: The node's share of the distributed key (i.e., `group_key`).
  - `signature` **Dict**: The node's generated share of the signature.
  - `group_key` **Point**: A point indicating the distributed key generated using `KeyGen`.
- **Outputs:** 
  - Returns a boolean indicating whether the share of the signature is verified or not.
- **Example:**
  ```python
  >>> sign['id'], msg, nonces_list, aggregated_public_nonce, dkg_key['public_shares'][str(sign['id'])], sign, dkg_key['public_key'])
  >>> id = 1
  >>> str_message = '651ecdfb1cbc7917644f5c3e16f014ac416470b990793e0ed5c2d2eb892d8c7f'
  >>> nonces_list = {'1': {'id': 1, 'public_nonce_d': 349042186269687657903918029097021035946240790024363563457247123869466727724904, 'public_nonce_e': 248237425400201679908511118467475923008578021798639515998329304887202095480425}, '2': {'id': 2, 'public_nonce_d': 232003305522782618192381500560408473570697895814518143723528305421500512412148, 'public_nonce_e': 317715046800072131083613892686194614787279733126861218939601214450999918821174}}
  >>> aggregated_public_nonce = X: 0x7986d308d799825889680f6424a9e82141c2c70433ff832466425032036fe913
  Y: 0xfd598e318ca0a073f2a067a51aaca79b13264be5b9c23c8132a5e3f7d16ab71d
  (On curve <secp256k1>)
  >>> public_share = 434857518911403231281957735014346859455075805194991608153904732048854704562605
  >>> sign = {'id': 1, 'signature': 102694053038190246370608485838590127748578269475777603993528845385451820908381, 'public_key': 434857518911403231281957735014346859455075805194991608153904732048854704562605, 'aggregated_public_nonce': 402344336404068161625970842224046931385487524799112280264088906225521846642963}
  >>> dkg_public_key = 254503007646527296878921173802219136565731252590780601714649547124390052407428
  >>> pyfrost.pyfrost.verify_single_signature(id, str_message, nonces_list, aggregated_public_nonce, public_share, sign, dkg_public_key)
  True
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

| Benchmark                     | DKG Time | Avg. Time per Node for Nonce Generation | Signing Time |
|-------------------------------|----------|----------------------------------------|--------------|
|  7 of 10                      | 0.840 sec| 0.352 sec                              | 0.135 sec    | 
| 15 of 20                      | 5.435 sec| 0.344 sec                              | 0.380 sec    |
| 25 of 30                      |14.183 sec| 0.345 sec                              | 0.601 sec    |

For the non-local evaluation, we utilized 30 node containers spread across three countries and four cities. Additionally, the Signature Aggregator was configured with dual vCPUs and 8GB of RAM.

| Benchmark                     | DKG Time | Avg. Time per Node for Nonce Generation | Signing Time |
|-------------------------------|----------|----------------------------------------|--------------|
| 25 of 30                      | 7.400 sec| 1.594 sec                              | 0.725 sec    |