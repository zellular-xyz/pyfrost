import json
import random
import secrets
import string

import requests
from bitcoinutils.keys import P2trAddress, P2wpkhAddress, PublicKey, PrivateKey
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput
from bitcoinutils.script import Script
from bitcoinutils.setup import setup
from bitcoinutils.constants import TAPROOT_SIGHASH_ALL
import pyfrost.frost as frost
from pyfrost.crypto_utils import code_to_pub, pub_to_code


def get_burned(tx_hash, web3, contract_address):
    contract_abi = json.loads("""[
        {
            "anonymous": false,
            "inputs": [
                {"indexed": true, "internalType": "address", "name": "burner", "type": "address"},
                {"indexed": false, "internalType": "uint256", "name": "amount", "type": "uint256"},
                {"indexed": false, "internalType": "bytes", "name": "bitcoinAddress", "type": "bytes"},
                {"indexed": false, "internalType": "uint256", "name": "singleSpendTx", "type": "uint256"}
            ],
            "name": "Burned",
            "type": "event"
        }
    ]""")
    contract = web3.eth.contract(address=contract_address, abi=contract_abi)
    receipt = web3.eth.get_transaction_receipt(tx_hash)

    # Iterate over logs and decode the Burned event
    for log in receipt["logs"]:
        if log["address"].lower() == contract_address.lower():
            try:
                decoded_log = contract.events.Burned().process_log(log)
                return {
                    "burner": decoded_log["args"]["burner"],
                    "amount": decoded_log["args"]["amount"],
                    "bitcoinAddress": decoded_log["args"]["bitcoinAddress"].hex(),
                    "singleSpendTx": hex(decoded_log["args"]["singleSpendTx"])[2:],
                }
            except Exception:
                continue

    return None


def get_taproot_address(public_key):
    public_key = code_to_pub(public_key)
    x_hex = hex(public_key.x)[2:].zfill(64)
    y_hex = hex(public_key.y)[2:].zfill(64)
    prefix = "02" if int(y_hex, 16) % 2 == 0 else "03"
    compressed_pubkey = prefix + x_hex
    public_key = PublicKey(compressed_pubkey)
    taproot_address = public_key.get_taproot_address()
    return taproot_address


def dkg(dkg_id, t, n, party):
    assert len(party) == n, f"party length does not match n: {n}!={len(party)}"
    base_coef0 = (
        76622783108274780747756398270842445905196011304614807988789919767093500641526
    )
    coef0 = [base_coef0 + i for i in range(n)]

    keys: list[frost.KeyGen] = []
    sign_keys: list[frost.Key] = []

    for coef0, node_id in zip(coef0, party):
        partners = party.copy()
        partners.remove(node_id)
        keys.append(frost.KeyGen(dkg_id, t, n, node_id, partners, coef0))

    round1_received_data = []
    for key in keys:
        round1_send_data = key.round1()
        round1_received_data.append(round1_send_data)
    round2_received_data = {}
    for node_id in party:
        round2_received_data[node_id] = []
    for key in keys:
        round2_send_data = key.round2(round1_received_data)
        for message in round2_send_data:
            round2_received_data[message["receiver_id"]].append(message)
    dkg_keys = set()
    for key in keys:
        result = key.round3(round2_received_data[key.node_id])
        dkg_keys.add(result["data"]["dkg_public_key"])
        sign_keys.append(frost.Key(key.dkg_key_pair, key.node_id))
    return sign_keys


def get_nonces(party):
    nonces = {"common_data": {}, "private_data": {}}
    for node_id in party:
        nonces_common_data, nonces_private_data = frost.create_nonces(int(node_id), 3)
        nonces["common_data"][node_id] = nonces_common_data
        nonces["private_data"][node_id] = nonces_private_data
    return nonces


def sign(sign_keys, nonces, t, msg):
    sign_subset = random.sample(sign_keys, t)
    signs = []
    agregated_nonces = []
    first_nonces = {
        key.node_id: nonces["common_data"][key.node_id][0] for key in sign_subset
    }
    for key in sign_subset:
        single_sign, remove_data = key.sign(
            first_nonces,
            msg,
            nonces["private_data"][key.node_id],
        )
        # saved_data["private_data"][key.node_id]["nonces"].remove(remove_data)
        agregated_nonces.append(single_sign["aggregated_public_nonce"])
        signs.append(single_sign)
    group_sign = frost.aggregate_signatures(
        msg,
        signs,
        agregated_nonces[0],
        pub_to_code(sign_subset[0].dkg_key_pair["dkg_public_key"]),
    )
    return group_sign


def get_withdraw_tx(
    from_address,
    utxos,
    to_address,
    send_amount,
    fee_amount,
    single_spend_txid,
    single_spend_vout,
):
    setup("testnet")

    from_address = P2trAddress(from_address)
    first_script_pubkey = from_address.to_script_pub_key()
    utxos_script_pubkeys = [first_script_pubkey]
    to_address = P2wpkhAddress(to_address)

    txins = [TxInput(utxo["tx_hash"], utxo["tx_output_n"]) for utxo in utxos]
    amounts = [utxo["value"] for utxo in utxos]

    txins.append(TxInput(single_spend_txid, single_spend_vout))
    amounts.append(1)

    first_amount = sum(amounts)

    txout1 = TxOutput(send_amount, to_address.to_script_pub_key())
    txout2 = TxOutput(
        first_amount - send_amount - fee_amount, from_address.to_script_pub_key()
    )

    tx = Transaction(txins, [txout1, txout2], has_segwit=True)
    tx_digest = tx.get_transaction_taproot_digest(
        0, utxos_script_pubkeys, amounts, 0, sighash=TAPROOT_SIGHASH_ALL
    )
    return tx, tx_digest


def get_utxos(bitcoin_address, desired_amount):
    url = f"https://api.blockcypher.com/v1/btc/test3/addrs/{bitcoin_address}?unspentOnly=true"
    response = requests.get(url)
    utxos = response.json().get("txrefs", [])
    total_value = 0
    selected_utxos = []
    for utxo in utxos:
        if utxo["value"] == 1:
            continue
        if total_value >= desired_amount:
            break
        selected_utxos.append(utxo)
        total_value += utxo["value"]
    return selected_utxos


def get_deposit(tx_hash, public_key_hex, mpc_wallet):
    public_key = PublicKey(public_key_hex)
    # todo: other types of bitcoin addresses should be implemented
    bitcoin_address = public_key.get_segwit_address().to_string()

    url = f"https://api.blockcypher.com/v1/btc/test3/txs/{tx_hash}"
    tx = requests.get(url).json()
    assert tx["confirmations"] >= 1, "tx does not have enough confirmations"
    outputs = tx["outputs"]
    check = lambda out: out["script_type"] == "pay-to-taproot" and out["addresses"] == [
        mpc_wallet
    ]
    amount = sum([out["value"] for out in outputs if check(out)])
    assert amount > 0, f"no pay-to-taproot deposit to {mpc_wallet}"

    data = [out["data_hex"] for out in outputs if out["script_type"] == "null-data"]
    assert len(data) > 0, "dest eth address is not included as OP RETURN output"
    eth_address = f"0x{data[0]}"
    validated = (
        all(c in string.hexdigits for c in eth_address[2:]) and len(eth_address) == 42
    )
    assert validated, f"{eth_address} is not valid eth address"

    print("Source Bitcoin Address:", bitcoin_address)
    print("Amount:", amount)
    print("Dest ETH Address:", eth_address)
    return {
        "tx": tx["hash"],
        "amount": amount,
        "bitcoin_address": bitcoin_address,
        "eth_address": eth_address,
    }


def new_wallet() -> tuple[PrivateKey, P2wpkhAddress]:
    priv = PrivateKey.from_bytes(secrets.token_bytes(32))
    return priv, priv.get_public_key().get_segwit_address()


def deposit_to_zex(
    private: PrivateKey,
    pub: P2wpkhAddress,
    change_pub: P2wpkhAddress,
    zex_pub: P2trAddress,
    deposit_sat: int,
    fee_sat: int,
    eth_address: str,
) -> str:
    utxos = get_utxos(pub.to_string(), fee_sat + deposit_sat)
    tx_ins = []
    amounts = []
    for utxo in utxos:
        tx_in = TxInput(utxo["tx_hash"], utxo["tx_output_n"])
        tx_ins.append(tx_in)
        amounts.append(utxo["value"])
    tx_outs = [
        TxOutput(deposit_sat, zex_pub.to_script_pub_key()),
        TxOutput(0, Script(["OP_RETURN", eth_address])),
    ]

    if sum(amounts) > fee_sat + deposit_sat:
        tx_outs.append(
            TxOutput(
                sum(amounts) - (fee_sat + deposit_sat), change_pub.to_script_pub_key()
            )
        )

    tx = Transaction(tx_ins, tx_outs, has_segwit=True)

    script_code = Script(
        [
            "OP_DUP",
            "OP_HASH160",
            private.get_public_key().to_hash160(),
            "OP_EQUALVERIFY",
            "OP_CHECKSIG",
        ]
    )
    for i, utxo in enumerate(utxos):
        sig = private.sign_segwit_input(tx, i, script_code, amounts[i])

        tx.witnesses.append(TxWitnessInput([sig, private.get_public_key().to_hex()]))

    return tx.serialize()


def broadcast_tx(raw_tx: str):
    url = "https://api.blockcypher.com/v1/btc/test3/txs/push"
    data = {"tx": raw_tx}
    response = requests.post(url, json=data)
    return response
