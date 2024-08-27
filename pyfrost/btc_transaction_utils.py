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
from pyfrost.zbtc.config import BASE_URL, BTC_NETWORK

setup(BTC_NETWORK)


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


def get_nonces(party):
    nonces = {"common_data": {}, "private_data": {}}
    for node_id in party:
        nonces_common_data, nonces_private_data = frost.create_nonces(int(node_id), 3)
        nonces["common_data"][node_id] = nonces_common_data
        nonces["private_data"][node_id] = nonces_private_data
    return nonces


def get_withdraw_tx(
    from_address,
    utxos,
    to_address,
    send_amount,
    fee_amount,
    single_spend_txid,
    single_spend_vout,
):
    from_address = P2trAddress(from_address)
    first_script_pubkey = from_address.to_script_pub_key()
    utxos_script_pubkeys = [first_script_pubkey] * len(utxos)
    to_address = P2wpkhAddress(to_address)

    txins = [TxInput(utxo["txid"], utxo["vout"]) for utxo in utxos]
    amounts = [utxo["value"] for utxo in utxos]
    txins.append(TxInput(single_spend_txid, single_spend_vout))
    amounts.append(1)

    first_amount = sum(amounts)

    txout1 = TxOutput(send_amount, to_address.to_script_pub_key())
    txout2 = TxOutput(
        first_amount - send_amount - fee_amount, from_address.to_script_pub_key()
    )

    tx = Transaction(txins, [txout1, txout2], has_segwit=True)
    tx_digests = [
        tx.get_transaction_taproot_digest(
            i, utxos_script_pubkeys, amounts, 0, sighash=TAPROOT_SIGHASH_ALL
        )
        for i in range(len(utxos))
    ]
    return tx, tx_digests


def get_simple_withdraw_tx(from_address, utxos, to_address, send_amount, fee_amount):
    from_address = P2trAddress(from_address)
    first_script_pubkey = from_address.to_script_pub_key()
    utxos_script_pubkeys = [first_script_pubkey] * len(utxos)
    to_address = P2wpkhAddress(to_address)

    txins = [TxInput(utxo["txid"], utxo["vout"]) for utxo in utxos]
    amounts = [utxo["value"] for utxo in utxos]

    first_amount = sum(amounts)

    txout1 = TxOutput(send_amount, to_address.to_script_pub_key())
    txout2 = TxOutput(
        first_amount - send_amount - fee_amount, from_address.to_script_pub_key()
    )

    tx = Transaction(txins, [txout1, txout2], has_segwit=True)
    tx_digests = [
        tx.get_transaction_taproot_digest(
            i, utxos_script_pubkeys, amounts, 0, sighash=TAPROOT_SIGHASH_ALL
        )
        for i in range(len(utxos))
    ]
    return tx, tx_digests


def get_utxos(bitcoin_address, desired_amount):
    url = f"{BASE_URL}/address/{bitcoin_address}/utxo"
    response = requests.get(url)
    utxos = response.json()
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

    url = f"{BASE_URL}/txs/{tx_hash}"
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
