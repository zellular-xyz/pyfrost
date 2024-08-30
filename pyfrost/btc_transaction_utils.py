import json
import secrets
import string

import requests
from bitcoinutils.keys import P2trAddress, P2wpkhAddress, PublicKey, PrivateKey
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput
from bitcoinutils.script import Script
from bitcoinutils.setup import setup
from bitcoinutils.constants import TAPROOT_SIGHASH_ALL

import pyfrost.frost as frost
from pyfrost.crypto_utils import code_to_pub
from pyfrost.zbtc.config import BASE_URL, BTC_NETWORK, DepositType

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
    eth_address,
):
    single_spend_tx = get_deposit(
        single_spend_txid, to_address, from_address, DepositType.WITHDRAW
    )
    assert (
        single_spend_tx["bitcoin_address"] == to_address
    ), f"The withdraw transaction is from address {single_spend_tx['bitcoin_address']} and cannot send funds to {to_address}"
    assert (
        int(single_spend_tx["eth_address"], 16) == int(eth_address, 16)
    ), f"{eth_address} initiates burn transaction, and the address on withdraw is {single_spend_tx['eth_address']}"

    from_address = P2trAddress(from_address)
    to_address = P2wpkhAddress(to_address)

    txins = [TxInput(utxo["txid"], utxo["vout"]) for utxo in utxos]
    amounts = [utxo["value"] for utxo in utxos]

    txins.append(TxInput(single_spend_txid, single_spend_vout))
    amounts.append(single_spend_tx["amount"])
    send_amount += single_spend_tx["amount"] - fee_amount

    first_amount = sum(amounts)

    txout1 = TxOutput(send_amount, to_address.to_script_pub_key())
    txout2 = TxOutput(first_amount - send_amount, from_address.to_script_pub_key())

    first_script_pubkey = from_address.to_script_pub_key()
    utxos_script_pubkeys = [first_script_pubkey] * len(txins)

    tx = Transaction(txins, [txout1, txout2], has_segwit=True)
    tx_digests = [
        tx.get_transaction_taproot_digest(
            i, utxos_script_pubkeys, amounts, 0, sighash=TAPROOT_SIGHASH_ALL
        )
        for i in range(len(txins))
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
        url = f"{BASE_URL}/tx/{utxo['txid']}"
        tx = requests.get(url).json()
        op_pushnum = f"OP_PUSHNUM_{DepositType.WITHDRAW}"
        is_deposit_for_withdraw = any(
            [
                out["scriptpubkey_type"] == "op_return"
                and op_pushnum in out["scriptpubkey_asm"]
                for out in tx["vout"]
            ]
        )
        if is_deposit_for_withdraw:
            continue
        if total_value >= desired_amount:
            break
        selected_utxos.append(utxo)
        total_value += utxo["value"]
    return selected_utxos


def get_deposit(tx_hash: str, bitcoin_address: str, mpc_wallet: str, type: DepositType):
    url = f"{BASE_URL}/tx/{tx_hash}"
    print(url)
    tx = requests.get(url).json()
    op_pushnum = f"OP_PUSHNUM_{type.value}"
    assert tx["status"]["confirmed"], "tx does not have enough confirmations"
    outputs = tx["vout"]
    check = (
        lambda out: out["scriptpubkey_type"] == "v1_p2tr"
        and out["scriptpubkey_address"] == mpc_wallet
    )
    amount = sum([out["value"] for out in outputs if check(out)])
    assert amount > 0, f"no pay-to-taproot deposit to {mpc_wallet}"

    data = [
        str(out["scriptpubkey_asm"]).split(" ")[-1]
        for out in outputs
        if out["scriptpubkey_type"] == "op_return"
        and op_pushnum in out["scriptpubkey_asm"]
    ]
    assert (
        len(data) > 0
    ), f"dest eth address is not included as {type.name} OP RETURN output"
    eth_address = f"0x{data[0]}"
    validated = (
        all(c in string.hexdigits for c in eth_address[2:]) and len(eth_address) == 42
    )
    assert validated, f"{eth_address} is not valid eth address"

    return {
        "tx": tx["txid"],
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
    type: DepositType,
) -> str:
    utxos = get_utxos(pub.to_string(), fee_sat + deposit_sat)
    tx_ins = []
    amounts = []
    for utxo in utxos:
        tx_in = TxInput(utxo["txid"], utxo["vout"])
        tx_ins.append(tx_in)
        amounts.append(utxo["value"])
    tx_outs = [
        TxOutput(deposit_sat, zex_pub.to_script_pub_key()),
        TxOutput(0, Script(["OP_RETURN", type.value, eth_address])),
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
    url = f"{BASE_URL}/tx"
    response = requests.post(url, data=raw_tx, headers={"Content-Type": "text/plain"})
    return response
