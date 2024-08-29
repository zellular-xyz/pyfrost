from bitcoinutils.keys import PrivateKey, P2trAddress
from bitcoinutils.utils import to_satoshis

from pyfrost.btc_transaction_utils import broadcast_tx, deposit_to_zex
from pyfrost.zbtc.config import MPC_ADDRESS, DepositType
from pyfrost.zbtc.setting import BTC_PRIVATE_KEY

eth_address = "0x0f525aF4819B2AC15CB2883094CCB1Ab0B4e1ac3"
private = PrivateKey.from_bytes(BTC_PRIVATE_KEY)
pub = private.get_public_key().get_segwit_address()
amount = to_satoshis(10000e-8)
fee = to_satoshis(2000e-8)

signed_tx = deposit_to_zex(
    private=private,
    pub=pub,
    change_pub=pub,
    zex_pub=P2trAddress(MPC_ADDRESS),
    deposit_sat=amount,
    fee_sat=fee,
    eth_address=eth_address.replace("0x", ""),
    type=DepositType.WITHDRAW,
)

resp = broadcast_tx(signed_tx)
print("Tx Hash:", resp.text)
