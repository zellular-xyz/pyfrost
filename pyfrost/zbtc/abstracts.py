import logging
import threading
import time
from urllib.parse import urlparse

from bitcoinutils.keys import PublicKey
from bitcoinutils.utils import to_satoshis
from web3 import Web3

from pyfrost.btc_transaction_utils import (
    get_utxos,
    get_simple_withdraw_tx,
    get_burned,
    get_deposit,
    get_withdraw_tx,
)
from pyfrost.network.abstract import Validators, DataManager, NodesInfo as BaseNodeInfo
from config import VALIDATED_IPS, ZBTC_ADDRESS, MPC_ADDRESS, DepositType
from typing import Dict
import hashlib

import json
import os


class NodeDataManager(DataManager):
    def __init__(
        self,
        dkg_keys_file="./pyfrost/zbtc/data/dkg_keys.json",
        nonces_file="./pyfrost/zbtc/data/nonces.json",
    ) -> None:
        super().__init__()
        self.dkg_keys_file = dkg_keys_file
        self.nonces_file = nonces_file

        # Load data from files if they exist
        self.__dkg_keys = self._load_data(self.dkg_keys_file)
        self.__nonces = self._load_data(self.nonces_file)

    def _load_data(self, file_path):
        if os.path.exists(file_path):
            with open(file_path, "r") as file:
                return json.load(file)
        return {}

    def _save_data(self, file_path, data):
        with open(file_path, "w") as file:
            json.dump(data, file, indent=4)

    def set_nonce(self, nonce_public: str, nonce_private: str) -> None:
        self.__nonces[nonce_public] = nonce_private
        self._save_data(self.nonces_file, self.__nonces)

    def get_nonce(self, nonce_public: str):
        data = self._load_data(self.nonces_file)
        return data.get(nonce_public)

    def remove_nonce(self, nonce_public: str) -> None:
        self.__nonces = self._load_data(self.nonces_file)
        if nonce_public in self.__nonces:
            del self.__nonces[nonce_public]
            self._save_data(self.nonces_file, self.__nonces)

    def set_key(self, key, value) -> None:
        self.__dkg_keys[key] = value
        self._save_data(self.dkg_keys_file, self.__dkg_keys)

    def get_key(self, key):
        data = self._load_data(self.dkg_keys_file)
        return data.get(key, {})

    def remove_key(self, key):
        self.__dkg_keys = self._load_data(self.dkg_keys_file)
        if key in self.__dkg_keys:
            del self.__dkg_keys[key]
            self._save_data(self.dkg_keys_file, self.__dkg_keys)


class NodeValidators(Validators):
    def __init__(self) -> None:
        super().__init__()

    @staticmethod
    def caller_validator(sender_ip: str, method: str):
        if method in VALIDATED_IPS.get(str(sender_ip), []):
            return True
        return False

    @staticmethod
    def data_validator(input_data: Dict):
        method = input_data["method"]
        data = input_data["data"]
        if method == "get_simple_withdraw_tx":
            from_address = data["from"]
            to_address = data["to"]
            fee = data["fee"]
            utxos = data["utxos"]
            tx_digest = bytes.fromhex(data["hash"])
            send_amount = data["send_amount"]
            tx, tx_digests = get_simple_withdraw_tx(
                from_address, utxos, to_address, send_amount, fee
            )
            if tx_digest in tx_digests:
                result = {
                    "input": input_data,
                    "sign_params": {"tx_digest": tx_digest.hex()},
                    "hash": tx_digest.hex(),
                }
                return result
            else:
                raise ValueError(f"Invalid Data: {input_data}")

        elif method == "get_withdraw_tx":
            rpc_url = "https://ethereum-holesky-rpc.publicnode.com"
            web3 = Web3(Web3.HTTPProvider(rpc_url))

            burn_tx_hash = data["burn_tx_hash"]
            tx_digest = bytes.fromhex(data["hash"])
            fee = data["fee"]
            utxos = data["utxos"]

            burned = get_burned(burn_tx_hash, web3, ZBTC_ADDRESS)
            logging.debug(f"Burn Info: {burned}")
            send_amount = burned["amount"]
            single_spend_txid = burned["singleSpendTx"]
            single_spend_vout = 0
            to_address = burned["bitcoinAddress"]
            to_address = PublicKey(to_address)
            to_address = to_address.get_segwit_address().to_string()
            burner_address = burned["burner"]

            tx, tx_digests = get_withdraw_tx(
                MPC_ADDRESS,
                utxos,
                to_address,
                send_amount,
                fee,
                single_spend_txid,
                single_spend_vout,
                burner_address,
            )
            if tx_digest in tx_digests:
                result = {
                    "input": input_data,
                    "sign_params": {"tx_digest": tx_digest.hex()},
                    "hash": tx_digest.hex(),
                }
                return result
            else:
                raise ValueError(f"Invalid Data: {input_data}")

        elif method == "mint":
            tx_hash = data["tx"]
            bitcoin_address = data["bitcoin_address"]
            amount = data["amount"]
            to = data["to"]
            message_hash = data["hash"]

            deposit = get_deposit(
                tx_hash, bitcoin_address, MPC_ADDRESS, DepositType.BRIDGE
            )
            msg = Web3.solidity_keccak(
                ["uint256", "uint256", "address"],
                [
                    int(deposit["tx"], 16),
                    deposit["amount"],
                    Web3.to_checksum_address(deposit["eth_address"]),
                ],
            ).hex()
            if (
                msg == message_hash
                and int(tx_hash, 16) == int(deposit["tx"], 16)
                and deposit["amount"] == amount
                and to == Web3.to_checksum_address(deposit["eth_address"])
            ):
                result = {
                    "input": input_data,
                    "sign_params": {
                        "tx": int(deposit["tx"], 16),
                        "amount": deposit["amount"],
                        "to": Web3.to_checksum_address(deposit["eth_address"]),
                    },
                    "hash": msg,
                }
                return result
            else:
                raise ValueError(f"Invalid Data: {input_data}")

        else:
            raise NotImplementedError()


class NodesInfo(BaseNodeInfo):
    prefix = "/pyfrost"
    subgraph_url = (
        "https://api.studio.thegraph.com/query/85556/bls_apk_registry/version/latest"
    )

    def __init__(self):
        self.nodes = {}
        self._stop_event = threading.Event()
        self.sync_with_subgraph()
        self.start_sync_thread()

    def sync_with_subgraph(self):
        query = """
        query MyQuery {
          operators(where: {registered: true}) {
            id
            operatorId
            pubkeyG1_X
            pubkeyG1_Y
            pubkeyG2_X
            pubkeyG2_Y
            socket
            stake
          }
        }
        """
        self.nodes = self._convert_operators_to_nodes(
            {
                "data": {
                    "operators": [
                        {
                            "id": 328770415483607537620835655248677510917372104546767211276878006445062912835143,
                            "operatorId": "0xfd17e3847a110c89925baf6daed35c6f1ddf8bc9c8b38a9bb41096535b5f97fd",
                            "pubkeyG1_X": "13136058664468634065216375495074052951238430846991157058743804374832267522753",
                            "pubkeyG1_Y": "11448663166422622690605895009604224092710018000821885173435009863555132846864",
                            "pubkeyG2_X": [
                                "10511559378400058845254311411570731849679292693017411812923774690860252808501",
                                "15620425198086360195633860348516614475072926775330350148765733898945732625720",
                            ],
                            "pubkeyG2_Y": [
                                "16017480246882045886082900913073979516950823832148982212683097568841948701108",
                                "14484632839742302641550896988066025133849822519077390584095458750594033151899",
                            ],
                            "socket": "http://127.0.0.1:6001",
                            "stake": "2974982461847618543",
                        },
                        {
                            "id": 366826606230888689541085718681786025668444134279884139140074940042583222575349,
                            "operatorId": "0x0d67cd10c7b7b113b067d42c84a40dee850474892d5647955fdcb7a108b642ed",
                            "pubkeyG1_X": "11399471800741056566877625555909729712376287795123904633138272159990180371807",
                            "pubkeyG1_Y": "10645553139467370838640057691282710801262607458640782135246892954426222314519",
                            "pubkeyG2_X": [
                                "8344850473033184686902482839436715877919563811752833276573923607099775865043",
                                "4287300409248618682415538776498257043987070039762239000711321122174379065112",
                            ],
                            "pubkeyG2_Y": [
                                "11807354621768019516854407377374237270594325804547558692677348859272579238961",
                                "20153654613358246757117843775082812593787681037043806947800580468943097651257",
                            ],
                            "socket": "http://127.0.0.1:6002",
                            "stake": "4776064595081970865",
                        },
                        {
                            "id": 324910018991026634260215376027343834221528157096062876921644580395908318623552,
                            "operatorId": "0xfe6ec3f9e9ad332de8fcdf8d630ccdc209d54e71fcd9cc866785cebe2db5197b",
                            "pubkeyG1_X": "16372471696281201100834877067300193172203705174007976156113229487517292180507",
                            "pubkeyG1_Y": "11195027664027499680857348217536701889329537780274329435496499469661205187126",
                            "pubkeyG2_X": [
                                "9129315811335480116895541563265372302966042939145012300375000784054906504662",
                                "8062867142918919339339326106766094266119169497663365068497830707296592726548",
                            ],
                            "pubkeyG2_Y": [
                                "7195420705070610085822336271177477197783222206049730346661288394390002326108",
                                "3843095263670262906968665217932572653461722681179190576442171778724113982749",
                            ],
                            "socket": "http://127.0.0.1:6003",
                            "stake": "1980028561960706956",
                        },
                        {
                            "id": 388172267086462125616873973700919348523043339018696303660100571160342164696419,
                            "operatorId": "0x3944d3035bcc914866777523827256cfb8cea660e432016cfc5f31c71d3edff1",
                            "pubkeyG1_X": "2107728905596792720263207598883501200301713353534115895072254842197409962090",
                            "pubkeyG1_Y": "8885092866510381984783787709758777165613856682655784435432364063498730570977",
                            "pubkeyG2_X": [
                                "18579596182924273925972577726738150048922941800743831539416930305484061936124",
                                "11078573884058873896260639338888752909345053591830996326194684213522477252975",
                            ],
                            "pubkeyG2_Y": [
                                "12815820260348750024509131099202316108391956812471978794258776298909273677956",
                                "4470851997511823466167593148008452052278478993200951997572975896620600296112",
                            ],
                            "socket": "http://127.0.0.1:6004",
                            "stake": "1036678674083155839644",
                        },
                        {
                            "id": 337440980244172592770442709787204468871664079923491991368721427786201124581700,
                            "operatorId": "0x579f7ab1902a30bae5542c835c00d78db52b153f466741fe04c8953e957a18a8",
                            "pubkeyG1_X": "14590362989264834695543631629361015631540784167586086184905965780954224754604",
                            "pubkeyG1_Y": "9365883818028778729400632369133871757956027117352364926519949663515964324573",
                            "pubkeyG2_X": [
                                "17841992338011959299830084698925465653222030673520058242737558022009449790245",
                                "17935590702077630769332531429621728906734851131249102999927123630243035111102",
                            ],
                            "pubkeyG2_Y": [
                                "15985009759716155838997669718798399097028266211518630688480960679184897016197",
                                "17129141937139424498171485392082139250320463326821287243331096121360058826182",
                            ],
                            "socket": "http://127.0.0.1:6005",
                            "stake": "1686037489182236898275",
                        },
                    ]
                }
            }.get("data", {}).get("operators", [])
        )
        # try:
        #     response = requests.post(self.subgraph_url, json={'query': query})
        #     if response.status_code == 200:
        #         data = response.json()
        #         operators = data.get('data', {}).get('operators', [])
        #         self.nodes = self._convert_operators_to_nodes(operators)
        #         print("Synced with subgraph successfully.")
        #     else:
        #         print(f"Failed to fetch data from subgraph. Status code: {response.status_code}")
        # except requests.exceptions.RequestException as e:
        #     print(f"An error occurred: {e}")

    def _convert_operators_to_nodes(self, operators):
        nodes = {}
        for operator in operators:
            parsed_url = urlparse(operator["socket"])
            node_info = {
                "public_key": operator["id"],
                "pubkeyG1_X": operator["pubkeyG1_X"],
                "pubkeyG1_Y": operator["pubkeyG1_Y"],
                "pubkeyG2_X": operator["pubkeyG2_X"],
                "pubkeyG2_Y": operator["pubkeyG2_Y"],
                "socket": operator["socket"],
                "stake": operator["stake"],
                "host": parsed_url.hostname,
                "port": parsed_url.port,
            }
            nodes[str(int(operator["operatorId"], 16))] = node_info
        return nodes

    def _sync_periodically(self, interval):
        while not self._stop_event.is_set():
            self.sync_with_subgraph()
            time.sleep(interval)

    def start_sync_thread(self):
        sync_interval = 60  # 1 minute
        self._sync_thread = threading.Thread(
            target=self._sync_periodically, args=(sync_interval,)
        )
        self._sync_thread.daemon = True
        self._sync_thread.start()

    def stop_sync_thread(self):
        self._stop_event.set()
        self._sync_thread.join()

    def lookup_node(self, node_id: str = None):
        return self.nodes.get(node_id, {})

    def get_all_nodes(self, n: int = None):
        if n is None:
            n = len(self.nodes)
        return list(self.nodes.keys())[:n]
