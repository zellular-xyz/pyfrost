from pyfrost.network.abstract import Validators, DataManager, NodeInfo as BaseNodeInfo
from libp2p.typing import TProtocol
from configs import VALIDATED_CALLERS
from itertools import islice
from typing import Dict, List
import hashlib
import json


class NodeDataManager(DataManager):
    def __init__(self) -> None:
        super().__init__()
        self.__dkg_keys = {}
        self.__nonces = []

    def set_nonces(self, nonces_list: List) -> None:
        self.__nonces = nonces_list

    def get_nonces(self):
        return self.__nonces

    def set_dkg_key(self, key, value) -> None:
        self.__dkg_keys[key] = value

    def get_dkg_key(self, key):
        return self.__dkg_keys.get(key, {})


class NodeValidators(Validators):
    def __init__(self) -> None:
        super().__init__()

    @staticmethod
    def caller_validator(sender_id: str, protocol: TProtocol):
        if protocol in VALIDATED_CALLERS.get(str(sender_id), {}):
            return True
        return False

    @staticmethod
    def data_validator(input_data: Dict):
        result = {
            'data': input_data
        }
        hash_obj = hashlib.sha3_256(json.dumps(result['data']).encode())
        hash_hex = hash_obj.hexdigest()
        result['hash'] = hash_hex
        return result


class NodeInfo(BaseNodeInfo):
    def __init__(self):
        self.nodes = {
            "1": {
                "16Uiu2HAkv3kvbv1LjsxQ62kXE8mmY16R97svaMFhZkrkXaXSBSTq": {
                    "ip": "127.0.0.1",
                    "port": "5079",
                    "public_key": "0802122102093e801cf1d55cb2423b370ec478f6d0fe8fa4dfaa62c37979d6a51d43f6ddb8"
                }
            },
            "2": {
                "16Uiu2HAkvumPB54FCBoNR8nh4aVBNhdv8sNAtt6GegL6aW2V5nCe": {
                    "ip": "127.0.0.1",
                    "port": "5065",
                    "public_key": "0802122102160e0f1485fdbff482e30b05d6b496e941682e99df831580f9885c75fa40f4b7"
                }
            },
            "3": {
                "16Uiu2HAkw89MG4Myh5hitNPVTqPekkCwMzib4Jq6BD9rtQLvJSPy": {
                    "ip": "127.0.0.1",
                    "port": "5072",
                    "public_key": "08021221021939dde56b4c814b25229eaed5b1504d64e291d0bc9746683fcbf1fa80db11d0"
                }
            },
            "4": {
                "16Uiu2HAkwAnCC6DunFsXvARa2pHSFJaQNAXbPntjxbEyFRsSzGSW": {
                    "ip": "127.0.0.1",
                    "port": "5074",
                    "public_key": "080212210219e6b0098d07e264db833334774cd686c3b28f5d53b3def4868c262fe63d509b"
                }
            },
            "5": {
                "16Uiu2HAkwDW3SKiofh5ypLxVVGsenzabbHjE9NzxhoxK8rpGw4mg": {
                    "ip": "127.0.0.1",
                    "port": "5070",
                    "public_key": "08021221021a992b0b8fbbc6735d3569b019c023576c65f13585ac0574b94e10c76d0c7e0b"
                }
            },
            "6": {
                "16Uiu2HAkwQ2NWsPszoeNkaMX4o3VV6rqb7b4AsVvJsw8jLMtvR1r": {
                    "ip": "127.0.0.1",
                    "port": "5052",
                    "public_key": "08021221021d4b44ef34ae3447acd445b313e41565888fef491820e662fc50402d21182349"
                }
            },
            "7": {
                "16Uiu2HAkwZuuxHZBvUDV4XLe54vDEBUM5SmNNmVb9As9EzJmDKZN": {
                    "ip": "127.0.0.1",
                    "port": "5094",
                    "public_key": "08021221021fd3c67bb438d811bb29f734c8f05bae677198e49d13acd85028cddd353128dd"
                }
            },
            "8": {
                "16Uiu2HAkx3HYEfKJZWp3gnxParDEs4SosH9bx2aJUSaxQtkLgyvf": {
                    "ip": "127.0.0.1",
                    "port": "5042",
                    "public_key": "080212210226d6e8c5a554926f24c15b7f27cf4b28c51ff7a3c6148bd9d49c69870b4acf70"
                }
            },
            "9": {
                "16Uiu2HAkxJNxQaXhftygPW8NZgHwNjfRgqeXCBGUmooun2hNrnAo": {
                    "ip": "127.0.0.1",
                    "port": "5056",
                    "public_key": "08021221022ab4bf026d6cf23babbf2febba8bf769d614f092727bbab52c62f40d3604ed44"
                }
            },
            "10": {
                "16Uiu2HAkxw3mLEidfSmUEecN7cwcXd9gkzgr1D4LPeaEbJkbA8w6": {
                    "ip": "127.0.0.1",
                    "port": "5031",
                    "public_key": "08021221023419896b65b7314f9868932dea9acf917ab04049235c7f8d6cb9936bdebe7be5"
                }
            },
            "11": {
                "16Uiu2HAkyY6N9LdJdmSELymYHFEuyvHphHheDRPZE8bpX5LWSZ3x": {
                    "ip": "127.0.0.1",
                    "port": "5035",
                    "public_key": "08021221023d13ce2023be5bf8eea6eda8089a70073ea020be8b208281e898413ab31a43c3"
                }
            },
            "12": {
                "16Uiu2HAkysXuPfw7w2JXXG73aYJemjYAMCmeytDsi7JQLzKqdisk": {
                    "ip": "127.0.0.1",
                    "port": "5033",
                    "public_key": "0802122102420eb7a0f223b3b575b35595cba5efdd84e5f4dc9a8221b89fff0c44b4bae8e3"
                }
            },
            "13": {
                "16Uiu2HAkyyJgoSzyvnEGXsJxZARKHpryNRPJqX2DxqMVwq53NxQQ": {
                    "ip": "127.0.0.1",
                    "port": "5021",
                    "public_key": "0802122102438941efd035323076698a57c6ce425afc9b80da21e6843b0e027d3d42910cf1"
                }
            },
            "14": {
                "16Uiu2HAkz6vRNGh6gobuK64EgcTopQU8cEaQ5AYUu2JGiMi6tJux": {
                    "ip": "127.0.0.1",
                    "port": "5043",
                    "public_key": "0802122102457cba48c2f2a07a52c9b4903bb4afbab159d14dd0f6896278f457a8945da1cb"
                }
            },
            "15": {
                "16Uiu2HAkzhvUZHCmBiFDEPmfD9JJFdagbNMdku2dCZgZYeQAHFQF": {
                    "ip": "127.0.0.1",
                    "port": "5075",
                    "public_key": "08021221024e741e40bcd986f0cfb006fc8a03cec3099b53e5dfd8d7e8d69eda52ca66c16c"
                }
            },
            "16": {
                "16Uiu2HAkzyAGdeUp7sGQS8Rr8wKbbjHJFYjgigQVAN2KSRoC79nD": {
                    "ip": "127.0.0.1",
                    "port": "5040",
                    "public_key": "0802122102525b6d7d28792e7f9c03183aac44fc69f5021a7313e5cd6cab980b0a2576a73e"
                }
            },
            "17": {
                "16Uiu2HAm1nPv2nUQAbzKEmNLxjXQtkp3BHpB2Hf8MZRZ1NktCwh7": {
                    "ip": "127.0.0.1",
                    "port": "5024",
                    "public_key": "08021221025e7527696c32b3b7a42424c5fa3e190d317d22ad9bef624797f24421e9c60db6"
                }
            },
            "18": {
                "16Uiu2HAm38JiV84kg9CGyMuicNbQJvFSuhbyuSeZaAi9ZNnqysjQ": {
                    "ip": "127.0.0.1",
                    "port": "5030",
                    "public_key": "0802122102726a9415b3d55386298cf5214bcfbba404760398a56b64ac9de48c1ac20a84c3"
                }
            },
            "19": {
                "16Uiu2HAm3Be3qSoam2r2WWgL1CFoWAm79Y6y12jydmaQikKvuNMB": {
                    "ip": "127.0.0.1",
                    "port": "5062",
                    "public_key": "080212210273452e75d97c81f743234513da1653b769c3e6f5d8a2202a1f14529152a73e76"
                }
            },
            "20": {
                "16Uiu2HAm3bYN4xcyXdNBAAhTeDXVfrePUEfkzdVSWNtC66hdKmfe": {
                    "ip": "127.0.0.1",
                    "port": "5054",
                    "public_key": "08021221027964b12f9490a7a74ff748fd35af3794a03de769b627d3ddb72f508ee56c71c1"
                }
            },
            "21": {
                "16Uiu2HAm3pChJeFoz5TqreVbUkL8pzBzooJ8A1oFjnpfX15eYe4G": {
                    "ip": "127.0.0.1",
                    "port": "5058",
                    "public_key": "08021221027ca300eaa34a9fdd06c45bf17761469c7326cc289bdd6e90d38da3371663d699"
                }
            },
            "22": {
                "16Uiu2HAm46gwTUqQFRGKfJyQeHbkk51AjREGRJVPXvWRmHyZbAaV": {
                    "ip": "127.0.0.1",
                    "port": "5026",
                    "public_key": "080212210280dc3b6c913074794cd877841f941edd70ae9e90ab1590010ffa7317386b742a"
                }
            },
            "23": {
                "16Uiu2HAm4DuQ724pJUW2kpR7w38Gx4YHLCJ6Ypuha5GgVBSBc1w1": {
                    "ip": "127.0.0.1",
                    "port": "5096",
                    "public_key": "080212210282b562be539d6010050185c0bba24d1af16002695ae035324d99f1e727490874"
                }
            },
            "24": {
                "16Uiu2HAm5XnWNQmUbT9u2ACdWRkZvEukvXQMFW7rGAQnq8YwNsVD": {
                    "ip": "127.0.0.1",
                    "port": "5095",
                    "public_key": "08021221029625bc0332b9dd757482e945d602340432e432dbe93bfde27448ad9d09e78f34"
                }
            },
            "25": {
                "16Uiu2HAm6jQnooavM9g2oX7n3FaBgX6TJuTAAS9MgW5ebVwQvVCp": {
                    "ip": "127.0.0.1",
                    "port": "5017",
                    "public_key": "0802122102a7fbd606455f812a16e0c0e615a02733f500003ecc4921d990c6f5056480c615"
                }
            },
            "26": {
                "16Uiu2HAm6pgCcFaJ4LcBdCivRWAk9ZTSpKw8zGr79AZkwCEyADT1": {
                    "ip": "127.0.0.1",
                    "port": "5085",
                    "public_key": "0802122102a9552a2501a6f6b34deb097c1c082068e4ff6571420a25f5a5e43d0d50322e5c"
                }
            },
            "27": {
                "16Uiu2HAm72WKcREmDtTgNeZEkbG2Gc1x4duhUeH7s6cSNTX1xsVA": {
                    "ip": "127.0.0.1",
                    "port": "5064",
                    "public_key": "0802122102ac5cf6bcec99f6588165eda3450a4a1e9b1eab68b41bbf61e74eea546c4e08c1"
                }
            },
            "28": {
                "16Uiu2HAm76CXkZTnpCkAUD5Ze4BivcebHGtzxsHVUpgM31qH4fZo": {
                    "ip": "127.0.0.1",
                    "port": "5087",
                    "public_key": "0802122102ad4f2bcb0b556431d82c73cbc3a9c49b71ff94c00d1db59c35f9bbadedd55b3e"
                }
            },
            "29": {
                "16Uiu2HAm77TDp3uNrkh7yirmgmk19AEHCsH3maxsrPn78Z7iTMax": {
                    "ip": "127.0.0.1",
                    "port": "5009",
                    "public_key": "0802122102ada15cd998d98e109e7b3b1a95117f98fc8dd322c19828c4d5ee77dac27f9961"
                }
            },
            "30": {
                "16Uiu2HAm7vnKNw1dSy549vdVhvY1zgkujC68n3eHeynwzSBZpMSv": {
                    "ip": "127.0.0.1",
                    "port": "5047",
                    "public_key": "0802122102b9c140ab7d24d993a6522f996794ad6066e778b44d9078de106beef43e0d9707"
                }
            },
            "31": {
                "16Uiu2HAm8AnZ2CqqkNRn9nptQ4uYzVYakscVZSNuV5XvSKTAeM7t": {
                    "ip": "127.0.0.1",
                    "port": "5004",
                    "public_key": "0802122102bd57a660346e4a246c1cd6cf54c695f822ad4c7e5e4860c17a545114df843ff7"
                }
            },
            "32": {
                "16Uiu2HAm8JJwBQrhgFDe3FNav97wuZDCVYW9XRLbTaETTV28hbmd": {
                    "ip": "127.0.0.1",
                    "port": "5046",
                    "public_key": "0802122102bf451193a9b6085bbf0dea2de29e33d7f7983f96ddfad7aaea5629735e591034"
                }
            },
            "33": {
                "16Uiu2HAm8UUfbxxXa2dorkjdR33dFGdseNCP45oegrsgNfpx9Whu": {
                    "ip": "127.0.0.1",
                    "port": "5015",
                    "public_key": "0802122102c1dfe14f99905f3ceca92a9adc900530fafeeae6325689a6a749ac1e6d496f68"
                }
            },
            "34": {
                "16Uiu2HAm8Z9DJtSTTXodtoebJx2NyJGQghytpnbo1AtFc9c9weEL": {
                    "ip": "127.0.0.1",
                    "port": "5028",
                    "public_key": "0802122102c311c9c6d880c3d59dd99b0734bed9d44dc2b3bfdd7721c2c6b37bd7cbecac89"
                }
            },
            "35": {
                "16Uiu2HAm8eaTYxTXFjG6g3ZA8QCMGuQ8PE4mCjiUJcuFGq97jJcg": {
                    "ip": "127.0.0.1",
                    "port": "5082",
                    "public_key": "0802122102c4763ccbb48959551aee09a39143a18395594f6d49e9d1b1dffe25948b8cd0e9"
                }
            },
            "36": {
                "16Uiu2HAm8mU5RM5mMcEEDGE5omXYJzv5QRxN22cH1SBHwjuerRKj": {
                    "ip": "127.0.0.1",
                    "port": "5067",
                    "public_key": "0802122102c63a166513326d54e394f3261453b62c856d053bf99b5d0027dacf454984be96"
                }
            },
            "37": {
                "16Uiu2HAm8oyrX2PDxExK3Xu4J2HeBEaLZmhoipbMp88LqEumkiRn": {
                    "ip": "127.0.0.1",
                    "port": "5069",
                    "public_key": "0802122102c6deeb2eab2c039e8860e29ec28fbf7f97d13d9bd88e2a9f655f3253d1708e99"
                }
            },
            "38": {
                "16Uiu2HAm8yipjAyjBMtsJSsM3Skj6r6gGAowwZ4N33MH6PzwUgBV": {
                    "ip": "127.0.0.1",
                    "port": "5071",
                    "public_key": "0802122102c95dbb3732753982bb3f3b463c6ffc5aef5c9973885cee55ec8578de5b1fd514"
                }
            },
            "39": {
                "16Uiu2HAm915vmRbxpE5UL9EFWtZK7SZRW9toexCZdhrgteSAxTkp": {
                    "ip": "127.0.0.1",
                    "port": "5012",
                    "public_key": "0802122102c9b72cb408978824701b80ed2f4c47634ae347143d4d26e9fa811a541932301d"
                }
            },
            "40": {
                "16Uiu2HAm9D3NEzM6MybjELGkD1xyyUAZjH59Du6u3cQCRgHeLowN": {
                    "ip": "127.0.0.1",
                    "port": "5092",
                    "public_key": "0802122102ccc73fb51e1b99a9b726e6bc7b7d1d6a608aff12d9172df1bf71f3252da323d1"
                }
            },
            "41": {
                "16Uiu2HAm9rGvQe5gxbgDWDhCxpa5xx3x3k7hq4yDWKLZCy7yJk2m": {
                    "ip": "127.0.0.1",
                    "port": "5083",
                    "public_key": "0802122102d65110a52aa057ca2dba9f3af4cf4f03bd493a2c78394b43a070a9839a865eda"
                }
            },
            "42": {
                "16Uiu2HAm9zebzCft973E6jsbtiw1ZJ6tytdR7wZr7AVW2n6RaVYT": {
                    "ip": "127.0.0.1",
                    "port": "5063",
                    "public_key": "0802122102d8763a5461084ed3cb4ab1f1d866fcde10680dc717118b9d0280ef2e88693898"
                }
            },
            "43": {
                "16Uiu2HAmBEnVWsVsHdfJSahmG84eX9msapCpCzdUQ4vuaE6gv6rV": {
                    "ip": "127.0.0.1",
                    "port": "5060",
                    "public_key": "0802122102eaf0f730075367cb367378f856259d41aa80962518b5b318736988346a8dd682"
                }
            },
            "44": {
                "16Uiu2HAmBVy9HxHpm2TdN13rhgnuA8RckSV3e2Hn5b4agNgv7TJJ": {
                    "ip": "127.0.0.1",
                    "port": "5077",
                    "public_key": "0802122102eed4b8a1674227d6e9a394a35fb26514c1bffbc26f8ea3ccbf6e6081979c79f3"
                }
            },
            "45": {
                "16Uiu2HAmCUWfW1Gp6BpLG5GVdVVo4DWdZjebnYavHrKKP3QYnDKm": {
                    "ip": "127.0.0.1",
                    "port": "5008",
                    "public_key": "0802122102fd50e32184385c3dfbf638d98116d76b3192b77aff0ee2137fe99ae2c9e74ec8"
                }
            },
            "46": {
                "16Uiu2HAmCW3a8Uecc67rqMd4DwbA3ueKAK92XnixQtnFFnfeJWsH": {
                    "ip": "127.0.0.1",
                    "port": "5080",
                    "public_key": "0802122102fdb56a46a727b4e5a4d3b5923b9c3fae26af7a08c60fd3233b50270587d5fe70"
                }
            },
            "47": {
                "16Uiu2HAmCXu2zYj1FCsF6u14wyKpXGgahQWfKEzktfspRHZq6YFN": {
                    "ip": "127.0.0.1",
                    "port": "5097",
                    "public_key": "0802122102fe2eec9352ceca62cbfb2113ba2d7f74c865dc1478102c7c90daf5584c6b4765"
                }
            },
            "48": {
                "16Uiu2HAmCptiqhC2HSrkw1WiNYBzCCQ4PDAn52WqD8BHraVGt91M": {
                    "ip": "127.0.0.1",
                    "port": "5000",
                    "public_key": "0802122103028971a98a51a20367615d3d06d99153669788f63dfed179c1915207a143615c"
                }
            },
            "49": {
                "16Uiu2HAmCq9jPmLaP7JhRWqaNxxPKuDR4Y4TwGY5h2stEgnXVD2R": {
                    "ip": "127.0.0.1",
                    "port": "5066",
                    "public_key": "0802122103029a6a52e1184256f5d670dc24e2e049b62b98d75b129d649226399f455056a2"
                }
            },
            "50": {
                "16Uiu2HAmE7bP2u1iTZSkYWkDLr6HEcMX5ieNPfZmWoLKctF2fAgb": {
                    "ip": "127.0.0.1",
                    "port": "5076",
                    "public_key": "080212210315ac65864e681d5df2842730dba5b3591ba70309ec4c27546105c1875bf9cb3c"
                }
            },
            "51": {
                "16Uiu2HAmEQ3vY1EoYLgEyDbqM1NCx9Fphcv9a5TriWeDtxXkBxJc": {
                    "ip": "127.0.0.1",
                    "port": "5032",
                    "public_key": "080212210319e3b3b2a4af1449bb3dbf01e38be084a2d6cd83f568ab64af4a813d99e81ff9"
                }
            },
            "52": {
                "16Uiu2HAmEascgB9rXUz1gr9EfPzMt6xRuktvEQ85S18ZXPHLaFkf": {
                    "ip": "127.0.0.1",
                    "port": "5016",
                    "public_key": "08021221031ca96f868c78e0082be4c0fdef433c77080e1a89fa8a768567aa34f49747b5b4"
                }
            },
            "53": {
                "16Uiu2HAmFLG2CxzhXiGri6qaV7vtourQvr2txQ84MX3doLsgcwxi": {
                    "ip": "127.0.0.1",
                    "port": "5086",
                    "public_key": "080212210327c6bea140b32569c0cdc9a0b78a459d55d9bc037af3d2b04ee189743af8161f"
                }
            },
            "54": {
                "16Uiu2HAmFQn5hLvh8qGADq84durPy3VHCc2GywbRVvMkYuLwekTW": {
                    "ip": "127.0.0.1",
                    "port": "5038",
                    "public_key": "080212210328ef0e98923bdbd2ffbb6ed751c58efd2183519ae41a2992d7ff9336c5217095"
                }
            },
            "55": {
                "16Uiu2HAmFrk11qasauxSLNHn6ShwfK3SakcjARCggVxJQDr5zDRT": {
                    "ip": "127.0.0.1",
                    "port": "5090",
                    "public_key": "08021221032f95ce2dc7ee477932a0b4f2d864c3af68062d7e51aaccaaef1a0c01a1352982"
                }
            },
            "56": {
                "16Uiu2HAmGEttySjXB7PfUiheTjdm7K5H2W2gFXGXEnTsUob9a3HK": {
                    "ip": "127.0.0.1",
                    "port": "5027",
                    "public_key": "08021221033542a44958503e99d81d59bab503e5234ea40de5b188b6808471968a7f9231e2"
                }
            },
            "57": {
                "16Uiu2HAmGiH1LSULdoUnWt74tSzbid2W5UUGiEDw36LzErC7do7S": {
                    "ip": "127.0.0.1",
                    "port": "5068",
                    "public_key": "08021221033c4652b657481d8dac5df25038183d2c60ddd0f912a7c3dc652cf43da0abed8d"
                }
            },
            "58": {
                "16Uiu2HAmGkr7i2ohpEfvZRffSRD6e4Bb3ARn9ac8Fs35HYFbxXzu": {
                    "ip": "127.0.0.1",
                    "port": "5022",
                    "public_key": "08021221033ceeec1297e4126493bfc706941b11e346a9d33ce8a293b561b424c784d1ca8e"
                }
            },
            "59": {
                "16Uiu2HAmHNKKMJ44jzNpZLV8kHFK8DeNt61AMMqVhMug7wG4hboB": {
                    "ip": "127.0.0.1",
                    "port": "5006",
                    "public_key": "0802122103460501a6325b77a574afa54ae590e9cf86b3255521cef6fa150b3b4482853a8e"
                }
            },
            "60": {
                "16Uiu2HAmHfMMPHVH4k3UAXQsGritPxJSnwWMazP1D5rSnnfbWURm": {
                    "ip": "127.0.0.1",
                    "port": "5036",
                    "public_key": "08021221034a622e67370dc273dd16ae9c10ecf6693877bd1d9d7d447830ba426606bd6590"
                }
            },
            "61": {
                "16Uiu2HAmHiAuNMrbtWkpas7xmJGtL7BYWzP14mrANt4zVsV9NCtW": {
                    "ip": "127.0.0.1",
                    "port": "5048",
                    "public_key": "08021221034b1b1c06990685ee2214a01883ed3c7b0a1cc1d4a4bff6ea30683d0901f570ff"
                }
            },
            "62": {
                "16Uiu2HAmJ85ECrST7Z7ozh7Q1dztH5gGReK3yaCH5hUTxBotkuRe": {
                    "ip": "127.0.0.1",
                    "port": "5093",
                    "public_key": "0802122103513aa1c2d5fca892a184bbd10d555986e6ac0c0f6498a0e3d49519523be18a8d"
                }
            },
            "63": {
                "16Uiu2HAmJH9zFv3AB46FCSM7x1Ja3dTsgYeY1GVTeE1Mwiozr5HV": {
                    "ip": "127.0.0.1",
                    "port": "5098",
                    "public_key": "0802122103538e3da3bc668e7ff93384ef807a7da0bc8f3fa78df3cebf41016aadb784ec84"
                }
            },
            "64": {
                "16Uiu2HAmJYPzYUt3FAdh2YD4hChNTYepECJrDGfNbKzWx3kKSMod": {
                    "ip": "127.0.0.1",
                    "port": "5045",
                    "public_key": "08021221035775c9d049e9650a82b06d11edf52579d6484c8e256f5dc9c708c5be470fa948"
                }
            },
            "65": {
                "16Uiu2HAmJcVZxKeooaiDkVEyPhRsdaRCCJgKbYryczJX1MdEHWGA": {
                    "ip": "127.0.0.1",
                    "port": "5099",
                    "public_key": "080212210358826a9b6378ceb74b82e012a4892e32ebf5ff66b634f265cc383189b80f4853"
                }
            },
            "66": {
                "16Uiu2HAmK2wRLg7tECgNdk7Ycx2EkD2v7m2977tDBJtc2D9EtfEN": {
                    "ip": "127.0.0.1",
                    "port": "5073",
                    "public_key": "08021221035ec596117bd2018c881fb343da12806db1aa5e6c1278b48216d262b5ad729da7"
                }
            },
            "67": {
                "16Uiu2HAmKA5QQk5nUk93XBPWLeZLsFkfH6KjW9RRCeM5cjfKnYdm": {
                    "ip": "127.0.0.1",
                    "port": "5061",
                    "public_key": "08021221036099adeb23cc6f6ab66dbe51a5c73422403cd6d4abe6b8ca9d2a29b3b8cdc798"
                }
            },
            "68": {
                "16Uiu2HAmKrkPHgb3EEv6ndUf83aFmXfMmKwYLd2RohSG56szJnLu": {
                    "ip": "127.0.0.1",
                    "port": "5057",
                    "public_key": "08021221036b04fcc00200ca6431cff812e8bd768367254c3004ce36d34786dc518e16248e"
                }
            },
            "69": {
                "16Uiu2HAmLNL2U7GFKLGFUeJB2Z6qQwT5gVHuk8QXr6VRh6kbuAY2": {
                    "ip": "127.0.0.1",
                    "port": "5051",
                    "public_key": "08021221037298de69cfa2d1ce335cd2b2d642981b84447afe8e2f4646d345672fb2c37aab"
                }
            },
            "70": {
                "16Uiu2HAmLNje54UHd8b7jHZgZUhDfuaY9eG1zkNcWAEKNaMpjRLp": {
                    "ip": "127.0.0.1",
                    "port": "5037",
                    "public_key": "080212210372b391ad871d0d7fbc2f817d6e111ecedff461772f1e092e84c30cc08d3b8b9d"
                }
            },
            "71": {
                "16Uiu2HAmLYD6Rg8Wxfg5PDtxiRDiS1mEAN5XApJtgLG7qzuFuH8M": {
                    "ip": "127.0.0.1",
                    "port": "5089",
                    "public_key": "08021221037520d6d12c73306829bc85fc6d2c42c4d642af0cfdc4c1191fe98aaf09afbbaa"
                }
            },
            "72": {
                "16Uiu2HAmLskVaF1BFUZMeTE96bCsFJJoeXHCkpLFGPD86uXpizHc": {
                    "ip": "127.0.0.1",
                    "port": "5088",
                    "public_key": "08021221037a2260a8c6de2b243ea0e95c66b956bcfc03f12e9da332dde1daca8efac9b85f"
                }
            },
            "73": {
                "16Uiu2HAmMwFYBVQSmBUq1Y8XWnE3x5fm6Hwfsj6vKRZnyST7CTPQ": {
                    "ip": "127.0.0.1",
                    "port": "5039",
                    "public_key": "080212210389e3a5ee862bd49022a2bcaed1fe54e3f717a6e78bc0c5153189b6628b7a5053"
                }
            },
            "74": {
                "16Uiu2HAmNXzrwsofwKoseR6SQcQDpghWg6tW7upDwLYrwdzh34S5": {
                    "ip": "127.0.0.1",
                    "port": "5002",
                    "public_key": "080212210392ca61bb1e5052d57518b140b3458803c28d5d1e7081f66190c289e7d8f4c78a"
                }
            },
            "75": {
                "16Uiu2HAmNgv3yCUiaapWueMWKw672KSovQ17W6TwKUxGQPYZqA9X": {
                    "ip": "127.0.0.1",
                    "port": "5078",
                    "public_key": "080212210395132ba0336f28db98c82c7f843e45b6e5d6c439055c20b7572717c363113c12"
                }
            },
            "76": {
                "16Uiu2HAmNmLZSmzvWxdXut5jaPJKYdErwDxd9q9EsZ3g9yVK6tFQ": {
                    "ip": "127.0.0.1",
                    "port": "5023",
                    "public_key": "0802122103963534853065c3560494ca4807342c92f11755c9a64699164df87899efbdd9d7"
                }
            },
            "77": {
                "16Uiu2HAmPWa48jxrHBf1AmC96fKsdavxiMsS41JchjygNcKKyozU": {
                    "ip": "127.0.0.1",
                    "port": "5081",
                    "public_key": "0802122103a1487039f366ad1ce9f1a8453d62cce2fcaf0db6003613caaad30dde90fff8dd"
                }
            },
            "78": {
                "16Uiu2HAmPi9yVmEca5mfShk3Mkx9vJyjoqovmqY5vTTZ9pxwfMu3": {
                    "ip": "127.0.0.1",
                    "port": "5013",
                    "public_key": "0802122103a4402e48c8219b967e8cb35a92f39f0c1eab26a8eebe2e8d2cd6ed759445a90a"
                }
            },
            "79": {
                "16Uiu2HAmPkBGbfqVJWFuQ6daPD3ADEhHR88pSXnEoTQMe1w81e2m": {
                    "ip": "127.0.0.1",
                    "port": "5029",
                    "public_key": "0802122103a4c4ce77fcdf7135bae67d2b3179edb95a2a6ff82439394ad9cc9b998863e84a"
                }
            },
            "80": {
                "16Uiu2HAmQ1xwiSahCYuVhjVTuVxHC6Uywmx5FApdEeNyh6DSBFuy": {
                    "ip": "127.0.0.1",
                    "port": "5025",
                    "public_key": "0802122103a8d029b36225fc0d22bb149cae80cf98d463c5761d5b555ca70afd0984fc2cd8"
                }
            },
            "81": {
                "16Uiu2HAmQE5c8e7YkkT92YQJwCw6DFxD1b3XZtNFCShQdixFJy9J": {
                    "ip": "127.0.0.1",
                    "port": "5091",
                    "public_key": "0802122103abeaaa6f791572f905dd23773d492bfb21ca4d58d4c541414c937da14f1297e9"
                }
            },
            "82": {
                "16Uiu2HAmQfQXir7c4ibJFh9guSAoYj3wERnCG7hjuS3N1Qusbcx6": {
                    "ip": "127.0.0.1",
                    "port": "5034",
                    "public_key": "0802122103b267955884ed5905875bef3a0bee2fba6cb221af1e56d1387249df6e07662017"
                }
            },
            "83": {
                "16Uiu2HAmRFWBqDr1VrMNKboSQAUpHEcNGxhs199tEu4YBofpzEES": {
                    "ip": "127.0.0.1",
                    "port": "5018",
                    "public_key": "0802122103bb23ba341126ff7cfc9a39c4ad1a5f11e4cd8b037565a4432985bddceb0c19f7"
                }
            },
            "84": {
                "16Uiu2HAmRmAH3A9PzaAu2aQGxEoAyNZcT6bf7XZCJN8sSTsdcf3Q": {
                    "ip": "127.0.0.1",
                    "port": "5019",
                    "public_key": "0802122103c2bca3985bf37b233ec0aa153105f79d7f90488cdf2963ed7851732d0f8293db"
                }
            },
            "85": {
                "16Uiu2HAmS8M32FEC14nFnc8uQL4CrvQ2rQKL1Txd3YQqXnSUu6sX": {
                    "ip": "127.0.0.1",
                    "port": "5005",
                    "public_key": "0802122103c82a00234d7448f3df8348a368ab1fe20e25f814b9cf155b06335d568bcfc0d6"
                }
            },
            "86": {
                "16Uiu2HAmSB4u2eQUsRxDB7pYeRPGZzV34AevoCZjebXgzAaBCDri": {
                    "ip": "127.0.0.1",
                    "port": "5041",
                    "public_key": "0802122103c8dc7ef23749753d4f184c7e58e1bc3a968a50460bef01ce12b14300859426ab"
                }
            },
            "87": {
                "16Uiu2HAmSE5uo7mR8XDaBePXVsmHXtUzyLAri5edYAYUQHXUebCQ": {
                    "ip": "127.0.0.1",
                    "port": "5059",
                    "public_key": "0802122103c9a2624b5613b467ccf43d84d5f5594245361f913e2e5b13183647a891796515"
                }
            },
            "88": {
                "16Uiu2HAmSPyQ31zAUr1RY1L8ReeqqWnUjSyqpw7qm6RxRwbyYtG5": {
                    "ip": "127.0.0.1",
                    "port": "5007",
                    "public_key": "0802122103cc2ad3e14e257603120fd2dd3c2dead357ae1ab43eb3d88e1af805b030f2cfae"
                }
            },
            "89": {
                "16Uiu2HAmSZBxoLD38xzFP7eNuSqSqX3YkBaT9dtnsi4KkP25cS1f": {
                    "ip": "127.0.0.1",
                    "port": "5010",
                    "public_key": "0802122103ce874319d426e54f2a82aca219b5bc9f15c63409882543bb33eaa366e220d702"
                }
            },
            "90": {
                "16Uiu2HAmT4thh6szCCDRQNCcd9FHt8TricoGSJqK4DuJiN1xJhAF": {
                    "ip": "127.0.0.1",
                    "port": "5055",
                    "public_key": "0802122103d6232b7efea8f6d4db549a34965ae1eff8f53b0ce944627b883612bc8a6dcd90"
                }
            },
            "91": {
                "16Uiu2HAmT8KUGvMMN9HLhvGdADo4NqHeQ6hKFaMDeyuWLa2LS3xR": {
                    "ip": "127.0.0.1",
                    "port": "5044",
                    "public_key": "0802122103d703eb19cd30e106350aab08ecf4d232287cbab05c4c885686e50174f9c0654e"
                }
            },
            "92": {
                "16Uiu2HAmTCua75sDufxd9LVRXYwomPUu3ER5RxQnBFjK1Z43YWVX": {
                    "ip": "127.0.0.1",
                    "port": "5084",
                    "public_key": "0802122103d830cc975cb55ae0bc3ef8135520267de593365dcecd266e067acd4bcb765f62"
                }
            },
            "93": {
                "16Uiu2HAmTmSV31nPuNYRNDeUaq1k8gtKSU3aYdC4JonMbVHXQVtx": {
                    "ip": "127.0.0.1",
                    "port": "5053",
                    "public_key": "0802122103e086568a0ff7298ad69f0b102462af685cee8b5e6af963e89fae2528d7d6212d"
                }
            },
            "94": {
                "16Uiu2HAmUA6dPNUdhg3HCmupjFZC7nPZJzPnxBm6HpEqUhXiH44n": {
                    "ip": "127.0.0.1",
                    "port": "5050",
                    "public_key": "0802122103e6543ed15e62b3ca96d08f253d3f90e93845ab7a078e9540ae30a88740258e97"
                }
            },
            "95": {
                "16Uiu2HAmUmWFsajcKnHK4tRdfF64ku4DhCpx7NojQvYmiR5MvrfN": {
                    "ip": "127.0.0.1",
                    "port": "5020",
                    "public_key": "0802122103ef664a8ad8ee8b45f848d6e376c48ecd214ef6100d2b16eb743dafab5260351d"
                }
            },
            "96": {
                "16Uiu2HAmVa4q41eVbYAa3vSc4mbJx4S6SQaGL8XsDNk7BwNEE1J4": {
                    "ip": "127.0.0.1",
                    "port": "5011",
                    "public_key": "0802122103fb53d676d730dd3ad61011a603c6db9ceae6ca93d5e85e5b80afc3517a2e5a55"
                }
            },
            "97": {
                "16Uiu2HAmVbCLUPHdfYxn3d3vLoHtNZgaJm9M7P77NXU2ZjcZ9e9p": {
                    "ip": "127.0.0.1",
                    "port": "5003",
                    "public_key": "0802122103fb9de833116093a67d3eeb0ddd9d448a4a4987a4600035bde6bde15f51c6e5d3"
                }
            },
            "98": {
                "16Uiu2HAmVjoo3kk8exCALSSmBkgXGb6sfZ7rKpXVUgzstFNoPDLF": {
                    "ip": "127.0.0.1",
                    "port": "5001",
                    "public_key": "0802122103fdd2a56e1c3ae58d9737b04598c2a080d3ab6f060331eddde793fe4d593cbf7c"
                }
            },
            "99": {
                "16Uiu2HAmVmERPFurWrpjqdFzmJc3CN2zz2stDjkqQ56EV1bZFGh5": {
                    "ip": "127.0.0.1",
                    "port": "5014",
                    "public_key": "0802122103fe301280d4c2e0947a7b22fe16967f92efc3ae3e68781ab03dc859478a37faa0"
                }
            },
            "100": {
                "16Uiu2HAmVrnDKphoVtGM7TK4YSt7MsJCsddocMD1gdWdUL4DwNwf": {
                    "ip": "127.0.0.1",
                    "port": "5049",
                    "public_key": "0802122103ff9bec7a9cc8b27a069784daa0e15a5f93a957567e3a562f85653f58bf7712a6"
                }
            }
        }
    
    def lookup_node(self, peer_id: str, node_id: str = None):
        if node_id is None:
            for node_id, data in self.nodes.items():
                result = data.get(peer_id, None)
                if result is not None:
                    return result, node_id
            return None
        return self.nodes.get(node_id, {}).get(peer_id, None), node_id
        

    def get_all_nodes(self, n: int = None) -> Dict:
        if n is None:
            n = len(self.nodes)
        result = {}
        for node, data in islice(self.nodes.items(), n):
            result[node] = list(data.keys())
        return result
