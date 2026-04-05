import struct

from pycoin.coins.litecoin import LTCTx, LTCBlock
from pycoin.networks.bitcoinish import create_bitcoinish_network
from pycoin.satoshi.satoshi_struct import parse_struct


network = create_bitcoinish_network(
    network_name="Litecoin",
    symbol="LTC",
    subnet_name="mainnet",
    wif_prefix_hex="b0",
    sec_prefix="LTCSEC:",
    address_prefix_hex="30",
    pay_to_script_prefix_hex="32",
    bip32_prv_prefix_hex="019d9cfe",
    bip32_pub_prefix_hex="019da462",
    bech32_hrp="ltc",
    bip49_prv_prefix_hex="01b26792",
    bip49_pub_prefix_hex="01B26EF6",
    bip84_prv_prefix_hex="04b2430c",
    bip84_pub_prefix_hex="04B24746",
    block=LTCBlock,
    tx=LTCTx,
)
