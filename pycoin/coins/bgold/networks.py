from pycoin.block import Block as BgoldBlock
from pycoin.coins.bitcoin.ScriptTools import BitcoinScriptTools
from pycoin.networks.bitcoinish import create_bitcoinish_network

from .Tx import Tx as BgoldTx


# fork at block 491407

BgoldMainnet = create_bitcoinish_network(
    netcode="BTG", network_name="Bgold", subnet_name="mainnet", tx=BgoldTx, block=BgoldBlock,
    wif_prefix_hex="80", sec_prefix="BTCSEC:", address_prefix_hex="26", pay_to_script_prefix_hex="17",
    bip32_prv_prefix_hex="0488ade4", bip32_pub_prefix_hex="0488B21E",
    magic_header_hex="e1476d44", default_port=8338,
    dns_bootstrap = [
        "eu-dnsseed.bitcoingold-official.org", "dnsseed.bitcoingold.org",
        "dnsseed.btcgpu.org",
    ],
    scriptTools=BitcoinScriptTools)


BgoldTestnet = create_bitcoinish_network(
    netcode="XTG", network_name="Bgold", subnet_name="testnet", tx=BgoldTx, block=BgoldBlock,
    wif_prefix_hex="ef", sec_prefix="XTNSEC:", address_prefix_hex="6f", pay_to_script_prefix_hex="c4",
    bip32_prv_prefix_hex="0488ade4", bip32_pub_prefix_hex="0488B21E", bech32_hrp="tb",
    magic_header_hex="e1476d44", default_port=18338,
    dns_bootstrap = [
        "eu-test-dnsseed.bitcoingold-official.org", "test-dnsseed.bitcoingold.org",
        "test-dnsseed.btcgpu.org", "btg.dnsseed.minertopia.org"
    ],
    scriptTools=BitcoinScriptTools)
