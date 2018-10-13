from pycoin.networks.bitcoinish import create_bitcoinish_network

from pycoin.coins.bgold.Tx import Tx as BgoldTx
from pycoin.coins.bgold.Block import Block as BgoldBlock

# fork at block 491407

network = create_bitcoinish_network(
    symbol="BTG", network_name="Bgold", subnet_name="mainnet", tx=BgoldTx, block=BgoldBlock,
    wif_prefix_hex="80", sec_prefix="BTGSEC:", address_prefix_hex="26", pay_to_script_prefix_hex="17",
    bip32_prv_prefix_hex="0488ade4", bip32_pub_prefix_hex="0488B21E",
    magic_header_hex="e1476d44", default_port=8338,
    dns_bootstrap=[
        "eu-dnsseed.bitcoingold-official.org", "dnsseed.bitcoingold.org",
        "dnsseed.btcgpu.org",
    ])
