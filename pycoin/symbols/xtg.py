from pycoin.networks.bitcoinish import create_bitcoinish_network

from pycoin.coins.bgold.Tx import Tx as BgoldTx


network = create_bitcoinish_network(
    symbol="XTG", network_name="Bgold", subnet_name="testnet", tx=BgoldTx,
    wif_prefix_hex="ef", sec_prefix="XTNSEC:", address_prefix_hex="6f", pay_to_script_prefix_hex="c4",
    bip32_prv_prefix_hex="0488ade4", bip32_pub_prefix_hex="0488B21E", bech32_hrp="tb",
    magic_header_hex="e1476d44", default_port=18338,
    dns_bootstrap=[
        "eu-test-dnsseed.bitcoingold-official.org", "test-dnsseed.bitcoingold.org",
        "test-dnsseed.btcgpu.org", "btg.dnsseed.minertopia.org"
    ])
