from pycoin.networks.bitcoinish import create_bitcoinish_network


network = create_bitcoinish_network(
    symbol="BTC", network_name="Bitcoin", subnet_name="mainnet",
    wif_prefix_hex="80", sec_prefix="BTCSEC:", address_prefix_hex="00", pay_to_script_prefix_hex="05",
    bip32_prv_prefix_hex="0488ade4", bip32_pub_prefix_hex="0488B21E", bech32_hrp="bc",
    bip49_prv_prefix_hex="049d7878", bip49_pub_prefix_hex="049D7CB2",
    bip84_prv_prefix_hex="04b2430c", bip84_pub_prefix_hex="04B24746",
    magic_header_hex="F9BEB4D9", default_port=8333,
    dns_bootstrap=[
        "seed.bitcoin.sipa.be", "dnsseed.bitcoin.dashjr.org",
        "bitseed.xf2.org", "dnsseed.bluematt.me",
    ])
