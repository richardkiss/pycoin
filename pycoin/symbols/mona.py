from pycoin.networks.bitcoinish import create_bitcoinish_network


network = create_bitcoinish_network(
    network_name="Monacoin", symbol="MONA", subnet_name="mainnet",
    wif_prefix_hex="b0", sec_prefix="MONASEC:", address_prefix_hex="32", pay_to_script_prefix_hex="37",
    bip32_prv_prefix_hex="0488ade4", bip32_pub_prefix_hex="0488b21e", bech32_hrp="mona",
    magic_header_hex="fbc0b6db", default_port=9401,
    dns_bootstrap=["dnsseed.monacoin.org"])
