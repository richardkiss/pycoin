from pycoin.networks.bitcoinish import create_bitcoinish_network

network = create_bitcoinish_network(
    network_name="Chaucha", symbol="CHA", subnet_name="mainnet",
    wif_prefix_hex="d8", address_prefix_hex="58", pay_to_script_prefix_hex="50",
    bip32_prv_prefix_hex="0488ADE4", bip32_pub_prefix_hex="0488B21E",
    magic_header_hex="AAA226A9", default_port=21663,
    dns_bootstrap=[
        "condor420.chaucha.cl", "huemul69.chaucha.cl",
    ])
