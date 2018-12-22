from pycoin.networks.bitcoinish import create_bitcoinish_network

network = create_bitcoinish_network(
    symbol="TBTX", network_name="BitCore", subnet_name="testnet3",
    wif_prefix_hex="EF", sec_prefix="TBTXSEC:", address_prefix_hex="6F", pay_to_script_prefix_hex="C4",
    bip32_prv_prefix_hex="04358394", bip32_pub_prefix_hex="043587CF",
    magic_header_hex="FDD2C8F1", default_port=8666,
    dns_bootstrap=[
        "188.68.52.172", "51.15.84.165"
    ])
