from pycoin.networks.bitcoinish import create_bitcoinish_network


network = create_bitcoinish_network(
    network_name="Monacoin", symbol="TMONA", subnet_name="testnet4",
    wif_prefix_hex="ef", sec_prefix="TMONASEC:", address_prefix_hex="6f", pay_to_script_prefix_hex="75",
    bip32_prv_prefix_hex="04358394", bip32_pub_prefix_hex="043587cf", bech32_hrp="tmona",
    magic_header_hex="fdd2c8f1", default_port=19403,
    dns_bootstrap=["testnet-dnsseed.monacoin.org"])
