from pycoin.networks.bitcoinish import create_bitcoinish_network

network = create_bitcoinish_network(
    symbol="tZEC", network_name="Zcash", subnet_name="testnet",
    wif_prefix_hex="ef", address_prefix_hex="1d25", pay_to_script_prefix_hex="1cba",
    bip32_prv_prefix_hex="04358394", bip32_pub_prefix_hex="043587cf")
