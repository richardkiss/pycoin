from pycoin.networks.bitcoinish import create_bitcoinish_network

network = create_bitcoinish_network(
    symbol="tCHC", network_name="Chaincoin", subnet_name="testnet",
    wif_prefix_hex="d8", address_prefix_hex="50", pay_to_script_prefix_hex="2c",
    bip32_prv_prefix_hex="04358394", bip32_pub_prefix_hex="043587cf")
