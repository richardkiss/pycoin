from pycoin.networks.bitcoinish import create_bitcoinish_network

network = create_bitcoinish_network(
    symbol="FTX", network_name="Feathercoin", subnet_name="testnet",
    wif_prefix_hex="c1", address_prefix_hex="41", pay_to_script_prefix_hex="c4",
    bip32_prv_prefix_hex="04358394", bip32_pub_prefix_hex="043587cf")
