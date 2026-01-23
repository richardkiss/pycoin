from pycoin.networks.bitcoinish import create_bitcoinish_network

network = create_bitcoinish_network(
    symbol="tSTAK", network_name="STRAKS", subnet_name="testnet",
    wif_prefix_hex="ef", address_prefix_hex="7f", pay_to_script_prefix_hex="13",
    bip32_prv_prefix_hex="46002a10", bip32_pub_prefix_hex="a2aec9a6")
