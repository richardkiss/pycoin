from pycoin.networks.bitcoinish import create_bitcoinish_network

network = create_bitcoinish_network(
    symbol="DFC", network_name="DEFCOIN", subnet_name="mainnet",
    wif_prefix_hex="9e", address_prefix_hex="1e", pay_to_script_prefix_hex="05",
    bip32_prv_prefix_hex="02fa54d7", bip32_pub_prefix_hex="02fa54ad")
