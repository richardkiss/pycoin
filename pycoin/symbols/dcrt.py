from pycoin.networks.bitcoinish import create_bitcoinish_network

network = create_bitcoinish_network(
    symbol="DCRT", network_name="Decred", subnet_name="testnet",
    wif_prefix_hex="230e", address_prefix_hex="0f21", pay_to_script_prefix_hex="0e6c",
    bip32_prv_prefix_hex="04358397", bip32_pub_prefix_hex="043587d1")
