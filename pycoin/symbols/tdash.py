from pycoin.networks.bitcoinish import create_bitcoinish_network

network = create_bitcoinish_network(
    symbol="tDASH", network_name="Dash", subnet_name="testnet",
    wif_prefix_hex="ef", address_prefix_hex="8c", pay_to_script_prefix_hex="13",
    bip32_prv_prefix_hex="3a8061a0", bip32_pub_prefix_hex="3a805837")
