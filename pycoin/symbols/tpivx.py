from pycoin.networks.bitcoinish import create_bitcoinish_network

network = create_bitcoinish_network(
    symbol="TPIVX", network_name="PIVX", subnet_name="testnet",
    wif_prefix_hex="ef", address_prefix_hex="8b", pay_to_script_prefix_hex="13",
    bip32_prv_prefix_hex="3a8061a0", bip32_pub_prefix_hex="3a805837")
