from pycoin.networks.bitcoinish import create_bitcoinish_network

network = create_bitcoinish_network(
    symbol="DASH", network_name="Dash", subnet_name="mainnet",
    wif_prefix_hex="cc", address_prefix_hex="4c", pay_to_script_prefix_hex="10",
    bip32_prv_prefix_hex="02fe52f8", bip32_pub_prefix_hex="02fe52cc")
