from pycoin.networks.bitcoinish import create_bitcoinish_network

network = create_bitcoinish_network(
    symbol="DOGE", network_name="Dogecoin", subnet_name="mainnet",
    wif_prefix_hex="9e", address_prefix_hex="1e", pay_to_script_prefix_hex="16",
    bip32_prv_prefix_hex="02fac398", bip32_pub_prefix_hex="02facafd")
