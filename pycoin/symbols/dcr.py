from pycoin.networks.bitcoinish import create_bitcoinish_network

network = create_bitcoinish_network(
    symbol="DCR", network_name="Decred", subnet_name="mainnet",
    wif_prefix_hex="22de", address_prefix_hex="073f", pay_to_script_prefix_hex="071a",
    bip32_prv_prefix_hex="02fda4e8", bip32_pub_prefix_hex="02fda926")
