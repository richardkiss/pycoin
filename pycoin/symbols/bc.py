from pycoin.networks.bitcoinish import create_bitcoinish_network

network = create_bitcoinish_network(
    symbol="BC", network_name="Blackcoin", subnet_name="mainnet",
    wif_prefix_hex="99", address_prefix_hex="19",
    bip32_prv_prefix_hex="02cfbf60", bip32_pub_prefix_hex="02cfbede")
