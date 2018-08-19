from pycoin.networks.bitcoinish import create_bitcoinish_network

network = create_bitcoinish_network(
    symbol="JBS", network_name="Jumbucks", subnet_name="mainnet",
    wif_prefix_hex="ab", address_prefix_hex="2b",
    bip32_prv_prefix_hex="037a6460", bip32_pub_prefix_hex="037a689a")
