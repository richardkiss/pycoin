from pycoin.networks.bitcoinish import create_bitcoinish_network

network = create_bitcoinish_network(
    symbol="MEC", network_name="Megacoin", subnet_name="mainnet",
    wif_prefix_hex="b2", address_prefix_hex="32",
    bip32_prv_prefix_hex="03a04db7", bip32_pub_prefix_hex="03a04d8b")
