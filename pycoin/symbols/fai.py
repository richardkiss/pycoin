from pycoin.networks.bitcoinish import create_bitcoinish_network

network = create_bitcoinish_network(
    symbol="FAI", network_name="Faircoin", subnet_name="mainnet",
    wif_prefix_hex="df", address_prefix_hex="5f", pay_to_script_prefix_hex="24",
    bip32_prv_prefix_hex="0488ade4", bip32_pub_prefix_hex="0488b21e")
