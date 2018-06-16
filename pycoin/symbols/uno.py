from pycoin.networks.bitcoinish import create_bitcoinish_network

network = create_bitcoinish_network(
    netcode="UNO", network_name="Unobtanium", subnet_name="mainnet",
    wif_prefix_hex="e0", address_prefix_hex="82", pay_to_script_prefix_hex="1e",
    bip32_prv_prefix_hex="0488ade4", bip32_pub_prefix_hex="0488b21e")
