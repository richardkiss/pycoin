from pycoin.networks.bitcoinish import create_bitcoinish_network

network = create_bitcoinish_network(
    symbol="MZC", network_name="Mazacoin", subnet_name="mainnet",
    wif_prefix_hex="e0", address_prefix_hex="32", pay_to_script_prefix_hex="5c39",
    bip32_prv_prefix_hex="0488ade4", bip32_pub_prefix_hex="0488b21e")
