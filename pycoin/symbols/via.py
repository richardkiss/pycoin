from pycoin.networks.bitcoinish import create_bitcoinish_network

network = create_bitcoinish_network(
    symbol="VIA", network_name="Viacoin", subnet_name="mainnet",
    wif_prefix_hex="c7", address_prefix_hex="47", pay_to_script_prefix_hex="21",
    bip32_prv_prefix_hex="0488ade4", bip32_pub_prefix_hex="0488b21e")
