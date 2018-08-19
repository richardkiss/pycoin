from pycoin.networks.bitcoinish import create_bitcoinish_network

network = create_bitcoinish_network(
    symbol="BTCD", network_name="BitcoinDark", subnet_name="mainnet",
    wif_prefix_hex="44", address_prefix_hex="3c", pay_to_script_prefix_hex="2d",
    bip32_prv_prefix_hex="0488ade4", bip32_pub_prefix_hex="0488b21e")
