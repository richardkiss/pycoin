from pycoin.networks.registry import network_for_netcode


BitcoinMainnet = network_for_netcode("BTC")
BitcoinTestnet = network_for_netcode("XTN")
BitcoinRegtest = network_for_netcode("XRT")
