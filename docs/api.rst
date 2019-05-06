pycoin API
==========

Note

    pycoin started out as a loose collection of utilities, and is slowly evolving to be
    a more cohesive API.


Networks
--------

A "network" is a particular coin, such as Bitcoin Mainnet or Bitcoin Testnet. There
are two main ways to fetch a network::

    from pycoin.symbols.btc import network

or ::

    from pycoin.networks.registry import network_for_netcode
    network = network_for_netcode("BTC")

These are the starting points. Nearly all API for a network can be accessed by drilling down
below the network object.

Some useful network attributes include:

    network.Tx
        the class for a transaction

    network.Block
        the class for a block

    network.message
        message api, to pack and parse messages used by bitcoin's peer-to-peer protocol

    network.keychain
        an object to aggregate private key information, useful for signing transactions

    network.parse
        :ref:`parse-api` for parsing human-readable items like keys, WIFs, addresses

    network.contract
        api for creating standard scripts in bitcoin

    network.address
        includes for_script API for turning a TxOut puzzle script into an address

    network.keys
        api for creating private keys, public keys, and hierarchical keys, both BIP32 and Electrum

    network.msg
        api for signing messages and verifying signed messages

    network.validator
        api for validating whether or not transactions are correctly signed

    network.tx_utils
        shortcuts for building and signing transactions

    network.who_signed
        utilities to determine which public keys have signed partially signed multisig transactions
