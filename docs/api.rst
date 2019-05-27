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

    :ref:`network.Tx`
        the class for a transaction

    :ref:`network.Block`
        the class for a block

    :ref:`network.message`
        message api, to pack and parse messages used by bitcoin's peer-to-peer protocol

    :ref:`network.keychain`
        an object to aggregate private key information, useful for signing transactions

    :ref:`network.parse`
        for parsing human-readable items like keys, WIFs, addresses

    :ref:`network.contract`
        api for creating standard scripts in bitcoin

    :ref:`network.address`
        includes for_script API for turning a TxOut puzzle script into an address

    :ref:`network.keys`
        api for creating private keys, public keys, and hierarchical keys, both BIP32 and Electrum

    :ref:`network.msg`
        api for signing messages and verifying signed messages

    :ref:`network.validator`
        api for validating whether or not transactions are correctly signed

    :ref:`network.tx_utils`
        shortcuts for building and signing transactions

    :ref:`network.who_signed`
        utilities to determine which public keys have signed partially signed multisig transactions


.. _network.Tx:

network.Tx
----------------

.. autoclass:: pycoin.coins.Tx.Tx
    :members:

.. autoclass:: pycoin.coins.Tx.TxIn
    :members:

.. autoclass:: pycoin.coins.Tx.TxOut
    :members:


.. _network.Block:

network.Block
----------------

.. autoclass:: pycoin.block.Block
    :members:


.. _network.message:

network.message
---------------

.. automethod:: pycoin.symbols.btc.network.message.pack

.. automethod:: pycoin.symbols.btc.network.message.parse


:mod:`InvItem` Module
----------------------------------

.. automodule:: pycoin.message.InvItem
    :members:
    :undoc-members:
    :show-inheritance:


:mod:`PeerAddress` Module
----------------------------------

.. automodule:: pycoin.message.PeerAddress
    :members:
    :undoc-members:
    :show-inheritance:


.. _network.keychain:

network.keychain
----------------

.. autoclass:: pycoin.key.Keychain.Keychain
    :members:


.. _network.parse:

network.parse
-------------

.. autoclass:: pycoin.networks.ParseAPI.ParseAPI
    :members:


.. _network.contract:

network.contract
----------------

.. automethod:: pycoin.symbols.btc.network.contract.for_address
.. automethod:: pycoin.symbols.btc.network.contract.for_p2pk
.. automethod:: pycoin.symbols.btc.network.contract.for_p2pkh
.. automethod:: pycoin.symbols.btc.network.contract.for_p2pkh_wit
.. automethod:: pycoin.symbols.btc.network.contract.for_p2sh
.. automethod:: pycoin.symbols.btc.network.contract.for_p2sh_wit
.. automethod:: pycoin.symbols.btc.network.contract.for_multisig
.. automethod:: pycoin.symbols.btc.network.contract.for_nulldata
.. automethod:: pycoin.symbols.btc.network.contract.for_p2s
.. automethod:: pycoin.symbols.btc.network.contract.for_p2s_wit
.. automethod:: pycoin.symbols.btc.network.contract.for_info
.. automethod:: pycoin.symbols.btc.network.contract.info_for_script


.. _network.address:

network.address
----------------

.. autoclass:: pycoin.symbols.btc.network.address
    :members:


.. _network.keys:

network.keys
------------

.. automethod:: pycoin.symbols.btc.network.keys.public
.. automethod:: pycoin.symbols.btc.network.keys.private
.. automethod:: pycoin.symbols.btc.network.keys.bip32_seed
.. automethod:: pycoin.symbols.btc.network.keys.bip32_deserialize
.. automethod:: pycoin.symbols.btc.network.keys.electrum_seed
.. automethod:: pycoin.symbols.btc.network.keys.electrum_private
.. autoclass:: pycoin.symbols.btc.network.keys.InvalidSecretExponentError
    :members:
.. autoclass:: pycoin.symbols.btc.network.keys.InvalidPublicPairError
    :members:


.. _network.msg:


network.generator
-----------------

Most bitcoin-like cryptocurrencies use an ECC group called secp256k1 for digital signatures.
The ecdsa.secp256k1 generator for this group provides most of the functionality you will need.

.. code-block:: python

    from pycoin.symbols.btc import network
    public_key = network.generator * 1
    print(public_key)

For bitcoin, network.generator is pycoin.ecdsa.secp256k1.secp256k1_generator, which is an instance of a :class:`Generator <pycoin.ecdsa.Generator.Generator>`.


network.msg
-----------

.. automethod:: pycoin.symbols.btc.network.msg.sign
.. automethod:: pycoin.symbols.btc.network.msg.verify
.. automethod:: pycoin.symbols.btc.network.msg.parse_signed
.. automethod:: pycoin.symbols.btc.network.msg.hash_for_signing
.. automethod:: pycoin.symbols.btc.network.msg.signature_for_message_hash
.. automethod:: pycoin.symbols.btc.network.msg.pair_for_message_hash


.. _network.validator:

network.validator
-----------------

.. autoclass:: pycoin.symbols.btc.network.validator.ScriptError
    :members:

.. autoclass:: pycoin.symbols.btc.network.validator.ValidationFailureError
    :members:

.. autoclass:: pycoin.symbols.btc.network.validator.errno
    :members:

.. autoclass:: pycoin.symbols.btc.network.validator.flags
    :members:


.. _network.tx_utils:

network.tx_utils
----------------

.. automethod:: pycoin.symbols.btc.network.tx_utils.create_tx
.. automethod:: pycoin.symbols.btc.network.tx_utils.sign_tx
.. automethod:: pycoin.symbols.btc.network.tx_utils.create_signed_tx
.. automethod:: pycoin.symbols.btc.network.tx_utils.split_with_remainder
.. automethod:: pycoin.symbols.btc.network.tx_utils.distribute_from_split_pool


.. _network.who_signed:

network.who_signed
------------------

.. automethod:: pycoin.symbols.btc.network.who_signed.solution_blobs
.. automethod:: pycoin.symbols.btc.network.who_signed.extract_signatures
.. automethod:: pycoin.symbols.btc.network.who_signed.extract_secs
.. automethod:: pycoin.symbols.btc.network.who_signed.public_pairs_for_script
.. automethod:: pycoin.symbols.btc.network.who_signed.public_pairs_signed
.. automethod:: pycoin.symbols.btc.network.who_signed.who_signed_tx
