# pycoin API

!!! note
    pycoin started out as a loose collection of utilities, and is slowly evolving to be
    a more cohesive API.


## Networks

A "network" is a particular coin, such as Bitcoin Mainnet or Bitcoin Testnet. There
are two main ways to fetch a network:

```python
from pycoin.symbols.btc import network
```

or

```python
from pycoin.networks.registry import network_for_netcode
network = network_for_netcode("BTC")
```

These are the starting points. Nearly all API for a network can be accessed by drilling down
below the network object.

Some useful network attributes include:

- **network.Tx** — the class for a transaction
- **network.Block** — the class for a block
- **network.message** — message api, to pack and parse messages used by bitcoin's peer-to-peer protocol
- **network.keychain** — an object to aggregate private key information, useful for signing transactions
- **network.parse** — for parsing human-readable items like keys, WIFs, addresses
- **network.contract** — api for creating standard scripts in bitcoin
- **network.address** — includes for_script API for turning a TxOut puzzle script into an address
- **network.keys** — api for creating private keys, public keys, and hierarchical keys, both BIP32 and Electrum
- **network.msg** — api for signing messages and verifying signed messages
- **network.validator** — api for validating whether or not transactions are correctly signed
- **network.tx_utils** — shortcuts for building and signing transactions
- **network.who_signed** — utilities to determine which public keys have signed partially signed multisig transactions


## network.Tx

The `network.Tx` class represents a transaction. It also contains the `TxIn` and `TxOut` subclasses.

See `pycoin.coins.Tx` for full class documentation.


## network.Block

The `network.Block` class represents a block.

See `pycoin.block.Block` for full class documentation.


## network.message

The message API packs and parses messages used by bitcoin's peer-to-peer protocol.

- `network.message.pack` — pack a message
- `network.message.parse` — parse a message

See also `pycoin.message.InvItem` and `pycoin.message.PeerAddress`.


## network.keychain

The `network.keychain` object aggregates private key information, useful for signing transactions.

See `pycoin.key.Keychain.Keychain` for full class documentation.


## network.parse

The parse API handles human-readable items like keys, WIFs, and addresses.

See `pycoin.networks.ParseAPI.ParseAPI` for full class documentation.


## network.contract

The contract API creates standard scripts in bitcoin:

- `network.contract.for_address`
- `network.contract.for_p2pk`
- `network.contract.for_p2pkh`
- `network.contract.for_p2pkh_wit`
- `network.contract.for_p2sh`
- `network.contract.for_p2sh_wit`
- `network.contract.for_multisig`
- `network.contract.for_nulldata`
- `network.contract.for_p2s`
- `network.contract.for_p2s_wit`
- `network.contract.for_info`
- `network.contract.info_for_script`


## network.address

The address API includes `for_script` for turning a TxOut puzzle script into an address.

See `pycoin.symbols.btc.network.address` for full class documentation.


## network.keys

The keys API creates private keys, public keys, and hierarchical keys (both BIP32 and Electrum):

- `network.keys.public`
- `network.keys.private`
- `network.keys.bip32_seed`
- `network.keys.bip32_deserialize`
- `network.keys.electrum_seed`
- `network.keys.electrum_private`
- `network.keys.InvalidSecretExponentError`
- `network.keys.InvalidPublicPairError`


## network.generator

Most bitcoin-like cryptocurrencies use an ECC group called secp256k1 for digital signatures.
The ecdsa.secp256k1 generator for this group provides most of the functionality you will need.

```python
from pycoin.symbols.btc import network
public_key = network.generator * 1
print(public_key)
```

For bitcoin, `network.generator` is `pycoin.ecdsa.secp256k1.secp256k1_generator`, which is an
instance of a `Generator` (`pycoin.ecdsa.Generator.Generator`).


## network.msg

The msg API signs messages and verifies signed messages:

- `network.msg.sign`
- `network.msg.verify`
- `network.msg.parse_signed`
- `network.msg.hash_for_signing`
- `network.msg.signature_for_message_hash`
- `network.msg.pair_for_message_hash`


## network.validator

The validator API checks whether transactions are correctly signed:

- `network.validator.ScriptError`
- `network.validator.ValidationFailureError`
- `network.validator.errno`
- `network.validator.flags`


## network.tx_utils

Shortcuts for building and signing transactions:

- `network.tx_utils.create_tx`
- `network.tx_utils.sign_tx`
- `network.tx_utils.create_signed_tx`
- `network.tx_utils.split_with_remainder`
- `network.tx_utils.distribute_from_split_pool`


## network.who_signed

Utilities to determine which public keys have signed partially signed multisig transactions:

- `network.who_signed.solution_blobs`
- `network.who_signed.extract_signatures`
- `network.who_signed.extract_secs`
- `network.who_signed.public_pairs_for_script`
- `network.who_signed.public_pairs_signed`
- `network.who_signed.who_signed_tx`
