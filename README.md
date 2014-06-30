pycoin -- Python Cryptocoin Utilities
=====================================

This is an implementation of a bunch of utility routines that may be useful when dealing with bitcoin and some
alt-coins. It has been tested with Python 2.7, 3.3 and 3.4.

See also http://github.com/richardkiss/pycoinnet/ for a library that speaks the bitcoin protocol.

High Level
==========

Keys & BIP32
------------

The class pycoin.key.Key contains a convenience Key class that will parse the base58 representation of a BIP 32
wallet [BIP0032] or a WIF or a bitcoin (or altcoin) address, and convert downwards.

WARNING: be extremely careful giving out public wallet keys. If someone has access to a private wallet key P, of
course they have access to all descendent wallet keys of P. But if they also have access to a public wallet key K
where P is a subkey of K, you can actually work your way up the tree to determine the private key that corresponds
to the public wallet key K (unless private derivation was used at some point between the two keys)! Be sure you
understand this warning before giving out public wallet keys!

pycoin.key.Key:

```Key(hierarchical_wallet=None, secret_exponent=None,
                 public_pair=None, hash160=None, prefer_uncompressed=None, is_compressed=True, netcode)```

Specify one of "hierarchical_wallet, secret_exponent, public_pair or hash160" to create a ```Key```.

Or

```Key.from_text(b58_text)``` accepts an address (bitcoin or other), a WIF, or a BIP32 wallet string and yield a Key.

```Key.from_sec(sec)``` creates a Key from the SEC bytestream encoding of a public pair.


pycoin.key.bip32.Wallet (formerly pycoin.wallet.Wallet) provides a BIP32 hierarchical wallet.

Much of this API is exposed in the ```ku``` command-line utility. See also COMMAND-LINE-TOOLS.md.

See ```BIP32.txt``` for more information.


Transactions
------------

pycoin.tx.Tx is a class that wraps a bitcoin transaction. You can create, edit, sign, or validate a transaction using
methods in this class.

You can also use ```pycoin.tx.tx_utils``` which has ```create_tx``` and ```create_signed_tx```, which gives you a
very easy way to create signed transactions.

The command-line utility ```tx``` is a Swiss Army knife of transaction utilities. See also COMMAND-LINE-TOOLS.md.


Services
--------

When signing or verifying signatures on a transaction, the source transactions are generally needed. If you set two
environment variables in your ```.profile``` like this:

    PYCOIN_CACHE_DIR=~/.pycoin_cache
    PYCOIN_SERVICE_PROVIDERS=BLOCKR_IO:BITEASY:BLOCKCHAIN_INFO:BLOCKEXPLORER
    export PYCOIN_CACHE_DIR PYCOIN_SERVICE_PROVIDERS

and then ```tx``` will automatically fetch transactions from the web sites listed and cache the results in
```PYCOIN_CACHE_DIR``` when they are needed.

The module pycoin.services includes two functions ```spendables_for_address```, ```get_tx_db``` that look at the
environment variables set to determine which web sites to use to fetch the underlying information. The sites are
polled in the order they are listed in the environment variable.


Blocks
------

The command-line utility ```block``` will dump a block in a human-readable format. For further information, look at
```pycoin.block```, which includes the object ```Block``` which will parse and stream the binary format of a block.


Low Level
=========

ECDSA Signing and Verification
------------------------------

The module ```pycoin.ecdsa``` deals with ECDSA keys directly. Important structures include:

- the ```secret_exponent``` (a large integer that represents a private key)
- the ```public_pair``` (a pair of large integers x and y that represent a public key)

There are a handful of functions: you can do things like create a signature, verify a signature, generate the public
pair from the secret exponent, and flush out the public pair from just the x value (there are two possible values
for y of opposite even/odd parity, so you include a flag indicating which value for y you want).


Encoding
--------

The ```pycoin.encoding``` module declares some conversion utilities useful when dealing with Bitcoin. Important
structures include:

* base58 (the encoding used for Bitcoin addresses)
* hashed base58 (with a standard checksum)
* Bitcoin hashes (double sha256, ripemd160/sha256, known as "hash160")
* Bitcoin addresses
* WIF (Wallet import format)
* SEC (the gross internal format of public keys used by OpenSSL), both compressed and uncompressed


Users
-----

Here's a partial list of users of pycoin:

ChangeTip https://changetip.com/

CoinSafe https://coinsafe.com/

GreenAddress https://greenaddress.it/

Coinkite https://coinkite.com/

Email me at him@richardkiss.com to be added to this list.


Donate
------

Want to donate? Feel free. Send to 1KissFDVu2wAYWPRm4UGh5ZCDU9sE9an8T.
I'm also available for bitcoin consulting... him@richardkiss.com.


[BIP0032]: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
