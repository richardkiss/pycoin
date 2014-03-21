pycoin -- Python Bitcoin Utilities
==================================

This is an implementation of a bunch of utility routines that may be useful when dealing with Bitcoin stuff. It has been tested with Python 2.7, 3.2 and 3.3.


ECDSA Signing and Verification
------------------------------

Instead of hiding behind a bunch of opaque abstraction, the library deals with ECDSA keys directly. Important structures include:

- the ```secret_exponent``` (a large integer that represents a private key)
- the ```public_pair``` (a pair of large integers x and y that represent a public key)

There are a handful of functions: you can do things like create a signature, verify a signature, generate the public pair from the secret exponent, and flush out the public pair from just the x value (there are two possible values for y of opposite even/odd parity, so you include a flag indicating which value for y you want).


Encoding
--------

The library declares some conversion utilities useful when dealing with Bitcoin. Important structures include:

* base58 (the encoding used for Bitcoin addresses)
* hashed base58 (with a standard checksum)
* Bitcoin hashes (double sha256, ripemd160/sha256, known as "hash160")
* Bitcoin addresses
* WIF (Wallet import format)
* SEC (the gross internal format of public keys used by OpenSSL), both compressed and uncompressed

The command-line utility "bu" ("Bitcoin utility") exposes a lot of this API on the command-line.


Wallets
-------

The library implements a deterministic wallet that will securly generate Bitcoin addresses compliant with [BIP0032].

This includes creating and parsing standard wallet keys.

Using this method, you can create a wallet that generates as many public keys as you need while keeping the private keys offline. For example,

xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8

is the public wallet the corresponds to the the private wallet

xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi

First, you generate a Wallet object from either a master secret (so a pass phrase of some kind) or a wallet key, like one of the above.

A Wallet object can generate a subkey using the "subkey" method, which is a child key that can be derived from the parent easily if you know the value for i (which usually ranges from 1 to as high as you want).

A private Wallet object can yield a public Wallet object (which generates only the corresponding public keys), but not the other way around.

A private Wallet object can generate a subkey whose addresses CANNOT be derived from the corresponding public Wallet object (to generate change addresses, for example). Set ```is_prime=True```.

The command-line utility "genwallet" exposes a lot of this API on the command-line.

IMPORTANT WARNING: be extremely careful giving out public wallet keys. If someone has access to a private wallet key P, of course they have access to all descendent wallet keys of P. But if they also have access to a public wallet key K where P is a subkey of P, you can actually work your way up the tree to determine the private key that corresponds to the public wallet key K (unless private derivation was used at some point between the two keys)! Be sure you understand this warning before giving out public wallet keys!


Transaction Viewing, Validation, Signing
----------------------------------------

There are several command-line tools for manipulating transactions.

    $ fetch_tx -h
    usage: fetch_tx [-h] [-o path-to-output-file] tx_hash [tx_hash ...]

    Fetch a binary transaction from blockexplorer.com.

    positional arguments:
      tx_hash               The hash of the transaction.

    optional arguments:
      -h, --help            show this help message and exit
      -o path-to-output-file, --output-file path-to-output-file
                            output file containing (more) signed transaction


Fetch a transaction from blockexplorer.com and place it into local storage. It will also cache it locally (see below).


    $ dump_tx -h
    usage: dump_tx [-h] [-v] tx_id_or_path [tx_id_or_path ...]

    Dump a transaction in human-readable form.

    positional arguments:
      tx_id_or_path   The transaction id or the path to the file containing the
                      transaction.

    optional arguments:
      -h, --help      show this help message and exit
      -v, --validate  fetch inputs and validate signatures (may fetch source
                      transactions from blockexplorer


For example, to see the "pizza" transaction:

    $ dump_tx -v 49d2adb6e476fa46d8357babf78b1b501fd39e177ac7833124b3f67b17c40c2a
    159 bytes   tx hash 49d2adb6e476fa46d8357babf78b1b501fd39e177ac7833124b3f67b17c40c2a
    TxIn count: 1; TxOut count: 1
    Lock time: 0 (valid anytime)
    Input:
      0:       (unknown, possibly coinbase) from 1e133f7de73ac7d074e2746a3d6717dfc99ecaa8e9f9fade2cb8b0b20a5e0441:0 10000000.00000 mBTC  sig ok
    Output:
      0: 1CZDM6oTttND6WPdt3D6bydo7DYKzd9Qik receives 10000000.00000 mBTC
    Total input  10000000.00000 mBTC
    Total output 10000000.00000 mBTC
    Total fees        0.00000 mBTC

You can also use this tool to dump transaction files by path on local storage, either fully or partially signed.


    $ create_tx -h
    usage: create_tx [-h] -o path-to-output-file txinfo [txinfo ...]

    Create an unsigned Bitcoin transaction moving funds from one address to
    another.

    positional arguments:
      txinfo                a 4-tuple tx_id/tx_out_idx/script_hex/satoshi_count as
                            an input or a "bitcoin_address/satoshi_count" pair as
                            an output. The fetch_unspent tool can help generate
                            inputs.

    optional arguments:
      -h, --help            show this help message and exit
      -o path-to-output-file, --output-file path-to-output-file
                            output file containing unsigned transaction

    Files are binary by default unless they end with the suffix ".hex".


The Tx transaction class makes it easy to generate and sign new transactions. Look at the test code in ```build_tx_test.py``` for examples.

You will need to create a hash160 lookup. Look at ```build_hash160_lookup_db``` in  "solver", and provide it with the private keys relevant to the transaction, then pass it into the "sign" method.


Transaction Cache
-----------------

When a referenced transaction is required (as a source TxOut), the directories listed in ```PYCOIN_TX_DB_DIRS``` and ```PYCOIN_CACHE_DIR``` are searched. If the transaction cannot be located in any of these directories, it is fetched from blockexplorer.com and cached in ```PYCOIN_CACHE_DIR``` to speed subsequent accesses.

```PYCOIN_CACHE_DIR``` defaults to "~/.pycoin_cache/txs/".


Users
-----

Here's a partial list of users of pycoin:

ChangeTip http://changetip.com/

CoinSafe http://coinsafe.com/

Email me at him@richardkiss.com to be added to this list.


Donate
------

Want to donate? Feel free. Send to 1KissFDVu2wAYWPRm4UGh5ZCDU9sE9an8T.
Or hire me to do bitcoin consulting... him@richardkiss.com.


[BIP0032]: https://en.bitcoin.it/wiki/BIP_0032
