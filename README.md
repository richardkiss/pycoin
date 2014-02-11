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
* SEC (the gross internal format of public keys used by OpenSSL, both compressed and uncompressed)

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


Transaction Validation and Signing
----------------------------------

The UnsignedTx transaction class makes it easy to generate and sign new transactions that reassign the incoming coins to new public keys. Look at the test code in build_tx_test.py or the spend.py script for examples.

You will need to create a "solver", and provide it with the private keys relevant to the transaction, then pass it into the "sign" method.

The command-line utility "spend" provides sample code for generating transactions. Note that it doesn't post the transactions to the network, so you can mess around with relative impunity.


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
