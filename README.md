pycoin -- Python Bitcoin Utilities
==================================

This is an implementation of a bunch of utility routines that may be useful when dealing with Bitcoin stuff. It has been test with Python 3.3 (but *not* Python 2.7).


ECDSA Signing and Verification
------------------------------

Instead of hiding behind a bunch of opaque abstraction, the library deals with ECDSA keys directly. The key structures are:

- the ```secret_exponent``` (a large integer that represents a private key)
- the ```public_pair``` (a pair of large integers x and y that represent a public key)

There are a handful of functions: you can do things like sign, verify, generate the public pair from the secret exponent, and flush out the public pair from just the x value (there are two possible values for y of opposite even/odd parity, so you include a flag indicating which value for y you want).


Encoding
--------

The library declares some conversion utilities useful when dealing with Bitcoin. The key structures are

* base58 (the encoding used for Bitcoin addresses)
* hashed base58 (with a standard checksum)
* Bitcoin hashes (double sha256, ripemd160/sha256)
* Bitcoin addresses
* WIF (Wallet import format)
* SEC (the gross internal format of public keys used by OpenSSL, both compressed and uncompressed)


Wallets
-------

The library also implements a deterministic wallet that will securly generate Bitcoin addresses compliant with [BIP0032].

This includes creating and parsing standard wallet keys.

Using this method, you can create a wallet that generates as many public keys as you need while keeping the private keys offline. For example,

xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8

is the public wallet the corresponds to the the private wallet

xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi

First, you generate a Wallet object from either a master secret (so a pass phrase of some kind) or a wallet key, like one of the above.

A Wallet object can generate a subkey using the "subkey" method, which is a child key that can be derived from the parent easily if you know the value for i (which usually ranges from 1 to as high as you want).

A private Wallet object can yield a public Wallet object (which generates only the corresponding public keys), but not the other way around.

A private Wallet object can generate a subkey whose addresses CANNOT be derived from the corresponding public Wallet object (to generate change addresses, for example). Set ```is_prime=True```.


Transaction Validation and Signing
----------------------------------

The Tx transaction class makes it easy to generate new coinbase transactions, or generate and sign new transactions that reassign the incoming coins to a new public keys. Look at the test code for an example.

You will need to provide the "sign" method with a Tx DB that includes the source transactions, and a list of private keys 
for the source transactions.


Donate
------

Want to donate? Feel free. Send to 1FKYxGDywd7giFbnmKdvYmVgBHB9B2HXMw.


[BIP0032]: https://en.bitcoin.it/wiki/BIP_0032

