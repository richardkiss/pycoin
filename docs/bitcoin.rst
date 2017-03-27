A Cryptocurrency Primer
=======================

We will describe bitcoin specifically here. Many cryptocurrencies
are minor variations of bitcoin, so certain details may be modified,
but the overall structure is the same.

Overview
--------

Bitcoin is a digital currency that will eventually generate a number of
bitcoins slightly under 21 million (2.1e7). Each bitcoin can be further
subdivided into ten million (1e8) quantum units each of which is known
as a "satoshi".

The Bitcoin network is a distributed append-only database that is
designed to append one blockto the linked-list of blocks once every
ten minutes. This database keeps track of *unspents* (more commonly
known as "UTXOs" for *unspent transaction outputs*).

Unspents
^^^^^^^^

An unspent corresponds to a roll of coins of any size (the quantum
unit being 1 satoshi, 1e8 of which make a bitcoin) protected by a
*puzzle script* (more commonly known as a "script pubkey", because
it almost always contains a public key or a reference to one). This puzzle
is written in a custom bitcoin stack-based low level scripting language,
but is usually one of only a few common forms.

An unspent is a potential input to a transaction.

Unspent Database
^^^^^^^^^^^^^^^^

The bitcoin database is a ledger of unspents. It doesn't explicitly
define ownership of bitcoins; instead, rules are applied that allow
bitcoin to be reassigned if the puzzles can be solve. So you can think
of "owning" bitcoin as being equivalent to having the information
required to solve the puzzle. In other words, the only benefit ownership
confers is the ability to reassign ownership. This may seem odd at first,
but it's really how all money works.


Transactions
^^^^^^^^^^^^

To spend coins, one creates a *transaction* (or *Tx*). A transaction
consists of a little metadata, one or more inputs, each of which is
known as a *TxIn* (commonly known as a vin), and one or more outputs,
each of which is known as a *TxOut* (or vout).

Each TxIn refers to exactly one unspent, and includes a *solution script*
that corresponds to the unspent's puzzle script, and "unlocks" it.
If the unspent's puzzle script is a lock, the solution script is a key
-- but a key that (usually) unlocks the coins *only* for the transaction
the TxIn is embedded in.

To "unlock" the coins, the puzzle script must be solved. This generally
requires knowing the private key corresponding to the public key,
and creating a signature proving that the private key is known and
approves the resultant transfer of coins expressed by the transaction.
This is done by hashing parts of the transaction, including the TxOut
list, and having the solution include a digital signature on that hash.

Roughly: a transaction unrolls rolled-up and locked coins from unspents,
puts them in a big pile, then rerolls them and locks them in new unspents.
The old unspents are now spent (and so no longer considered "unspents").

Transactions are named by their transaction ID, which is a 256-bit
binary string, generally expressed as a 64-character hex id. Example::

    0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098


TxIn
^^^^

TxOut
^^^^^

Puzzles
^^^^^^^


Block
^^^^^

Transactions are passed around the peer-to-peer Bitcoin network, and
eventually reach validating nodes known as "miners". Miners attempt to
bundle transactions into a *block* using a proof-of-work trick that
makes finding blocks a time-consuming process. Once a block is found,

Mining
^^^^^^

- lotto ticket


Keys
----

A bitcoin private key is an integer between 1 and
115792089237316195423570985008687907852837564279074904382605163141518161494336
which is about 1.15e77 (inclusive). This number is called a "secret
exponent"

Each private key has a public key
