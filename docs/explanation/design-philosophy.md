# Design Philosophy

This page explains the thinking behind pycoin's architecture and naming conventions. Understanding
these choices will help you navigate the API more confidently.

---

## The Network Object

Every cryptocurrency is different — Bitcoin mainnet addresses start with `1`, testnet addresses
start with `m` or `n`, Litecoin addresses start with `L`, and so on. The encoding of keys, the
signing algorithm, and the script rules can all vary.

pycoin handles this by anchoring everything to a **network object**. Every API call that depends on
a particular coin's rules lives under the network object for that coin:

```python
from pycoin.symbols.btc import network   # Bitcoin mainnet
from pycoin.symbols.xtn import network   # Bitcoin testnet
from pycoin.symbols.ltc import network   # Litecoin
```

This design avoids hidden global state. Instead of calling a function like `address_from_wif(wif)`
and having the code silently assume Bitcoin mainnet, you call `network.parse.private(wif)` and the
network context is always explicit.

The network object is the *single entry point* for all coin-specific functionality:

```
network
├── keys          # create private/public/BIP32 keys
├── parse         # parse WIFs, addresses, BIP32 keys, transactions
├── contract      # create standard puzzle scripts (P2PKH, P2SH, multisig, …)
├── address       # convert puzzle scripts to addresses
├── tx            # the Tx class, plus TxIn and TxOut
├── tx_utils      # shortcuts: create_tx, sign_tx, create_signed_tx, …
├── keychain      # aggregate keys for signing
├── msg           # sign and verify messages
├── validator     # validate signed transactions
├── who_signed    # inspect partial multisig signatures
├── generator     # the ECC generator point (secp256k1 for Bitcoin)
└── message       # peer-to-peer protocol message packing/parsing
```

---

## Naming: pycoin vs Satoshi

Bitcoin's original implementation (the "Satoshi client") was written under time pressure, and many
of the names it introduced have persisted despite being confusing or overly generic.

pycoin uses clearer names where the original ones are misleading. Here is a guide to the most
important differences:

| pycoin name | Satoshi / "official" name | Notes |
|---|---|---|
| `puzzle_script` | `scriptPubKey` | A script that locks coins. Called "pubkey script" because it usually contains a public key, but the lock can be any script. |
| `solution_script` | `scriptSig` | A script that unlocks coins by satisfying the puzzle. Called "sig script" because it usually contains a signature. |
| `Tx` | `transaction` | A transaction. |
| `TxIn` | `vin` / `input` | One input of a transaction. |
| `TxOut` | `vout` / `output` | One output of a transaction. |
| `spendable` | `UTXO` (unspent transaction output) | An output from a prior transaction that has not yet been spent. |
| `coin_value` | `value` | The number of satoshis in a TxOut. |
| `secret_exponent` | `private key` | The raw integer representing the private key. |
| `public_pair` | `public key` | The (x, y) pair on the secp256k1 curve. |

These renames aim to make the relationships clearer:
- A "puzzle script" is a puzzle that must be solved to spend the coins.
- A "solution script" provides the solution to that puzzle.
- Calling the lock/unlock pair "puzzle/solution" makes the relationship obvious without requiring
  prior exposure to the Satoshi codebase.

---

## The Key Hierarchy

pycoin models keys as a hierarchy:

```
Key (base)
├── BIP32Node    — hierarchical deterministic keys (xprv / xpub)
│   ├── BIP49Node  — BIP49 wrapped segwit (m/49'/…)
│   └── BIP84Node  — BIP84 native segwit (m/84'/…)
└── ElectrumWallet — Electrum-style deterministic keys
```

All key types provide a consistent interface: `.wif()`, `.sec()`, `.address()`, `.hash160()`.
BIP32 nodes additionally provide `.hwif()` (hierarchical WIF) and `.subkey_for_path()`.

---

## Transactions and Scripts

A transaction in pycoin is a `Tx` object containing a list of `TxIn` objects and `TxOut` objects.

- A **TxOut** holds a `coin_value` (satoshis) and a `puzzle_script`.
- A **TxIn** holds a reference to a prior TxOut (via `previous_hash` and `previous_index`) and a
  `solution_script`.

The `network.contract` API creates common puzzle scripts by type (P2PKH, P2SH, P2PK, multisig,
nulldata, etc.). The `network.address` API converts a puzzle script to a human-readable address
string and back.

---

## Multi-network support

pycoin includes support for dozens of coins. They are defined in `pycoin/symbols/`:

```
btc.py    → Bitcoin mainnet
xtn.py    → Bitcoin testnet
ltc.py    → Litecoin
doge.py   → Dogecoin
bch.py    → Bitcoin Cash
...
```

Each symbol file defines the coin's parameters (address prefixes, WIF version bytes, BIP32
version bytes, etc.) and creates a `Network` object with those parameters.

To get a network by its code string rather than by a direct import:

```python
from pycoin.networks.registry import network_for_netcode
network = network_for_netcode("LTC")
```

---

## ECDSA acceleration

By default pycoin uses a pure-Python ECDSA implementation. For production use, you can
enable hardware-accelerated ECDSA via two optional native libraries:

| Backend | How to enable |
|---------|--------------|
| OpenSSL | `PYCOIN_NATIVE=openssl` environment variable |
| libsecp256k1 | `PYCOIN_NATIVE=secp256k1` environment variable |

pycoin will also search for these libraries automatically if the environment variables
`PYCOIN_LIBCRYPTO_PATH` and `PYCOIN_LIBSECP256K1_PATH` are set.

---

## See also

- [Bitcoin Primer](../bitcoin.md) — background on Bitcoin concepts
- [Getting Started tutorial](../tutorials/getting-started.md)
- [API Reference](../api.md)
