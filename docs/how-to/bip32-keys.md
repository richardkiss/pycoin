# How to Work with BIP32 Hierarchical Keys

BIP32 defines a scheme for deriving a tree of keys from a single root seed. This guide shows you
how to create, derive, export, and import BIP32 keys using pycoin.

---

## Prerequisites

```python
from pycoin.symbols.btc import network
```

---

## Create a root key from a seed

A BIP32 seed can be any byte string. In production, use 128–256 bits of cryptographically secure
randomness.

```python
import os

# Secure random seed (use this in production)
seed = os.urandom(32)
root = network.keys.bip32_seed(seed)

# For demonstration, a fixed seed can be used
demo_root = network.keys.bip32_seed(b"demo seed — not secure")
```

---

## Export the root key

```python
# Extended private key (xprv) — keep this secret
xprv = demo_root.hwif(as_private=True)
print("xprv:", xprv)

# Extended public key (xpub) — safe to share for watch-only use
xpub = demo_root.hwif()
print("xpub:", xpub)
```

!!! warning "xpub security"
    Sharing an extended public key (`xpub`) allows anyone to derive all child public keys in its
    subtree. If *any* corresponding child private key is later leaked, the attacker can work back
    up the tree to recover the xprv — **unless** hardened derivation was used. Prefer hardened
    derivation (`H`) for account-level keys.

---

## Import an existing xprv or xpub

```python
xprv_str = ("xprv9s21ZrQH143K31AgNK5pyVvW23gHnkBq2wh5aEk6g1s496M"
            "8ZMjxncCKZKgb5jZoY5eSJMJ2Vbyvi2hbmQnCuHBujZ2WXGTux1X2k9Krdtq")

key = network.parse.bip32(xprv_str)
print("address:", key.address())
print("wif:    ", key.wif())
```

---

## Derive child keys with a path

Paths use `/` as separator. Hardened derivation is indicated by `H` (or `'`).

```python
# Normal derivation
child = demo_root.subkey_for_path("0/1")
print("m/0/1 address:", child.address())

# Hardened derivation (only possible from a private key)
hardened = demo_root.subkey_for_path("44H/0H/0H")
print("m/44'/0'/0' address:", hardened.address())

# Mix of hardened and normal
account = demo_root.subkey_for_path("44H/0H/0H/0/5")
print("m/44'/0'/0'/0/5 address:", account.address())
```

---

## Derive a range of child keys

```python
# Derive addresses at m/0/0 through m/0/4
for i in range(5):
    child = demo_root.subkey_for_path(f"0/{i}")
    print(f"m/0/{i}: {child.address()}")
```

---

## Derive from a public key only

Once you have an xpub, you can derive child *public* keys (and therefore addresses) without
ever exposing the private key. This is used in watch-only wallets.

```python
xpub_str = demo_root.hwif()  # public version of the root
public_root = network.parse.bip32(xpub_str)

# Normal child derivation from xpub
child_pub = public_root.subkey_for_path("0/0")
print("public-only child address:", child_pub.address())

# Hardened derivation from xpub is NOT possible
# child_pub.subkey_for_path("0H")  # would raise an error
```

---

## BIP44 / BIP49 / BIP84 standard paths

```
m / purpose' / coin_type' / account' / change / index

purpose:
  44' → P2PKH (legacy addresses, start with 1)
  49' → P2SH-P2WPKH (wrapped segwit, start with 3)
  84' → P2WPKH (native segwit, start with bc1)

coin_type:
  0' → Bitcoin mainnet
  1' → Bitcoin testnet

change:
  0 → external (receiving) addresses
  1 → internal (change) addresses
```

Example — a receiving address at BIP44 account 0, index 0:

```python
receiving_key = demo_root.subkey_for_path("44H/0H/0H/0/0")
print("BIP44 receiving[0]:", receiving_key.address())
```

---

## Export a child key's WIF

```python
child = demo_root.subkey_for_path("0/0")
print("WIF:", child.wif())
```

---

## Use `ku` on the command line

```bash
# Show full info for a BIP32 seed passphrase
ku P:myseed

# Show xpub only
ku -w -P P:myseed

# Derive child keys
ku -s 0/0-4 -a P:myseed

# Hardened derivation
ku -s 44H/0H/0H/0/0 -a P:myseed
```

---

## See also

- [Getting Started tutorial](../tutorials/getting-started.md)
- [Sign a Transaction](sign-a-transaction.md)
- [Multisig](multisig.md)
- [API Reference](../api.md)
