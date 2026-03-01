# Getting Started with pycoin

This tutorial walks you through installing pycoin and using the most fundamental features: creating
keys, deriving addresses, and exploring the `ku` command-line tool. No prior knowledge of Bitcoin
programming is required, although a basic familiarity with Python and Bitcoin concepts will help.

By the end you will have:

- pycoin installed and verified
- A private key created in Python
- The matching Bitcoin address printed
- A BIP32 hierarchical key created and navigated
- The `ku` command-line tool used to inspect keys

---

## 1. Install pycoin

```bash
pip install pycoin
```

Verify the installation by running the `ku` (key utility) command:

```bash
ku 1
```

You should see output like:

```
input           : 1
network         : Bitcoin mainnet
netcode         : BTC
secret exponent : 1
 hex            : 1
wif             : KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn
 uncompressed   : 5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf
...
Bitcoin address : 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
```

This shows all the information derived from the private key whose secret exponent is 1. (This is a
well-known key used only for demonstrations — never use it to hold real funds.)

---

## 2. Create your first private key in Python

Open a Python shell and run:

```python
from pycoin.symbols.btc import network

# secret_exponent=1 is a well-known demo key — never use for real funds
key = network.keys.private(secret_exponent=1)

print("WIF:    ", key.wif())
print("SEC:    ", key.sec().hex())
print("Address:", key.address())
```

Expected output:

```
WIF:     KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn
SEC:     0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
Address: 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
```

### What just happened?

- `network.keys.private(secret_exponent=1)` creates a private key object. The *secret exponent* is
  the raw private-key integer.
- `key.wif()` returns the key in *Wallet Import Format* — the standard way to export a private key
  as a human-readable string.
- `key.sec()` returns the public key as a 33-byte *compressed SEC* binary blob.
- `key.address()` returns the corresponding Bitcoin P2PKH address.

---

## 3. Round-trip: parse a WIF back to a key

```python
wif = key.wif()

# Parse the WIF string back into a key object
same_key = network.parse.private(wif)

print(same_key.address())  # 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
```

`network.parse.private()` recognises the WIF encoding and reconstructs the private key object,
including its matching public key and address.

---

## 4. Create a BIP32 hierarchical key

BIP32 lets you derive a whole tree of keys from a single seed. This is the basis of "HD wallets"
used by most modern Bitcoin software.

```python
# Derive a BIP32 root key from a passphrase-like seed
# A real seed should come from secure randomness — never a short string
bip32_key = network.keys.bip32_seed(b"this is a demo seed — not secure")

# Export as an extended private key (xprv) string
print("xprv:", bip32_key.hwif(as_private=True))

# Export as an extended public key (xpub) string
print("xpub:", bip32_key.hwif())

# The address of the root key
print("address:", bip32_key.address())
```

### Deriving child keys

```python
# Derive child key at path m/0/1
child = bip32_key.subkey_for_path("0/1")
print("child address:", child.address())

# Hardened derivation uses H or ' notation
hardened_child = bip32_key.subkey_for_path("44H/0H/0H")
print("hardened child address:", hardened_child.address())
```

Child keys are deterministic — the same seed and path always produce the same key.

---

## 5. Parse an existing BIP32 key

```python
xprv = ("xprv9s21ZrQH143K31AgNK5pyVvW23gHnkBq2wh5aEk6g1s496M"
        "8ZMjxncCKZKgb5jZoY5eSJMJ2Vbyvi2hbmQnCuHBujZ2WXGTux1X2k9Krdtq")

key = network.parse.bip32(xprv)

print("xprv:", key.hwif(as_private=True))
print("xpub:", key.hwif())
print("wif: ", key.wif())
print("addr:", key.address())
```

---

## 6. Use a different network (Testnet)

pycoin supports many networks. To work with Bitcoin Testnet instead of Mainnet:

```python
from pycoin.symbols.xtn import network as testnet

key = testnet.keys.private(secret_exponent=1)
print("Testnet address:", key.address())
# address starts with 'm' or 'n' for testnet
```

To use Litecoin:

```python
from pycoin.symbols.ltc import network as litecoin

key = litecoin.keys.private(secret_exponent=1)
print("Litecoin address:", key.address())
# address starts with 'L'
```

---

## 7. Explore further with `ku`

The `ku` command-line tool exposes most of the key API above. Some useful examples:

```bash
# Key from secret exponent
ku 1

# Key from BIP32 passphrase
ku P:myseedphrase

# Show only the address
ku -a P:myseedphrase

# Show only the WIF
ku -W P:myseedphrase

# Show as JSON
ku -j P:myseedphrase

# Derive child keys at a path
ku -s 0/0-4 -a P:myseedphrase

# Work with Testnet
ku -n XTN 1
```

---

## Next steps

- [Your First Transaction](first-transaction.md) — create, inspect, and sign a Bitcoin transaction
- [BIP32 Keys](../how-to/bip32-keys.md) — in-depth guide to hierarchical key derivation
- [API Reference](../api.md) — complete API overview
- [Bitcoin Primer](../bitcoin.md) — background on how Bitcoin works
