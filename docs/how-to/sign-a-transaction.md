# How to Sign a Transaction

This guide covers the common scenarios for signing Bitcoin transactions using pycoin's Python API:
signing with a single key, signing with multiple keys, and partially signing a multisig
transaction.

---

## Prerequisites

```python
from pycoin.symbols.btc import network
```

---

## Scenario 1: Sign with a single WIF

This is the most common case — one input, one key.

```python
# Build a spendable from a known UTXO
# Format: "txid/output_index/puzzle_script_hex/coin_value_satoshis"
spendable_str = (
    "d61aa2a5f5bce59d2a57447134f7ce9ce9d29b5c471f4bf747c43bf82aa26c2a"
    "/1"
    "/76a91491b24bf9f5288532960ac687abb035127b1d28a588ac"
    "/12345678"
)
spendable = network.parse.spendable(spendable_str)

# Create the unsigned transaction
destination = "1KissFDVu2wAYWPRm4UGh5ZCDU9sE9an8T"
unsigned_tx = network.tx_utils.create_tx(
    spendables=[spendable],
    payables=[destination],
    fee=10_000,
)

print("unsigned, bad solutions:", unsigned_tx.bad_solution_count())  # > 0

# Sign it
wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
network.tx_utils.sign_tx(unsigned_tx, wifs=[wif])

print("signed, bad solutions:", unsigned_tx.bad_solution_count())  # 0
print("tx hex:", unsigned_tx.as_hex())
```

---

## Scenario 2: Sign with multiple WIFs (multiple inputs)

When a transaction has inputs from different addresses, pass all the relevant WIFs:

```python
wifs = [
    "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn",  # key for input 0
    "L26c3H6jEPVSqAr1usXUp9qtQJw6NHgApq6Ls4ncyqtsvcq2MwKH",  # key for input 1
]

network.tx_utils.sign_tx(multi_input_tx, wifs=wifs)
```

pycoin automatically matches each WIF to the corresponding input by checking which puzzle script
the key can solve.

---

## Scenario 3: Sign from a BIP32 key

Instead of passing raw WIFs, you can pass a BIP32 key. pycoin derives the correct child key for
each input automatically.

```python
bip32_key = network.parse.bip32("xprv9s21ZrQH143K...")

# sign_tx accepts BIP32 nodes directly alongside WIFs
network.tx_utils.sign_tx(unsigned_tx, wifs=[bip32_key.subkey_for_path("0/0").wif()])
```

---

## Scenario 4: Create and sign in one step

Use `create_signed_tx` when you have the keys available upfront:

```python
signed_tx = network.tx_utils.create_signed_tx(
    spendables=spendables,
    payables=[destination],
    wifs=[wif],
    fee=10_000,
)

assert signed_tx.bad_solution_count() == 0
```

---

## Scenario 5: Use a Keychain

A `Keychain` aggregates multiple private keys and is passed to the transaction for signing:

```python
from pycoin.key.Keychain import Keychain

key1 = network.parse.private("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn")
key2 = network.parse.private("L26c3H6jEPVSqAr1usXUp9qtQJw6NHgApq6Ls4ncyqtsvcq2MwKH")

keychain = Keychain([key1, key2])

# sign_tx accepts a keychain
network.tx_utils.sign_tx(unsigned_tx, wifs=[], keychain=keychain)
```

---

## Scenario 6: Validate an already-signed transaction

```python
# bad_solution_count() returns the number of inputs that are not correctly signed
count = signed_tx.bad_solution_count()
if count == 0:
    print("Transaction is fully signed and valid")
else:
    print(f"{count} input(s) still unsigned or invalid")
```

---

## Scenario 7: Partially sign a multisig transaction

For a 2-of-3 multisig input, sign once with the first key, then again with the second:

```python
# First signature
network.tx_utils.sign_tx(tx, wifs=[wif1], p2sh_lookup=p2sh_lookup)
print("after first sig, bad solutions:", tx.bad_solution_count())  # still 1+

# Second signature — the transaction becomes fully valid
network.tx_utils.sign_tx(tx, wifs=[wif2], p2sh_lookup=p2sh_lookup)
print("after second sig, bad solutions:", tx.bad_solution_count())  # 0
```

The `p2sh_lookup` maps script hashes to the underlying redeem scripts. Build it with:

```python
p2sh_lookup = network.tx.solve.build_p2sh_lookup([redeem_script_bytes])
```

See the [Multisig How-to](multisig.md) for a complete walkthrough.

---

## Sign via the `tx` command-line tool

```bash
# Sign tx.bin with a WIF directly
tx tx.bin KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn -o signed.hex

# Sign using a file containing WIFs
tx tx.bin -f wifs.txt -o signed.hex

# Sign using a GPG-encrypted WIF file (passphrase prompted interactively)
tx tx.bin -f wifs.gpg -o signed.hex
```

---

## See also

- [Your First Transaction tutorial](../tutorials/first-transaction.md)
- [Multisig How-to](multisig.md)
- [BIP32 Keys How-to](bip32-keys.md)
- [API Reference — network.tx_utils](../api.md#networktx_utils)
