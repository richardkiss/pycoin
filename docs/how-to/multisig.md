# How to Create and Use a Multisig Address

A *multisig* (multiple-signature) Bitcoin address requires M-of-N private keys to spend the
funds. This guide shows how to create a 2-of-3 multisig address and build a transaction that spends
from it, using pycoin's Python API.

!!! info "What is 2-of-3 multisig?"
    A 2-of-3 multisig address is controlled by three public keys. Any two of the corresponding
    private keys can authorise a spend. This is commonly used for shared custody and as a security
    measure (one key can be lost without losing access to funds).

---

## Prerequisites

```python
from pycoin.symbols.btc import network
from pycoin.encoding.hexbytes import h2b, b2h
```

---

## Step 1: Gather three public keys

In a real setup each participant generates their own key. For this guide we derive three keys from
a BIP32 root:

```python
# In production, each of the three parties supplies their own BIP32 key
root = network.keys.bip32_seed(b"demo-root-key — not secure")

# Derive three compressed public keys (SEC format)
sec_0 = root.subkey_for_path("0/0/0").sec()
sec_1 = root.subkey_for_path("0/1/0").sec()
sec_2 = root.subkey_for_path("0/2/0").sec()

public_keys = [sec_0, sec_1, sec_2]
print("public key 0:", b2h(sec_0))
```

---

## Step 2: Create the 2-of-3 multisig redeem script

```python
# 2-of-3: any 2 signatures from the 3 keys can spend
redeem_script = network.contract.for_multisig(2, public_keys)

print("redeem script:", b2h(redeem_script))
```

The redeem script encodes the M-of-N policy and the three public keys in Bitcoin script.

---

## Step 3: Create the P2SH address

Pay-to-Script-Hash (P2SH) hides the redeem script behind a script hash, giving a standard-looking
address:

```python
multisig_address = network.address.for_p2s(redeem_script)
print("2-of-3 multisig address:", multisig_address)
# Looks like: 3Xxx...  (starts with '3' for mainnet P2SH)
```

---

## Step 4: Fund the multisig address (simulation)

For testing, create a fake coinbase transaction that pays to the multisig address:

```python
tx_in = network.tx.TxIn.coinbase_tx_in(script=b'')
# 1 BTC = 100_000_000 satoshis; 50 BTC = 5_000_000_000 satoshis
tx_out = network.tx.TxOut(
    50 * 100_000_000,  # 5_000_000_000 satoshis
    network.contract.for_address(multisig_address),
)
funding_tx = network.tx(1, [tx_in], [tx_out])

print("funding tx id:", funding_tx.id())
```

---

## Step 5: Create an unsigned spending transaction

```python
spendable = funding_tx.tx_outs_as_spendable()[0]
destination = "1KissFDVu2wAYWPRm4UGh5ZCDU9sE9an8T"

unsigned_tx = network.tx_utils.create_tx(
    spendables=[spendable],
    payables=[destination],
    fee=10_000,
)

print("unsigned bad solutions:", unsigned_tx.bad_solution_count())  # > 0
```

---

## Step 6: Build the P2SH lookup

The signer needs to know which redeem script corresponds to the P2SH output. Build a lookup
dictionary from the raw redeem script bytes:

```python
p2sh_lookup = network.tx.solve.build_p2sh_lookup([redeem_script])
```

---

## Step 7: Sign with the first key

```python
wif_0 = root.subkey_for_path("0/0/0").wif()

network.tx_utils.sign_tx(
    unsigned_tx,
    wifs=[wif_0],
    p2sh_lookup=p2sh_lookup,
)

print("after first sig, bad solutions:", unsigned_tx.bad_solution_count())
# Still > 0 because 2 signatures are required
```

---

## Step 8: Sign with the second key

```python
wif_1 = root.subkey_for_path("0/1/0").wif()

network.tx_utils.sign_tx(
    unsigned_tx,
    wifs=[wif_1],
    p2sh_lookup=p2sh_lookup,
)

print("after second sig, bad solutions:", unsigned_tx.bad_solution_count())
# Now 0 — the transaction is fully signed
```

---

## Step 9: Inspect and broadcast

```python
# Verify the transaction is fully signed
assert unsigned_tx.bad_solution_count() == 0

# Serialize to hex for broadcast
print("signed tx hex:", unsigned_tx.as_hex())
```

---

## Full example as a script

```python
from pycoin.symbols.btc import network
from pycoin.encoding.hexbytes import b2h

# 1. Keys
root = network.keys.bip32_seed(b"demo-root-key — not secure")
sec_0 = root.subkey_for_path("0/0/0").sec()
sec_1 = root.subkey_for_path("0/1/0").sec()
sec_2 = root.subkey_for_path("0/2/0").sec()

# 2. Redeem script and address
redeem_script = network.contract.for_multisig(2, [sec_0, sec_1, sec_2])
address = network.address.for_p2s(redeem_script)
print("multisig address:", address)

# 3. Funding transaction
tx_in = network.tx.TxIn.coinbase_tx_in(script=b'')
funding_tx = network.tx(
    1,
    [tx_in],
    [network.tx.TxOut(50 * 100_000_000, network.contract.for_address(address))],  # 5_000_000_000 satoshis
)

# 4. Spending transaction (unsigned)
spendable = funding_tx.tx_outs_as_spendable()[0]
tx = network.tx_utils.create_tx(
    spendables=[spendable],
    payables=["1KissFDVu2wAYWPRm4UGh5ZCDU9sE9an8T"],
    fee=10_000,
)

# 5. P2SH lookup
p2sh_lookup = network.tx.solve.build_p2sh_lookup([redeem_script])

# 6. Sign with 2 of 3 keys
for path in ("0/0/0", "0/1/0"):
    wif = root.subkey_for_path(path).wif()
    network.tx_utils.sign_tx(tx, wifs=[wif], p2sh_lookup=p2sh_lookup)

print("fully signed:", tx.bad_solution_count() == 0)
print("tx hex:", tx.as_hex())
```

---

## Determine which keys have already signed

```python
# Inspect partial signatures on a multisig transaction
who_signed = network.who_signed.who_signed_tx(
    tx,
    tx_in_index=0,
    p2sh_lookup=p2sh_lookup,
)
print("public keys that have signed:", [b2h(pk) for pk in who_signed])
```

---

## See also

- [Sign a Transaction](sign-a-transaction.md)
- [BIP32 Keys](bip32-keys.md)
- [Your First Transaction tutorial](../tutorials/first-transaction.md)
- [API Reference](../api.md)
