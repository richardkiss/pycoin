# Your First Transaction

This tutorial walks you through creating, inspecting, and signing a Bitcoin transaction using
pycoin's Python API. By the end you will understand how transactions are built from spendable
outputs, how the signing flow works, and how to inspect a transaction's state.

!!! note "Demo keys"
    This tutorial uses well-known private keys (secret exponent `1`) that appear in the blockchain.
    Do **not** use these keys to hold real funds.

---

## 1. Background: inputs, outputs, and signing

A Bitcoin transaction takes one or more *spendable outputs* (UTXOs) as inputs and creates one or
more new outputs. Each input must be *signed* by the private key that controls the corresponding
output. pycoin models this flow as:

1. **Build** a list of `Spendable` objects from prior transactions.
2. **Create** an unsigned transaction from those spendables and a list of payable addresses.
3. **Sign** the transaction with the relevant private keys (WIFs).

---

## 2. Get the network object

```python
from pycoin.symbols.btc import network
```

All pycoin API for a particular coin flows through a `network` object.

---

## 3. Create a coinbase transaction (for testing)

In production you would obtain spendables from a real prior transaction. For testing, we create
a fake *coinbase* transaction — one that generates coins out of thin air, as the block reward does.

```python
# A coinbase TxIn has no predecessor
tx_in = network.tx.TxIn.coinbase_tx_in(script=b'')

# Pay 50 BTC to a demo address.
# 1 BTC = 100_000_000 satoshis (the smallest unit), so 50 BTC = 5_000_000_000 satoshis.
satoshis = 50 * 100_000_000  # 5_000_000_000 satoshis
script = network.contract.for_address("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")
tx_out = network.tx.TxOut(satoshis, script)

# version=1, inputs, outputs
coinbase_tx = network.tx(1, [tx_in], [tx_out])

print("coinbase tx id:", coinbase_tx.id())
print("coinbase tx hex:", coinbase_tx.as_hex())
```

---

## 4. Extract spendables from the coinbase transaction

```python
# Each TxOut in a confirmed transaction becomes a spendable
spendables = coinbase_tx.tx_outs_as_spendable()
print("spendable[0]:", spendables[0])
# Shows: coin_value / puzzle_script / tx_hash:index
```

---

## 5. Create an unsigned transaction

```python
# Send all coins (minus a fee) to another address
destination = "1KissFDVu2wAYWPRm4UGh5ZCDU9sE9an8T"

unsigned_tx = network.tx_utils.create_tx(
    spendables=[spendables[0]],
    payables=[destination],
    fee=10_000,          # 10_000 satoshis transaction fee
)

print("unsigned tx id:", unsigned_tx.id())
print("bad solutions: ", unsigned_tx.bad_solution_count())
# bad_solution_count > 0 because not yet signed
```

`create_tx` builds a transaction that spends the given UTXOs and distributes the remaining value
(after the fee) across the payable addresses.

---

## 6. Sign the transaction

The address `1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH` corresponds to secret exponent `1`, whose WIF is
`KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn`.

```python
wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"

network.tx_utils.sign_tx(unsigned_tx, wifs=[wif])

print("bad solutions after signing:", unsigned_tx.bad_solution_count())
# Should print 0 if signing succeeded

print("signed tx hex:", unsigned_tx.as_hex())
```

---

## 7. Inspect the transaction

```python
# Print a summary of each input
for i, tx_in in enumerate(unsigned_tx.txs_in):
    print(f"TxIn  {i}: script length {len(tx_in.script)} bytes")

# Print a summary of each output
for i, tx_out in enumerate(unsigned_tx.txs_out):
    addr = network.address.for_script(tx_out.puzzle_script())
    print(f"TxOut {i}: {tx_out.coin_value} satoshis → {addr}")
```

---

## 8. Serialize and deserialize

```python
# Serialize to hex for broadcast or storage
hex_str = unsigned_tx.as_hex()

# Deserialize back
reconstructed = network.tx.from_hex(hex_str)
print("reconstructed id:", reconstructed.id())
assert reconstructed.id() == unsigned_tx.id()
```

---

## 9. One-shot: create and sign in a single call

If you already have the WIFs available, you can skip the separate sign step:

```python
signed_tx = network.tx_utils.create_signed_tx(
    spendables=[spendables[0]],
    payables=[destination],
    wifs=[wif],
    fee=10_000,
)

print("fully signed:", signed_tx.bad_solution_count() == 0)
```

---

## Next steps

- [Sign a Transaction (How-to)](../how-to/sign-a-transaction.md) — more signing scenarios
- [Create a Multisig Address (How-to)](../how-to/multisig.md) — 2-of-3 multisig
- [API Reference](../api.md) — complete reference for `network.tx_utils` and `network.tx`
- [Bitcoin Primer](../bitcoin.md) — background on transactions, inputs, and outputs
