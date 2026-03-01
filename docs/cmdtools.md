# Command-line Tools Reference

pycoin ships two command-line utilities: **`ku`** (key utility) and **`tx`** (transaction utility).

---

## ku — Key Utility

`ku` is a Swiss Army knife for manipulating Bitcoin (and alt-coin) keys. It accepts keys in many
formats and outputs information about them: BIP32 extended keys, WIF, addresses, public pairs,
hash160 values, and more.

### Basic usage

```
ku [OPTIONS] [KEY ...]
```

A key can be any of the following:

- A **secret exponent** (integer)
- A **WIF** string
- A **BIP32 extended key** (`xprv…` or `xpub…`)
- A passphrase prefixed with `P:` (e.g. `P:foo`) — hashed into a BIP32 seed
- A **public pair** as `x,parity` (e.g. `12345...,even`)
- A **hash160** (40 hex characters)
- The word `create` — generates a fresh random key

### Options

| Option | Description |
|--------|-------------|
| `-n NETCODE` | Network to use (default: `BTC`). Examples: `XTN`, `LTC`, `DOGE` |
| `-a` | Show address only |
| `-w` | Show BIP32 wallet key only |
| `-W` | Show WIF only |
| `-P` | Show public BIP32 key only |
| `-j` | Output as JSON |
| `-s PATH` | Derive subkey at path (e.g. `0/1`, `44H/0H/0H`, `0/0-5`) |
| `-u` | Show uncompressed address |

### Examples

**From secret exponent:**

```
$ ku 1

input           : 1
network         : Bitcoin mainnet
netcode         : BTC
secret exponent : 1
 hex            : 1
wif             : KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn
 uncompressed   : 5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf
public pair x   : 55066263022277343669578718895168534326250603453777594175500187360389116729240
public pair y   : 32670510020758816978083085130507043184471273380659243275938904335757337482424
 x as hex       : 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
 y as hex       : 483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
y parity        : even
key pair as sec : 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
 uncompressed   : 0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\
                    483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
hash160         : 751e76e8199196d454941c45d1b3a323f1433bd6
 uncompressed   : 91b24bf9f5288532960ac687abb035127b1d28a5
Bitcoin address : 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
 uncompressed   : 1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm
```

**Create a random BIP32 key:**

```
$ ku create

input           : create
network         : Bitcoin
wallet key      : xprv9s21ZrQH143K3LU5ctPZTBnb9kTjA5Su9DcWHvXJemiJBsY7VqXUG7hipgdWaU\
                    m2nhnzdvxJf5KJo9vjP2nABX65c5sFsWsV8oXcbpehtJi
public version  : xpub661MyMwAqRbcFpYYiuvZpKjKhnJDZYAkWSY76JvvD7FH4fsG3Nqiov2CfxzxY8\
                    DGcpfT56AMFeo8M8KPkFMfLUtvwjwb6WPv8rY65L2q8Hz
...
Bitcoin address : 1FNNRQ5fSv1wBi5gyfVBs2rkNheMGt86sp
```

**From a passphrase (BIP32 seed):**

!!! warning
    The passphrase `P:foo` is shown for demonstration only — it is trivially guessable and must
    never be used for real funds.

```
$ ku P:foo

input           : P:foo
network         : Bitcoin mainnet
wallet key      : xprv9s21ZrQH143K31AgNK5pyVvW23gHnkBq2wh5aEk6g1s496M8ZMjxncCKZKgb5j\
                    ZoY5eSJMJ2Vbyvi2hbmQnCuHBujZ2WXGTux1X2k9Krdtq
public version  : xpub661MyMwAqRbcFVF9ULcqLdsEa5WnCCugQAcgNd9iEMQ31tgH6u4DLQWoQayvtS\
                    VYFvXz2vPPpbXE1qpjoUFidhjFj82pVShWu9curWmb2zy
...
Bitcoin address : 19Vqc8uLTfUonmxUEZac7fz1M5c5ZZbAii
```

**Address only:**

```
$ ku -a P:foo
19Vqc8uLTfUonmxUEZac7fz1M5c5ZZbAii
```

**WIF only:**

```
$ ku -W P:foo
L26c3H6jEPVSqAr1usXUp9qtQJw6NHgApq6Ls4ncyqtsvcq2MwKH
```

**Public BIP32 key only:**

```
$ ku -w -P P:foo
xpub661MyMwAqRbcFVF9ULcqLdsEa5WnCCugQAcgNd9iEMQ31tgH6u4DLQWoQayvtSVYFvXz2vPPpbXE1qpjoUFidhjFj82pVShWu9curWmb2zy
```

**JSON output:**

```
$ ku P:foo -P -j
{
   "btc_address": "19Vqc8uLTfUonmxUEZac7fz1M5c5ZZbAii",
   "chain_code": "5eeb1023fd6dd1ae52a005ce0e73420821e1d90e08be980a85e9111fd7646bbc",
   "fingerprint": "5d353a2e",
   "netcode": "BTC",
   "network": "Bitcoin mainnet",
   "wallet_key": "xpub661MyMwAqRbcFVF9ULcqLdsEa5WnCCugQAcgNd9iEMQ31tgH6u4DLQWoQayvtSVYFvXz2vPPpbXE1qpjoUFidhjFj82pVShWu9curWmb2zy",
   ...
}
```

**Derive subkeys:**

```
$ ku -w -s 3/2 P:foo
xprv9wTErTSkjVyJa1v4cUTFMFkWMe5eu8ErbQcs9xajnsUzCBT7ykHAwdrxvG3g3f6BFk7ms5hHBvmbdutNmyg6iogWKxx6mefEw4M8EroLgKj

$ ku -w -s 3/2H P:foo
xprv9wTErTSu5AWGkDeUPmqBcbZWX1xq85ZNX9iQRQW9DXwygFp7iRGJo79dsVctcsCHsnZ3XU3DhsuaGZbDh8iDkBN45k67UKsJUXM1JfRCdn1
```

**Derive a range of subkeys:**

```
$ ku P:foo -s 0/0-5 -a
1MrjE78H1R1rqdFrmkjdHnPUdLCJALbv3x
1AnYyVEcuqeoVzH96zj1eYKwoWfwte2pxu
1GXr1kZfxE1FcK6ZRD5sqqqs5YfvuzA1Lb
116AXZc4bDVQrqmcinzu4aaPdrYqvuiBEK
1Cz2rTLjRM6pMnxPNrRKp9ZSvRtj5dDUML
1WstdwPnU6HEUPme1DQayN9nm6j7nDVEM
```

**Work with alt-coins:**

```
$ ku -n LTC 1
...
Litecoin address : LVuDpNCSSj6pQ7t9Pv6d6sUkLKoqDEVUnJ

$ ku -n DOGE -W 1
QNcdLVw8fHkixm6NNyN6nVwxKek4u7qrioRbQmjxac5TVoTtZuot

$ ku -n XTN 1
...
Bitcoin address : mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r
```

**From a hash160:**

```
$ ku 751e76e8199196d454941c45d1b3a323f1433bd6

input           : 751e76e8199196d454941c45d1b3a323f1433bd6
hash160         : 751e76e8199196d454941c45d1b3a323f1433bd6
Bitcoin address : 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
```

---

## tx — Transaction Utility

`tx` displays, constructs, modifies, signs, and broadcasts Bitcoin transactions. It can read
transactions from hex strings, binary files, or by fetching them from block explorers.

### Basic usage

```
tx [OPTIONS] [ARGUMENT ...]
```

Arguments can be:

- A **transaction ID** (fetched from a block explorer if web services are configured)
- A **hex string** of a transaction
- A **file path** to a binary transaction
- A spendable in the form `txid/index/puzzle_script_hex/coin_value`
- A Bitcoin **address** (becomes a TxOut destination)
- A **WIF** string (used to sign inputs)

### Options

| Option | Description |
|--------|-------------|
| `-n NETCODE` | Network (default: `BTC`) |
| `-a` | Augment transaction with source inputs for validation |
| `-i ADDRESS` | Fetch all unspents for ADDRESS and use as inputs |
| `-f FILE` | Read private keys from FILE (`.gpg` files are decrypted via `gpg -d`) |
| `-g GPG_ARG` | Extra argument passed to gpg |
| `-F FEE` | Set transaction fee in satoshis |
| `-u` | Show unspents (UTXOs) for the transaction |
| `-o FILE` | Write output to FILE (`.hex` extension → hex, otherwise binary) |
| `-t VERSION` | Set transaction version |
| `-l LOCK_TIME` | Set lock time |
| `--remove-tx-in N` | Remove TxIn at index N |
| `--remove-tx-out N` | Remove TxOut at index N |
| `-b URL` | Use bitcoind at URL for broadcasting |

### Environment variables

| Variable | Description |
|----------|-------------|
| `PYCOIN_CACHE_DIR` | Directory to cache fetched transactions |
| `PYCOIN_BTC_PROVIDERS` | Space-separated list of block explorer hosts |
| `PYCOIN_XTN_PROVIDERS` | Block explorers for Bitcoin testnet |

Set these in your shell profile to enable automatic transaction fetching and caching:

```bash
export PYCOIN_CACHE_DIR=~/.pycoin_cache
export PYCOIN_BTC_PROVIDERS="blockchain.info blockexplorer.com chain.so"
```

### Examples

**Display a transaction (requires web services):**

```
$ tx 49d2adb6e476fa46d8357babf78b1b501fd39e177ac7833124b3f67b17c40c2a

Version:  1  tx hash 49d2adb6e476fa46d8357babf78b1b501fd39e177ac7833124b3f67b17c40c2a  159 bytes
TxIn count: 1; TxOut count: 1
...
```

**Augment with source transactions for full validation:**

```
$ tx -a 49d2adb6e476fa46d8357babf78b1b501fd39e177ac7833124b3f67b17c40c2a

Input:
  0: 17WFx2GQZUmh6Up2NDNCEDk3deYomdNCfk from 1e133f7d...:0  10000000.00000 mBTC  sig ok
...
all incoming transaction values validated
```

**Build a transaction from a UTXO:**

```
$ tx TXID/INDEX/SCRIPT_HEX/SATOSHIS DESTINATION_ADDRESS -o unsigned.bin
```

**Sign a transaction with a WIF:**

```
$ tx unsigned.bin KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn -o signed.hex
signing...
all incoming transaction values validated
```

**Sign using a GPG-encrypted key file (cold storage workflow):**

```
$ tx unsigned.bin -f private_keys.gpg -o signed.hex
```

If the file ends with `.gpg`, `gpg -d` is invoked automatically and you are prompted for your
passphrase. This makes `tx` + GPG a reasonably secure cold-storage solution.

**List all unspents for a transaction:**

```
$ tx -u TXID
TXID/0/SCRIPT_HEX/SATOSHIS
TXID/1/SCRIPT_HEX/SATOSHIS
```

**Fetch all UTXOs for an address (requires web services):**

```
$ tx -i 12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX
a3a6f902.../0/76a914.../333000
...
```

**Build, split, and sign in one command:**

```
$ tx -F 85000 -i SOURCE_ADDRESS DEST1 DEST2 SOURCE_ADDRESS/50 -o tx.bin
```

This fetches all UTXOs for `SOURCE_ADDRESS`, subtracts a fee of 85 000 satoshis, allocates 50
satoshis back to the source, and splits the remainder evenly between `DEST1` and `DEST2`.

**Output format:**

- File ending with `.hex` → hex-encoded transaction
- Any other file (or omitted) → binary transaction

---

## See also

- [Getting Started tutorial](tutorials/getting-started.md)
- [Sign a Transaction how-to](how-to/sign-a-transaction.md)
- [BIP32 Keys how-to](how-to/bip32-keys.md)
- [API Reference](api.md)
