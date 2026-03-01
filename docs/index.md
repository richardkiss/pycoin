# pycoin

[![GitHub Actions](https://github.com/richardkiss/pycoin/actions/workflows/test.yml/badge.svg)](https://github.com/richardkiss/pycoin/actions/workflows/test.yml)
[![codecov.io](https://codecov.io/github/richardkiss/pycoin/coverage.svg?branch=master)](https://codecov.io/github/richardkiss/pycoin)
[![PyPI License](https://img.shields.io/pypi/l/pycoin.svg)](https://pypi.python.org/pypi/pycoin)
[![PyPI Python versions](https://img.shields.io/pypi/pyversions/pycoin.svg)](https://pypi.python.org/pypi/pycoin)

**pycoin** is a Python library for working with Bitcoin and Bitcoin-like alt-coins. It provides:

- Key generation, derivation, and serialisation (BIP32, WIF, SEC, address formats)
- Transaction construction, signing, and validation
- Multisig and P2SH support
- Command-line tools `ku` and `tx`
- Support for dozens of networks (Bitcoin, Litecoin, Dogecoin, testnet, and more)

This documentation follows the [Diátaxis](https://diataxis.fr/) framework, organised into four
quadrants:

---

## 📖 Tutorials — learning by doing

Start here if you are new to pycoin.

| Page | What you will learn |
|------|---------------------|
| [Getting Started](tutorials/getting-started.md) | Install pycoin, create keys, derive addresses, use `ku` |
| [Your First Transaction](tutorials/first-transaction.md) | Build, inspect, and sign a Bitcoin transaction |

---

## 🛠 How-to Guides — solving specific problems

Practical recipes for common tasks.

| Page | Task |
|------|------|
| [BIP32 Keys](how-to/bip32-keys.md) | Derive hierarchical keys, export xprv/xpub, use standard paths |
| [Sign a Transaction](how-to/sign-a-transaction.md) | Sign with WIFs, keychains, BIP32 keys, or GPG-encrypted files |
| [Multisig](how-to/multisig.md) | Create a 2-of-3 multisig address and spend from it |

---

## 📚 Reference — technical details

Precise descriptions of the API and tools.

| Page | Contents |
|------|----------|
| [API Reference](api.md) | Full overview of the `network` object and all sub-APIs |
| [Command-line Tools](cmdtools.md) | Complete `ku` and `tx` reference with examples |
| [ECDSA](source/pycoin.ecdsa.md) | Low-level ECDSA modules |
| [Services](source/pycoin.services.md) | Blockchain data provider modules |
| [Contract](source/contract.md) | Script-building API |

---

## 💡 Explanation — understanding the design

Background reading to understand *why* pycoin works the way it does.

| Page | Topic |
|------|-------|
| [Design Philosophy](explanation/design-philosophy.md) | Network model, naming conventions, key hierarchy |
| [Bitcoin Primer](bitcoin.md) | How Bitcoin works: UTXOs, transactions, scripts, keys |

---

## Quick start

```bash
pip install pycoin
ku 1          # show all info for secret exponent 1
```

```python
from pycoin.symbols.btc import network

key = network.keys.private(secret_exponent=1)
print(key.wif())      # KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn
print(key.address())  # 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
```

Contributions and corrections are welcome at <https://github.com/richardkiss/pycoin>.
