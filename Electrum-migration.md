# Electrum Migration

This document describes how to migrate from Electrum to pycoin, for both creating and signing transactions offline. It supports multisig, Bitcoin, Bcash (aka Bitcoin Cash), and Bgold (aka Bitcoin Gold).


# Electrum Multisig Wallets

An Electrum M-of-N multisig watch-only wallet is completely defined by a list of N BIP32 hierarchical public keys (an **xpub**) and a number M indicating the size of a quorum (ie. the count of signatures corresponding to any distinct M of the N **xpub** keys required to validate a transaction).

An Electrum wallet file is a json text file. The xpubs can be extracted from the file. Alternatively, you can open the wallet and go to "Wallet > Information" to get the xpubs.

Each **xpub** has a corresponding **xprv** private key, which must remain secret. This **xprv** is stored in the signer's version of the Electrum wallet.


# pycoin Signing

The pycoin tool tx can extract **xprv** information from a GPG file, and can look up source info (address to BIP32 path translation, pay-to-script-hash translation) from the keychain file.

# Set-up

### Converting an Electrum private key into GPG format.

Preferably on an always offline, air-gapped machine, open the Electrum private wallet. Open the console tab (if necessary, select View > Show Console). The console is a python shell, and so has the prompt `>>`. In the console, type the following lines:

    >> import os
    >> xprv = wallet.keystore.get_master_private_key(window.password_dialog()) # fetch xprv
    >> os.system("echo %s | gpg -ac > path-to-wallet.gpg" % xprv)

This will display a password dialog in Electrum. It will then extract the **xprv**. You will see two more password dialogs, these ones from gpg. It's simplest to use the same password that Electrum used. This will then write the **xprv** to the encrypted file path-to-wallet.gpg (you may have to adjust this path, and feel free to name the gpg file something other than "wallet"). This GPG file contains the signing secret and must be protected.

The second line may or may not work depending on how gpg is set up in your environment. If it does not work, you may wish to dump the unencrypted **xprv** value into a file (preferably on a RAM disk), then encrypt it from the shell using

    $ gpg -ac path-to-xprv-file

If you use this method, you should securely delete the original unencrypted file afterward. Because this can be difficult, this method is not recommended.


### Set up a "keychain"

The tx tool needs a database that includes information about two things: which underlying public keys are associated with a given pay-to-script address (the style of address that begins with "3" in bitcoin); and, for a given public key, the associated key path from the BIP32 root key to the BIP32 key that created the public key.

The signing machine needs to have this database. At a shell prompt, with pycoin installed enter the following:

    $ keychain -m3 3of6.keychain 0-1/0-100  xpub661...1  xpub661...2  xpub661...3  xpub661...4  xpub661...5  xpub661...6

Use your own **xpub** values here. Each **xpub** is 111 characters long, so this will be a very long command-line.

The *-m3* means 3-of-N signatures.

The *3of6.keychain* is the keychain, an SQLite3 database.

The 0-1/0-100 is a list of key paths to iterate through. This example will include 0/0, 1/0, 0/1, 1/1, 0/2, 1/2, ..., 0/100, 1/100. You generally want 0-1 (0 means "receive address" and 1 means "change address"), and the 100 value may be larger and smaller depending on how many addresses are used in the Electrum wallet.

The only consequence to making this value too large is the tool takes longer and the database on disk takes up more space. It will not significantly slow down signing. If this number is too small, the source of the coins can be unknown to **tx**, and it will be unable to sign the transaction even though it may actually have the correct base BIP32 key.

In other words, err on the side of the "100" value being too large. This will insulate you from the Electrum wallet growing to include more addresses.

If it ever turns out the value you entered was too small, you can simply run the command again with a larger value for 100. In fact, you can even exclude already generated addresses (so you might run it again with `0-1/101-200`).

#### Creating an unsigned transaction using web services

This method is quite mature (except web services are limited for BTG).

Before using web services, you must set environment variables to designate which services to query. Here are some examples:

    $ export PYCOIN_BTC_PROVIDERS='blockchain.info blockexplorer.com chain.so'
    $ export PYCOIN_BCH_PROVIDERS=insight:http://blockdozer.com/insight-api
    $ export PYCOIN_BTG_PROVIDERS=btgexp.com

Note this potentially compromises privacy, since the API providers can see what addresses or transactions you are interested in.

To use web services to get spendables for particular address, use "-i address". Here is an examples:

    $ tx -n BTC -i 1dyoBoF5vDmPCxwSsUZbbYhA5qjAfBTx9
    f8325d8f7fa5d658ea143629288d0530d2710dc9193ddc067439de803c37066e/0/41046cc86ddcd0860b7cef16cbaad7fe31fda1bf073c25cb833fa9e409e7f51e296f39b653a9c8040a2f967319ff37cf14b0991b86173462a2d5907cb6c5648b5b76ac/5000000000/0/0/0

At this time, there is no service that provides this functionality for BTG that is compatible with tx.

You can also query by transaction. For a given transaction id, you can list the spendable outputs with `-u`. (This feature is supported by the BTG service btgexp.com) Note that a transaction generally has multiple outputs, with different private keys behind each output. It's not typical that you have will have keys for all outputs, so use care in determining which outputs you really can spend.

    $ tx -n BTC -u f8325d8f7fa5d658ea143629288d0530d2710dc9193ddc067439de803c37066e
f8325d8f7fa5d658ea143629288d0530d2710dc9193ddc067439de803c37066e/0/41046cc86ddcd0860b7cef16cbaad7fe31fda1bf073c25cb833fa9e409e7f51e296f39b653a9c8040a2f967319ff37cf14b0991b86173462a2d5907cb6c5648b5b76ac/5000000000/0/0/0

Once you have the spendables or spendables to use, you can build the unsigned transaction.

    $ tx -n BTC f8325d8f7fa5d658ea143629288d0530d2710dc9193ddc067439de803c37066e/0/41046cc86ddcd0860b7cef16cbaad7fe31fda1bf073c25cb833fa9e409e7f51e296f39b653a9c8040a2f967319ff37cf14b0991b86173462a2d5907cb6c5648b5b76ac/5000000000/0/0/0 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH/4000000000 1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP -F 400 -o unsigned_tx.bin

Note that the second address in each example does not specify a quantity. The tx tool splits all unallocated funds equally among the addresses that have no value specified (so put a change address there).

The `-F 400` means 400 satoshi fee. You should check [earn.com](https://bitcoinfees.earn.com/) (or other resources) to determine fee level.

You can double-check the transaction with tx:

    $ tx unsigned_tx.bin

and examine the output.

#### Using the experimental "wallet" tool

The [pycoinnet library](https://github.com/richardkiss/pycoinnet.git) has an experiment wallet tool in the "remix" branch. This is in heavy flux, and certainly contains serious bugs and shortcomings, so temper your expectations. The upside is that, since the main goal of this tool is to collect interesting spendables, a bug generally can only result in creating transaction that attempt to do double-spends, or transactions that we do not actually have the correct secret information to sign. In both cases, the network will ignore the output, and there will be no permanent loss beyond time wasted.

To use the wallet tool, install custom versions of pycoin and pycoinnet.

    $ pip install -e git+https://github.com/richardkiss/pycoin.git@9fa1719e79024115c50a5bf604365765faba4c7c#egg=pycoin
    $ pip install -e git+https://github.com/richardkiss/pycoinnet.git@7fcdd454aa2a7d57bae654bb8314c351145fe7d6#egg=pycoinnet

Wallet configuration is done by listing watched address in a text file (and this is an ugly placeholder mechanism). Put addresses into the file `~/.pycoin/wallet/default/$NETCODE/watch_addresses` where NETCODE is one of BTC, BCH, BTG.

You can create these files with something like

    $ keychain -m3 3of6.keychain 0-1/0-100  xpub661...1  xpub661...2  xpub661...3  xpub661...4  xpub661...5  xpub661...6 > ~/.pycoin/wallet/default/BTC/watch_addresses

Then, you can sync the wallet with

    $ wallet -n BTC fetch

This is perform an SPV fetch to the blockchain tip. This can take a long time, especially the first time. You can speed things up by noting the birth date of the wallet (so the blocks with timestamps prior to this date are not downloaded).

    $ wallet -n BTC fetch -d 2017-01-01

The initial fetch can take a long time, especially if a slow peer is chosen. However, checkpoints are taken every 1000 blocks, so you can interrupt the download with control-C and restart without losing all the work done.

Because this is an SPV download, and transactions are inspected and discarded if they are not considered "interesting" based on `watch_addresses` list, if you change the `watch_addresses` list, you will have to resync. You can use `watch rewind` to force a resync to an earlier block number.

You can dump a list of spendables with "wallet dump", and then create the transaction with tx.

Or you can use "wallet create".

    $ wallet -n BTG create -o unsigned_btg_tx.bin -F 400 GUXByHDZLvU4DnVH9imSFckt3HEQ5cFgE5/10000 GUXByHDZLvU4DnVH9imSFckt3HEQ5cFgE5

This will NOT create a change address; you should specify one manually, without no amount. Change will be sent equally to addresses that have no amount specified. Fees are specified by -F.


Then, you can sync the wallet with

    $ wallet -n BTC fetch

This is an SPV fetch to the tip. This can take a long time, especially the first time. You can speed things up by noting the birth date of the wallet (so the blocks with timestamps prior to this date are not downloaded).

    $ wallet -n BTC fetch -d 2017-01-01

The initial fetch can take a long time, especially if a slow peer is chosen. However, checkpoints are taken every 1000 blocks, so you can interrupt the download with control-C and restart without losing all the work done.

Because this is an SPV download, and transactions are inspected and discarded if they are not considered "interesting" based on `watch_addresses` list, if you change the `watch_addresses` list, you will have to resync. You can use "watch rewind" to force a resync to an earlier block number.

You can dump a list of spendables with "wallet dump", and then create the transaction with tx.

Or you can use "wallet create".

    $ wallet -n BTG create -o unsigned_btg_tx.bin -F 400 GUXByHDZLvU4DnVH9imSFckt3HEQ5cFgE5/10000 GUXByHDZLvU4DnVH9imSFckt3HEQ5cFgE5

This will NOT create a change address; you should specify one manually, without no amount. Change will be sent equally to addresses that have no amount specified. Fees are specified by -F.


### Signing a transaction

Once you have an unsigned transction, signing it on the air-gapped offline machine is simple.

    $ tx -n $NETCODE -k $KEYCHAIN_FILE $UNSIGNED_TX_PATH -f $PATH_TO_GPG_WALLET -o $SIGNED_TX.hex

If the output file has a .hex suffix, the output is written as hex instead of binary. This is useful when transmitting the transaction to the network.


### Broadcasting a transaction

This must obviously be done on a connected machine.

* BTC: use Electrum, or [Blockchain.info send tool](https://blockchain.info/pushtx)
* BCH: use Electrum
* BTG: use Electrum, or [BTGExplorer send tool](https://btgexplorer.com/tx/send)

Or use (the very immature) pushtx

    $ pushtx -n BTC 0000...(hex elided)..7800
