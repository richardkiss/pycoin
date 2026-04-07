from __future__ import annotations

from typing import Any

from pycoin.block import Block
from .network import Network, NetworkKeys, NetworkMessage, NetworkMsg, NetworkTxUtils, NetworkValidator
from pycoin.coins.bitcoin.ScriptTools import BitcoinScriptTools
from pycoin.coins.bitcoin.Tx import Tx
from pycoin.coins.exceptions import ValidationFailureError
from pycoin.coins.tx_utils import (
    create_tx,
    split_with_remainder,
    distribute_from_split_pool,
    sign_tx,
    create_signed_tx,
)
from pycoin.coins.SolutionChecker import ScriptError
from pycoin.contrib.msg_signing import MessageSigner
from pycoin.contrib.who_signed import WhoSigned
from pycoin.ecdsa.secp256k1 import secp256k1_generator
from pycoin.encoding.b58 import b2a_hashed_base58
from pycoin.key.Keychain import Keychain
from pycoin.key.Key import Key, InvalidSecretExponentError, InvalidPublicPairError
from pycoin.key.BIP32Node import BIP32Node
from pycoin.key.BIP49Node import BIP49Node
from pycoin.key.BIP84Node import BIP84Node
from pycoin.key.electrum import ElectrumWallet
from pycoin.message.make_parser_and_packer import (
    make_parser_and_packer,
    standard_messages,
    standard_message_post_unpacks,
    standard_streamer,
    standard_parsing_functions,
)
from pycoin.encoding.hexbytes import b2h, h2b
from pycoin.satoshi import errno, flags
from pycoin.solve.utils import build_hash160_lookup, build_p2sh_lookup, build_sec_lookup
from pycoin.vm.annotate import Annotate

from .AddressAPI import make_address_api
from .ParseAPI import ParseAPI
from .ContractAPI import ContractAPI
from .parseable_str import parseable_str


class API(object):
    """Legacy namespace shim — kept for external compatibility but not used internally."""
    pass


def make_output_for_secret_exponent(Key: Any) -> Any:
    def f(secret_exponent: int) -> Any:
        yield ("secret_exponent", "%d" % secret_exponent, None)
        yield ("secret_exponent_hex", "%x" % secret_exponent, " hex")
        key = Key(secret_exponent)
        yield ("wif", key.wif(is_compressed=True), None)
        yield ("wif_uncompressed", key.wif(is_compressed=False), " uncompressed")

    return f


def make_output_for_public_pair(Key: Any, network: Any) -> Any:
    def f(public_pair: Any) -> Any:
        yield ("public_pair_x", "%d" % public_pair[0], None)
        yield ("public_pair_y", "%d" % public_pair[1], None)
        yield ("public_pair_x_hex", "%x" % public_pair[0], " x as hex")
        yield ("public_pair_y_hex", "%x" % public_pair[1], " y as hex")
        yield ("y_parity", "odd" if (public_pair[1] & 1) else "even", None)

        key = Key(public_pair=public_pair)
        yield ("key_pair_as_sec", b2h(key.sec(is_compressed=True)), None)
        yield (
            "key_pair_as_sec_uncompressed",
            b2h(key.sec(is_compressed=False)),
            " uncompressed",
        )

        network_name = network.network_name
        hash160_u = key.hash160(is_compressed=False)
        hash160_c = key.hash160(is_compressed=True)

        yield ("hash160", b2h(hash160_c), None)

        if hash160_c and hash160_u:
            yield ("hash160_uncompressed", b2h(hash160_u), " uncompressed")

        address = network.address.for_p2pkh(hash160_c)
        yield ("address", address, "%s address" % network_name)
        yield ("%s_address" % network.symbol, address, "legacy")

        address = key.address(is_compressed=False)
        yield (
            "address_uncompressed",
            address,
            "%s address uncompressed" % network_name,
        )
        yield ("%s_address_uncompressed" % network.symbol, address, "legacy")

        # don't print segwit addresses unless we're sure we have a compressed key
        if hash160_c:
            address_segwit = network.address.for_p2pkh_wit(hash160_c) if network.address else None
            if address_segwit:
                # this network seems to support segwit
                yield (
                    "address_segwit",
                    address_segwit,
                    "%s segwit address" % network_name,
                )
                yield ("%s_address_segwit" % network.symbol, address_segwit, "legacy")

                p2sh_script = network.contract.for_p2pkh_wit(hash160_c)
                p2s_address = network.address.for_p2s(p2sh_script)
                if p2s_address:
                    yield ("p2sh_segwit", p2s_address, None)

                p2sh_script_hex = b2h(p2sh_script)
                yield (
                    "p2sh_segwit_script",
                    p2sh_script_hex,
                    " corresponding p2sh script",
                )

    return f


def create_bitcoinish_network(symbol: str, network_name: str, subnet_name: str, **kwargs: Any) -> Network:
    # potential kwargs:
    #   tx, block, magic_header_hex, default_port, dns_bootstrap,
    #   wif_prefix_hex, address_prefix_hex, pay_to_script_prefix_hex
    #   bip32_prv_prefix_hex, bip32_pub_prefix_hex, sec_prefix, script_tools
    #   bip49_prv_prefix, bip49_pub_prefix, bip84_prv_prefix, bip84_pub_prefix

    # --- Phase 1: primitives, no dependency on network object yet ---

    generator = kwargs.get("generator", secp256k1_generator)
    kwargs.setdefault("sec_prefix", "%sSEC" % symbol.upper())
    KEYS_TO_H2B = (
        "bip32_prv_prefix bip32_pub_prefix bip49_prv_prefix bip49_pub_prefix "
        "bip84_prv_prefix bip84_pub_prefix wif_prefix address_prefix "
        "pay_to_script_prefix sec_prefix magic_header"
    ).split()
    for k in KEYS_TO_H2B:
        k_hex = "%s_hex" % k
        if k_hex in kwargs:
            kwargs[k] = h2b(kwargs[k_hex])

    script_tools = kwargs.get("script_tools", BitcoinScriptTools)

    UI_KEYS = (
        "bip32_prv_prefix bip32_pub_prefix bip49_prv_prefix bip49_pub_prefix "
        "bip84_prv_prefix bip84_pub_prefix wif_prefix sec_prefix "
        "address_prefix pay_to_script_prefix bech32_hrp"
    ).split()
    ui_kwargs = {k: kwargs[k] for k in UI_KEYS if k in kwargs}

    _wif_prefix = ui_kwargs.get("wif_prefix")
    _sec_prefix = ui_kwargs.get("sec_prefix")

    def bip32_as_string(blob: bytes, as_private: bool) -> str:
        prefix = ui_kwargs.get("bip32_%s_prefix" % ("prv" if as_private else "pub"))
        return b2a_hashed_base58(prefix + blob)  # type: ignore[operator]

    def bip49_as_string(blob: bytes, as_private: bool) -> str:
        prefix = ui_kwargs.get("bip49_%s_prefix" % ("prv" if as_private else "pub"))
        return b2a_hashed_base58(prefix + blob)  # type: ignore[operator]

    def bip84_as_string(blob: bytes, as_private: bool) -> str:
        prefix = ui_kwargs.get("bip84_%s_prefix" % ("prv" if as_private else "pub"))
        return b2a_hashed_base58(prefix + blob)  # type: ignore[operator]

    def wif_for_blob(blob: bytes) -> str:
        return b2a_hashed_base58(_wif_prefix + blob)  # type: ignore[operator]

    def sec_text_for_blob(blob: bytes) -> str:
        return _sec_prefix + b2h(blob)  # type: ignore[operator,no-any-return]

    tx_class: Any = kwargs.get("tx") or Tx

    # --- Phase 2: create bare Network so Key subclasses can store a reference ---
    # Python reference semantics: subclasses store a pointer; remaining fields
    # are filled in below and will be visible through that pointer.

    network = Network(symbol=symbol, network_name=network_name, subnet_name=subnet_name)

    # Propagate optional top-level network metadata from kwargs
    for k in "dns_bootstrap default_port magic_header".split():
        if k in kwargs:
            setattr(network, k, kwargs[k])

    # Key subclasses capture network by reference; they use it lazily at call time.
    NetworkKey: Any = Key.make_subclass(symbol, network=network, generator=generator)
    NetworkElectrumKey: Any = ElectrumWallet.make_subclass(
        symbol, network=network, generator=generator
    )
    NetworkBIP32Node: Any = BIP32Node.make_subclass(
        symbol, network=network, generator=generator
    )
    NetworkBIP49Node: Any = BIP49Node.make_subclass(
        symbol, network=network, generator=generator
    )
    NetworkBIP84Node: Any = BIP84Node.make_subclass(
        symbol, network=network, generator=generator
    )

    # --- Phase 3: build sub-objects and assign to network fields ---

    network.tx = tx_class
    network.block = kwargs.get("block") or Block.make_subclass(symbol, tx_class)
    network.generator = generator
    network.keychain = Keychain
    network.script = script_tools
    network.parseable_str_type = parseable_str

    # tx.solve namespace (still uses API() shim — Tx class is untyped)
    network.tx.solve = API()
    network.tx.solve.build_hash160_lookup = (
        lambda iter: build_hash160_lookup(iter, [generator])
    )
    network.tx.solve.build_p2sh_lookup = build_p2sh_lookup
    network.tx.solve.build_sec_lookup = build_sec_lookup

    # message (P2P serialisation)
    streamer = standard_streamer(standard_parsing_functions(network.block, network.tx))
    msg_parse, msg_pack = make_parser_and_packer(
        streamer, standard_messages(), standard_message_post_unpacks(streamer)
    )
    network.message = NetworkMessage(parse=msg_parse, pack=msg_pack)

    # circular-dep sub-objects: contract → parse → address
    network.contract = ContractAPI(network, script_tools)
    parse_api_class = kwargs.get("parse_api_class", ParseAPI)
    network.parse = parse_api_class(network, **ui_kwargs)
    network.address = make_address_api(network.contract, **ui_kwargs)

    # objects that depend on network.address
    message_signer = MessageSigner(network, generator)
    network.annotate = Annotate(script_tools, network.address)
    network.who_signed = WhoSigned(script_tools, network.address, generator)

    # typed sub-dataclasses

    def keys_private(secret_exponent: int, is_compressed: bool = True) -> Any:
        return NetworkKey(secret_exponent=secret_exponent, is_compressed=is_compressed)

    def keys_public(item: Any, is_compressed: bool | None = None) -> Any:
        if isinstance(item, tuple):
            if is_compressed is None:
                is_compressed = True
            return NetworkKey(public_pair=item, is_compressed=is_compressed)
        if is_compressed is not None:
            raise ValueError("can't set is_compressed from sec")
        return NetworkKey.from_sec(item)

    network.keys = NetworkKeys(
        private=keys_private,
        public=keys_public,
        bip32_seed=NetworkBIP32Node.from_master_secret,
        bip32_deserialize=NetworkBIP32Node.deserialize,
        bip49_deserialize=NetworkBIP49Node.deserialize,
        bip84_deserialize=NetworkBIP84Node.deserialize,
        electrum_seed=lambda seed=None, **kw: NetworkElectrumKey(initial_key=seed, **kw),
        electrum_private=lambda master_private_key=None, **kw: NetworkElectrumKey(
            master_private_key=master_private_key, **kw
        ),
        electrum_public=lambda master_public_key=None, **kw: NetworkElectrumKey(
            master_public_key=master_public_key, **kw
        ),
        InvalidSecretExponentError=InvalidSecretExponentError,
        InvalidPublicPairError=InvalidPublicPairError,
    )

    network.msg = NetworkMsg(
        sign=message_signer.sign_message,
        verify=message_signer.verify_message,
        parse_signed=message_signer.parse_signed_message,
        hash_for_signing=message_signer.hash_for_signing,
        signature_for_message_hash=message_signer.signature_for_message_hash,
        pair_for_message_hash=message_signer.pair_for_message_hash,
    )

    network.validator = NetworkValidator(
        ScriptError=ScriptError,
        ValidationFailureError=ValidationFailureError,
        errno=errno,
        flags=flags,
    )

    network.tx_utils = NetworkTxUtils(
        create_tx=lambda *a, **kw: create_tx(network, *a, **kw),
        sign_tx=lambda *a, **kw: sign_tx(network, *a, **kw),
        create_signed_tx=lambda *a, **kw: create_signed_tx(network, *a, **kw),
        split_with_remainder=lambda *a, **kw: split_with_remainder(*a, **kw),
        distribute_from_split_pool=distribute_from_split_pool,
    )

    network.bip32_as_string = bip32_as_string
    network.bip49_as_string = bip49_as_string
    network.bip84_as_string = bip84_as_string
    network.wif_for_blob = wif_for_blob
    network.sec_text_for_blob = sec_text_for_blob
    network.output_for_secret_exponent = make_output_for_secret_exponent(NetworkKey)
    network.output_for_public_pair = make_output_for_public_pair(NetworkKey, network)

    return network
