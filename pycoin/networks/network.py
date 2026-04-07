from __future__ import annotations

import dataclasses
from collections.abc import Callable
from typing import Any

from pycoin.ecdsa.Generator import Generator
from pycoin.key.Keychain import Keychain
from pycoin.vm.ScriptTools import ScriptTools
from pycoin.vm.annotate import Annotate
from pycoin.contrib.who_signed import WhoSigned
from .AddressAPI import AddressAPI
from .ContractAPI import ContractAPI
from .ParseAPI import ParseAPI
from .parseable_str import parseable_str


@dataclasses.dataclass
class NetworkKeys:
    private: Callable[..., Any]
    public: Callable[..., Any]
    bip32_seed: Callable[[bytes], Any]
    bip32_deserialize: Callable[[str], Any]
    bip49_deserialize: Callable[[str], Any]
    bip84_deserialize: Callable[[str], Any]
    electrum_seed: Callable[[str], Any]
    electrum_private: Callable[[int], Any]
    electrum_public: Callable[[bytes], Any]
    InvalidSecretExponentError: type[Exception]
    InvalidPublicPairError: type[Exception]


@dataclasses.dataclass
class NetworkMessage:
    parse: Callable[[str, bytes], dict[str, Any]]
    pack: Callable[..., bytes]


@dataclasses.dataclass
class NetworkMsg:
    sign: Callable[..., Any]
    verify: Callable[..., Any]
    parse_signed: Callable[..., Any]
    hash_for_signing: Callable[..., Any]
    signature_for_message_hash: Callable[..., Any]
    pair_for_message_hash: Callable[..., Any]


@dataclasses.dataclass
class NetworkTxUtils:
    create_tx: Callable[..., Any]
    sign_tx: Callable[..., Any]
    create_signed_tx: Callable[..., Any]
    split_with_remainder: Callable[..., Any]
    distribute_from_split_pool: Callable[..., Any]


@dataclasses.dataclass
class NetworkValidator:
    ScriptError: type[Exception]
    ValidationFailureError: type[Exception]
    errno: Any
    flags: Any


@dataclasses.dataclass
class Network:
    """
    Represents a coin network (Bitcoin mainnet, testnet, Groestlcoin, etc.).

    Constructed by create_bitcoinish_network in a two-phase pattern:
      1. Network(symbol, network_name, subnet_name) — creates the object early so
         it can be passed by reference to Key.make_subclass and friends.
      2. All remaining fields are set as the factory builds sub-objects, relying
         on Python reference semantics (mutations are visible via stored references).
    """

    # Required at construction time
    symbol: str
    network_name: str
    subnet_name: str

    # Typed sub-objects — set by create_bitcoinish_network before it returns.
    # Typed as Optional so the two-phase init is type-safe; all will be non-None
    # by the time the factory returns.
    keys: NetworkKeys | None = None
    message: NetworkMessage | None = None
    msg: NetworkMsg | None = None
    tx_utils: NetworkTxUtils | None = None
    validator: NetworkValidator | None = None

    # Concrete types — all set by create_bitcoinish_network before it returns.
    # Optional only to support the two-phase construction pattern.
    parse: ParseAPI | None = None
    contract: ContractAPI | None = None
    address: AddressAPI | None = None
    annotate: Annotate | None = None
    who_signed: WhoSigned | None = None
    generator: Generator | None = None
    script: ScriptTools | None = None
    keychain: type[Keychain] | None = None
    parseable_str_type: type[parseable_str] | None = None

    # Any-typed fields
    Key: Any = None  # set to None by Groestlcoin symbols when C library is absent
    tx: Any = None
    block: Any = None

    # String-encoding callables
    bip32_as_string: Callable[[bytes, bool], str] | None = None
    bip49_as_string: Callable[[bytes, bool], str] | None = None
    bip84_as_string: Callable[[bytes, bool], str] | None = None
    wif_for_blob: Callable[[bytes], str] | None = None
    sec_text_for_blob: Callable[[bytes], str] | None = None
    output_for_secret_exponent: Callable[..., Any] | None = None
    output_for_public_pair: Callable[..., Any] | None = None

    @property
    def Tx(self) -> Any:
        """Alias for network.tx — kept for backward compatibility."""
        return self.tx

    @property
    def Block(self) -> Any:
        """Alias for network.block — kept for backward compatibility."""
        return self.block

    def full_name(self) -> str:
        return "%s %s" % (self.network_name, self.subnet_name)

    def __repr__(self) -> str:
        return "<Network %s>" % self.full_name()
