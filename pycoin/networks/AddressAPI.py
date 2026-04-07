from __future__ import annotations

import hashlib
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from pycoin.contrib import bech32m
from pycoin.encoding.b58 import b2a_hashed_base58
from pycoin.encoding.hash import hash160
from pycoin.encoding.hexbytes import b2h

if TYPE_CHECKING:
    from .ContractAPI import ContractAPI


class AddressAPI:
    """
    Converts raw script-hash values to human-readable addresses for a specific
    network. Every method that depends on a network prefix returns ``str | None``
    and returns ``None`` when that prefix was not configured for the network.

    ``b2a`` is stored as an instance attribute (not a bound method) so that
    coin-specific networks (e.g. Groestlcoin) can swap it out:
        network.address.b2a = groestlcoin_specific_b2a
    """

    def __init__(
        self,
        contracts: ContractAPI,
        address_prefix: bytes | None = None,
        pay_to_script_prefix: bytes | None = None,
        bech32_hrp: str | None = None,
    ) -> None:
        self._contracts = contracts
        self._address_prefix = address_prefix
        self._pay_to_script_prefix = pay_to_script_prefix
        self._bech32_hrp = bech32_hrp
        self.b2a: Callable[[bytes], str] = b2a_hashed_base58

    def for_p2pkh(self, h160: bytes) -> str | None:
        if self._address_prefix is None:
            return None
        return self.b2a(self._address_prefix + h160)

    def for_p2sh(self, h160: bytes) -> str | None:
        if self._pay_to_script_prefix is None:
            return None
        return self.b2a(self._pay_to_script_prefix + h160)

    def for_p2pkh_wit(self, h160: bytes) -> str | None:
        if self._bech32_hrp is None:
            return None
        assert len(h160) == 20
        return bech32m.encode(self._bech32_hrp, 0, h160)  # type: ignore[arg-type,return-value]

    def for_p2sh_wit(self, hash256: bytes) -> str | None:
        if self._bech32_hrp is None:
            return None
        assert len(hash256) == 32
        return bech32m.encode(self._bech32_hrp, 0, hash256)  # type: ignore[arg-type,return-value]

    def for_p2tr(self, synthetic_key: bytes) -> str | None:
        if self._bech32_hrp is None:
            return None
        return bech32m.encode(self._bech32_hrp, 1, synthetic_key)  # type: ignore[arg-type,return-value]

    def for_p2s(self, script: bytes) -> str | None:
        return self.for_p2sh(hash160(script))

    def for_p2s_wit(self, script: bytes) -> str | None:
        return self.for_p2sh_wit(hashlib.sha256(script).digest())

    def for_script(self, script: bytes) -> Any:
        info = self._contracts.info_for_script(script)
        return self.for_script_info(info)

    def for_script_info(self, script_info: dict[str, Any]) -> Any:
        type_ = script_info.get("type")

        if type_ == "p2pkh":
            return self.for_p2pkh(script_info["hash160"])

        if type_ == "p2pkh_wit":
            return self.for_p2pkh_wit(script_info["hash160"])

        if type_ == "p2sh_wit":
            return self.for_p2sh_wit(script_info["hash256"])

        if type_ == "p2pk":
            h160 = hash160(script_info["sec"])
            # BRAIN DAMAGE: this isn't really a p2pkh
            return self.for_p2pkh(h160)

        if type_ == "p2sh":
            return self.for_p2sh(script_info["hash160"])

        if type_ == "p2tr":
            return self.for_p2tr(script_info["synthetic_key"])

        if type_ == "nulldata":
            return "(nulldata %s)" % b2h(script_info["data"])

        return "???"


def make_address_api(
    contracts: ContractAPI,
    address_prefix: bytes | None = None,
    pay_to_script_prefix: bytes | None = None,
    bech32_hrp: str | None = None,
    **_ignored: Any,
) -> AddressAPI:
    """
    Factory wrapper kept for backward compatibility.
    Accepts the full ``ui_kwargs`` dict; unknown keys are silently ignored.
    """
    return AddressAPI(
        contracts=contracts,
        address_prefix=address_prefix,
        pay_to_script_prefix=pay_to_script_prefix,
        bech32_hrp=bech32_hrp,
    )
