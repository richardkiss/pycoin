from __future__ import annotations

import hashlib
from typing import Any

from pycoin.contrib import bech32m
from pycoin.encoding.b58 import b2a_hashed_base58
from pycoin.encoding.hash import hash160
from pycoin.encoding.hexbytes import b2h


def make_address_api(
    contracts: Any,
    bip32_prv_prefix: bytes | None = None,
    bip32_pub_prefix: bytes | None = None,
    bip49_prv_prefix: bytes | None = None,
    bip49_pub_prefix: bytes | None = None,
    bip84_prv_prefix: bytes | None = None,
    bip84_pub_prefix: bytes | None = None,
    wif_prefix: bytes | None = None,
    sec_prefix: bytes | None = None,
    address_prefix: bytes | None = None,
    pay_to_script_prefix: bytes | None = None,
    bech32_hrp: str | None = None,
) -> Any:

    class AddressAPI(object):
        def for_script(self, script: bytes) -> Any:
            info = contracts.info_for_script(script)
            return self.for_script_info(info)

        def b2a(self, blob: bytes) -> str:
            return b2a_hashed_base58(blob)

        def for_script_info(self, script_info: dict[str, Any]) -> Any:
            type = script_info.get("type")

            if type == "p2pkh":
                return self.for_p2pkh(script_info["hash160"])  # type: ignore[attr-defined]

            if type == "p2pkh_wit":
                return self.for_p2pkh_wit(script_info["hash160"])  # type: ignore[attr-defined]

            if type == "p2sh_wit":
                return self.for_p2sh_wit(script_info["hash256"])  # type: ignore[attr-defined]

            if type == "p2pk":
                h160 = hash160(script_info["sec"])
                # BRAIN DAMAGE: this isn't really a p2pkh
                return self.for_p2pkh(h160)  # type: ignore[attr-defined]

            if type == "p2sh":
                return self.for_p2sh(script_info["hash160"])  # type: ignore[attr-defined]

            if type == "p2tr":
                return self.for_p2tr(script_info["synthetic_key"])  # type: ignore[attr-defined]

            if type == "nulldata":
                return "(nulldata %s)" % b2h(script_info["data"])

            return "???"

        if address_prefix:

            def for_p2pkh(self, h160: bytes) -> str:
                return self.b2a(address_prefix + h160)  # type: ignore[operator]

        if pay_to_script_prefix:

            def for_p2sh(self, h160: bytes) -> str:
                return self.b2a(pay_to_script_prefix + h160)  # type: ignore[operator]

        if bech32_hrp:

            def for_p2pkh_wit(self, h160: bytes) -> str:
                assert len(h160) == 20
                return bech32m.encode(bech32_hrp, 0, h160)  # type: ignore[arg-type,no-any-return]

        if bech32_hrp:

            def for_p2sh_wit(self, hash256: bytes) -> str:
                assert len(hash256) == 32
                return bech32m.encode(bech32_hrp, 0, hash256)  # type: ignore[arg-type,no-any-return]

        if bech32_hrp:

            def for_p2tr(self, synthetic_key: bytes) -> str:
                return bech32m.encode(bech32_hrp, 1, synthetic_key)  # type: ignore[arg-type,no-any-return]

        if pay_to_script_prefix:

            def for_p2s(self, script: bytes) -> str:
                return self.for_p2sh(hash160(script))  # type: ignore[attr-defined]

        if bech32_hrp:

            def for_p2s_wit(self, script: bytes) -> str:
                return self.for_p2sh_wit(hashlib.sha256(script).digest())  # type: ignore[attr-defined]

    return AddressAPI()
