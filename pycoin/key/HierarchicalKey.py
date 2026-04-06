from __future__ import annotations

from typing import Any, Iterator

from ..encoding.hexbytes import b2h

from .Key import Key
from .subpaths import subpaths_for_path_range


class HierarchicalKey(Key):
    def subkeys(self, path: str) -> Iterator[Any]:  # type: ignore[override]
        """
        A generalized form that can return multiple subkeys.
        """
        for _ in subpaths_for_path_range(path, hardening_chars="'pH"):
            yield self.subkey_for_path(_)

    def ku_output_for_hk(self) -> Iterator[tuple[str, Any, Any]]:
        yield ("wallet_key", self.hwif(as_private=self.is_private()), None)  # type: ignore[attr-defined]
        if self.is_private():
            yield ("public_version", self.hwif(as_private=False), None)  # type: ignore[attr-defined]

        child_number = self.child_index()  # type: ignore[attr-defined]
        if child_number >= 0x80000000:
            wc = child_number - 0x80000000
            child_index = "%dH (%d)" % (wc, child_number)
        else:
            child_index = "%d" % child_number
        yield ("tree_depth", "%d" % self.tree_depth(), None)  # type: ignore[attr-defined]
        yield ("fingerprint", b2h(self.fingerprint()), None)
        yield ("parent_fingerprint", b2h(self.parent_fingerprint()), "parent f'print")  # type: ignore[attr-defined]
        yield ("child_index", child_index, None)
        yield ("chain_code", b2h(self.chain_code()), None)  # type: ignore[attr-defined]

        yield ("private_key", "yes" if self.is_private() else "no", None)

    def ku_output(self) -> Iterator[Any]:
        for _ in self.ku_output_for_hk():
            yield _

        for _ in super(HierarchicalKey, self).ku_output():
            yield _
