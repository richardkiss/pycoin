from ..encoding.hexbytes import b2h

from .Key import Key
from .subpaths import subpaths_for_path_range


class HierarchicalKey(Key):
    def subkeys(self, path):
        """
        A generalized form that can return multiple subkeys.
        """
        for _ in subpaths_for_path_range(path, hardening_chars="'pH"):
            yield self.subkey_for_path(_)

    def ku_output_for_hk(self):
        yield ("wallet_key", self.hwif(as_private=self.is_private()), None)
        if self.is_private():
            yield ("public_version", self.hwif(as_private=False), None)

        child_number = self.child_index()
        if child_number >= 0x80000000:
            wc = child_number - 0x80000000
            child_index = "%dH (%d)" % (wc, child_number)
        else:
            child_index = "%d" % child_number
        yield ("tree_depth", "%d" % self.tree_depth(), None)
        yield ("fingerprint", b2h(self.fingerprint()), None)
        yield ("parent_fingerprint", b2h(self.parent_fingerprint()), "parent f'print")
        yield ("child_index", child_index, None)
        yield ("chain_code", b2h(self.chain_code()), None)

        yield ("private_key", "yes" if self.is_private() else "no", None)

    def ku_output(self):
        for _ in self.ku_output_for_hk():
            yield _

        for _ in super(HierarchicalKey, self).ku_output():
            yield _