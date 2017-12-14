from pycoin.encoding.bytes32 import from_bytes_32
from pycoin.serialize import h2b
from pycoin.ui.Parser import Parser


class ElectrumParser(Parser):
    TYPE = "electrum"

    def __init__(self, generator, electrum_class):
        self._generator = generator
        self._electrum_class = electrum_class
        self._colon_prefixes = dict(E=[self.info_for_E])

    def info_for_E(self, prefix, data):
        bin_data = h2b(data)

        size = len(bin_data)
        if size not in (16, 32, 64):
            return

        is_private = (size != 64)

        if size == 16:
            kwargs = dict(initial_key=data, generator=self._generator)
            electrum_type = "seed"

        if size == 32:
            kwargs = dict(master_private_key=from_bytes_32(bin_data), generator=self._generator)
            electrum_type = "private"

        if size == 64:
            kwargs = dict(master_public_key=bin_data, generator=self._generator)
            electrum_type = "public"

        return dict(type="key", key_type="electrum", electrum_type=electrum_type, is_private=is_private,
                    key_class=self._electrum_class, kwargs=kwargs, create_f=lambda: self._electrum_class(**kwargs))
