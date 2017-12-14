from pycoin.encoding.bytes32 import from_bytes_32
from pycoin.ui.Parser import Parser, make_base58_prefixes


class WIFParser(Parser):
    TYPE = "key"

    def __init__(self, generator, wif_prefix, address_prefix, key_class):
        self._generator = generator
        self._key_class = key_class
        self._base58_prefixes = make_base58_prefixes([
            (wif_prefix, self.info_for_wif),
        ])

    def info_for_wif(self, data):
        data = data[1:]
        is_compressed = (len(data) > 32)
        if is_compressed:
            data = data[:-1]
        se = from_bytes_32(data)
        kwargs = dict(secret_exponent=se, generator=self._generator,
                      prefer_uncompressed=not is_compressed)

        return dict(type="key", key_type="wif", is_private=True, kwargs=kwargs,
                    key_class=self._key_class, create_f=lambda: self._key_class(**kwargs))
