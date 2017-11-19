from pycoin.ui.Parser import Parser, make_base58_prefixes


class Hash160Parser(Parser):
    TYPE = "key"

    def __init__(self, address_prefix, key_class):
        self._key_class = key_class
        self._base58_prefixes = make_base58_prefixes([
            (address_prefix, self.info_for_address),
        ])

    def info_for_address(self, data):
        kwargs = dict(hash160=data[1:])
        return dict(type="key", key_type="hash160", is_private=False, kwargs=kwargs,
                    key_class=self._key_class, create_f=lambda: self._key_class(**kwargs))
