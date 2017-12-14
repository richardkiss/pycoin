
from pycoin.encoding.sec import is_sec_compressed, sec_to_public_pair
from pycoin.serialize import h2b
from pycoin.ui.Parser import Parser


class SECParser(Parser):
    TYPE = "key"

    def __init__(self, generator, sec_prefix, key_class):
        self._generator = generator
        self._key_class = key_class
        self._colon_prefixes = {"SEC": [self.info_for_sec]}

    def info_for_sec(self, prefix, text):
        sec = h2b(text)
        public_pair = sec_to_public_pair(sec, self._generator)
        is_compressed = is_sec_compressed(sec)
        kwargs = dict(public_pair=public_pair, is_compressed=is_compressed)
        return dict(type="key", key_type="sec", is_private=False, kwargs=kwargs,
                    key_class=self._key_class, create_f=lambda: self._key_class(**kwargs))
