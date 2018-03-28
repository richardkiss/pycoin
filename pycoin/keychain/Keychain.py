import sqlite3
import textwrap

from collections import defaultdict


class Keychain(object):
    def __init__(self, sqlite3_db=None):
        self._db = sqlite3_db or sqlite3.connect(":memory:")
        self._db.text_factory = type(b'')
        self._init_tables()
        self.clear_secrets()

    def _exec_sql(self, sql, *args):
        c = self._db.cursor()
        c.execute(sql, args)
        return c

    def _init_table_hash160(self):
        SQL = [textwrap.dedent(_) for _ in [
            "create table if not exists HASH160 (hash160 blob primary key, path text, fingerprint blob)",
            ]]

        for sql in SQL:
            self._exec_sql(sql)
        self._db.commit()

    def _init_tables(self):
        self._init_table_hash160()

    def add_key_paths(self, key, path_iterator=[""]):
        fingerprint = key.fingerprint()
        total = 0
        for path in path_iterator:
            hash160 = key.subkey_for_path(path).hash160()
            self._exec_sql("insert or ignore into HASH160 values (?, ?, ?)", hash160, path, fingerprint)
            total += 1
        self._db.commit()
        return total

    def path_for_hash160(self, hash160):
        SQL = "select fingerprint, path from HASH160 where hash160 = ?"
        c = self._exec_sql(SQL, hash160)
        r = c.fetchone()
        if r is not None:
            return r[0], r[1].decode("utf8")

    def add_key_to_cache(self, key):
        secret_exponent = key.secret_exponent()
        public_pair = key.public_pair()
        for use_uncompressed in (True, False):
            hash160 = key.hash160(use_uncompressed=use_uncompressed)
            self._secret_exponent_cache[hash160] = (secret_exponent, public_pair, not use_uncompressed, key._generator)

    def get(self, hash160):
        if hash160 not in self._secret_exponent_cache:
            v = self.path_for_hash160(hash160)
            if v:
                fingerprint, path = v
                for key in self._secrets.get(fingerprint):
                    subkey = key.subkey_for_path(path)
                    self.add_key_to_cache(subkey)

        return self._secret_exponent_cache.get(hash160)

    def add_secrets(self, private_keys):
        self._secrets = defaultdict(set)
        for key in private_keys:
            self._secrets[key.fingerprint()].add(key)
            self.add_key_to_cache(key)

    def has_secrets(self):
        return len(self._secrets) + len(self._secret_exponent_cache) > 0

    def clear_secrets(self):
        self._secrets = {}
        self._secret_exponent_cache = {}
