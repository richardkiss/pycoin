import hashlib
import textwrap

try:
    import sqlite3
except ImportError:
    pass

from collections import defaultdict

from pycoin.encoding.hash import hash160


class Keychain(object):
    def __init__(self, sqlite3_db=None):
        self._db = sqlite3_db or sqlite3.connect(":memory:")
        self._db.text_factory = type(b'')
        self._init_tables()
        self.clear_secrets()

    def commit(self):
        self._db.commit()

    def _exec_sql(self, sql, *args):
        c = self._db.cursor()
        c.execute(textwrap.dedent(sql), args)
        return c

    def _exec_sql_list(self, SQL):
        for sql in SQL:
            self._exec_sql(sql)

    def _init_table_hash160(self):
        self._exec_sql_list([
            "create table if not exists HASH160 (hash160 blob primary key, path text, fingerprint blob)",
        ])

    def _init_table_p2s(self):
        self._exec_sql_list([
            "create table if not exists P2S (hash160 blob primary key, hash256 blob, script blob)",
            "create index if not exists P2S_H256 on P2S (hash256)",
        ])

    def _init_tables(self):
        self._init_table_hash160()
        self._init_table_p2s()
        self.commit()

    def add_keys_path(self, keys, path):
        total = 0
        for key in keys:
            fingerprint = key.fingerprint()
            hash160 = key.subkey_for_path(path).hash160()
            self._exec_sql("insert or ignore into HASH160 values (?, ?, ?)", hash160, path, fingerprint)
            total += 1
        return total

    def add_key_paths(self, key, path_iterator=[""]):
        fingerprint = key.fingerprint()
        total = 0
        for path in path_iterator:
            hash160 = key.subkey_for_path(path).hash160()
            self._exec_sql("insert or ignore into HASH160 values (?, ?, ?)", hash160, path, fingerprint)
            total += 1
        return total

    def path_for_hash160(self, hash160):
        SQL = "select fingerprint, path from HASH160 where hash160 = ?"
        c = self._exec_sql(SQL, hash160)
        r = c.fetchone()
        if r is not None:
            return r[0], r[1].decode("utf8")

    def add_p2s_script(self, script):
        h160 = hash160(script)
        h256 = hashlib.sha256(script).digest()
        self._exec_sql("insert or ignore into P2S values (?, ?, ?)", h160, h256, script)

    def add_p2s_scripts(self, scripts):
        for script in scripts:
            self.add_p2s_script(script)
        self.commit()

    def p2s_for_hash(self, hash160or256):
        SQL = "select script from P2S where hash160 = ? or hash256 = ?"
        c = self._exec_sql(SQL, hash160or256, hash160or256)
        r = c.fetchone()
        if r is not None:
            return r[0]

    def _add_key_to_cache(self, key):
        secret_exponent = key.secret_exponent()
        public_pair = key.public_pair()
        for is_compressed in (True, False):
            hash160 = key.hash160(is_compressed=is_compressed)
            self._secret_exponent_cache[hash160] = (secret_exponent, public_pair, is_compressed, key._generator)

    def get(self, hash160, default=None):
        v = self.p2s_for_hash(hash160)
        if v:
            return v

        if hash160 not in self._secret_exponent_cache:
            v = self.path_for_hash160(hash160)
            if v:
                fingerprint, path = v
                for key in self._secrets.get(fingerprint, []):
                    subkey = key.subkey_for_path(path)
                    self._add_key_to_cache(subkey)

        return self._secret_exponent_cache.get(hash160, default)

    def add_secret(self, private_key):
        self._secrets[private_key.fingerprint()].add(private_key)
        self._add_key_to_cache(private_key)

    def add_secrets(self, private_keys):
        for key in private_keys:
            self.add_secret(key)

    def has_secrets(self):
        return len(self._secrets) + len(self._secret_exponent_cache) > 0

    def clear_secrets(self):
        self._secrets = defaultdict(set)
        self._secret_exponent_cache = {}

    def interested_hashes(self):
        SQL = "select hash160 from HASH160"
        c = self._exec_sql(SQL)
        for r in c:
            yield r[0]
        SQL = "select hash160, hash256 from P2S"
        c = self._exec_sql(SQL)
        for r in c:
            yield r[0]
            yield r[1]
