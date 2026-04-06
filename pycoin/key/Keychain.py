from __future__ import annotations

import hashlib
import sqlite3
import textwrap
from collections import defaultdict
from collections.abc import Generator, Iterable
from typing import Any

from pycoin.encoding.hash import hash160 as _hash160


class Keychain(object):
    def __init__(self, sqlite3_db: sqlite3.Connection | None = None) -> None:
        self._db = sqlite3_db or sqlite3.connect(":memory:")
        self._db.text_factory = type(b"")
        self._init_tables()
        self.clear_secrets()

    def commit(self) -> None:
        self._db.commit()

    def _exec_sql(self, sql: str, *args: Any) -> sqlite3.Cursor:
        c = self._db.cursor()
        c.execute(textwrap.dedent(sql), args)
        return c

    def _exec_sql_list(self, SQL: list[str]) -> None:
        for sql in SQL:
            self._exec_sql(sql)

    def _init_table_hash160(self) -> None:
        self._exec_sql_list(
            [
                "create table if not exists HASH160 (hash160 blob primary key, path text, fingerprint blob)",
            ]
        )

    def _init_table_p2s(self) -> None:
        self._exec_sql_list(
            [
                "create table if not exists P2S (hash160 blob primary key, hash256 blob, script blob)",
                "create index if not exists P2S_H256 on P2S (hash256)",
            ]
        )

    def _init_tables(self) -> None:
        self._init_table_hash160()
        self._init_table_p2s()
        self.commit()

    def add_keys_path(self, keys: Iterable[Any], path: str) -> int:
        total = 0
        for key in keys:
            fingerprint = key.fingerprint()
            h160 = key.subkey_for_path(path).hash160()
            self._exec_sql(
                "insert or ignore into HASH160 values (?, ?, ?)",
                h160,
                path,
                fingerprint,
            )
            total += 1
        return total

    def add_key_paths(self, key: Any, path_iterator: Iterable[str] = [""]) -> int:
        fingerprint = key.fingerprint()
        total = 0
        for path in path_iterator:
            h160 = key.subkey_for_path(path).hash160()
            self._exec_sql(
                "insert or ignore into HASH160 values (?, ?, ?)",
                h160,
                path,
                fingerprint,
            )
            total += 1
        return total

    def path_for_hash160(self, h160: bytes) -> tuple[bytes, str] | None:
        SQL = "select fingerprint, path from HASH160 where hash160 = ?"
        c = self._exec_sql(SQL, h160)
        r = c.fetchone()
        if r is not None:
            return r[0], r[1].decode("utf8")
        return None

    def add_p2s_script(self, script: bytes) -> None:
        h160 = _hash160(script)
        h256 = hashlib.sha256(script).digest()
        self._exec_sql("insert or ignore into P2S values (?, ?, ?)", h160, h256, script)

    def add_p2s_scripts(self, scripts: Iterable[bytes]) -> None:
        for script in scripts:
            self.add_p2s_script(script)
        self.commit()

    def p2s_for_hash(self, hash160or256: bytes) -> bytes | None:
        SQL = "select script from P2S where hash160 = ? or hash256 = ?"
        c = self._exec_sql(SQL, hash160or256, hash160or256)
        r = c.fetchone()
        if r is not None:
            return r[0]  # type: ignore[no-any-return]
        return None

    def _add_key_to_cache(self, key: Any) -> None:
        secret_exponent = key.secret_exponent()
        public_pair = key.public_pair()
        for is_compressed in (True, False):
            h160 = key.hash160(is_compressed=is_compressed)
            self._secret_exponent_cache[h160] = (
                secret_exponent,
                public_pair,
                is_compressed,
                key._generator,
            )

    def get(self, h160: bytes, default: Any = None) -> Any:
        v = self.p2s_for_hash(h160)
        if v:
            return v

        if h160 not in self._secret_exponent_cache:
            result = self.path_for_hash160(h160)
            if result:
                fingerprint, path = result
                for key in self._secrets.get(fingerprint, []):
                    subkey = key.subkey_for_path(path)
                    self._add_key_to_cache(subkey)

        return self._secret_exponent_cache.get(h160, default)

    def add_secret(self, private_key: Any) -> None:
        self._secrets[private_key.fingerprint()].add(private_key)
        self._add_key_to_cache(private_key)

    def add_secrets(self, private_keys: Iterable[Any]) -> None:
        for key in private_keys:
            self.add_secret(key)

    def has_secrets(self) -> bool:
        return len(self._secrets) + len(self._secret_exponent_cache) > 0

    def clear_secrets(self) -> None:
        self._secrets: defaultdict[Any, set[Any]] = defaultdict(set)
        self._secret_exponent_cache: dict[bytes, Any] = {}

    def interested_hashes(self) -> Generator[bytes, None, None]:
        SQL = "select hash160 from HASH160"
        c = self._exec_sql(SQL)
        for r in c:
            yield r[0]
        SQL = "select hash160, hash256 from P2S"
        c = self._exec_sql(SQL)
        for r in c:
            yield r[0]
            yield r[1]
