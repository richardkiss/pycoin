import textwrap

from .RAMKeychain import RAMKeychain


class SQLKeychain(RAMKeychain):
    def __init__(self, sqlite3_db):
        self._db = sqlite3_db
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
        return r
