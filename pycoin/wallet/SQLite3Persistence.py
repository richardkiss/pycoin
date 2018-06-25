from pycoin.encoding.hexbytes import b2h, h2b, b2h_rev, h2b_rev
from pycoin.key.BIP32Node import BIP32Node


class SQLite3Persistence(object):
    def __init__(self, sqlite3_db):
        self.db = sqlite3_db
        self._init_tables()

    def _exec_sql(self, sql, *args):
        c = self.db.cursor()
        c.execute(sql, args)
        return c

    def commit(self):
        self.db.commit()

    def rollback(self):
        self.db.rollback()

    def _init_tables(self):
        self._init_table_bip32key()
        self._init_table_bip32node()
        self._init_table_spendable()
        self._init_table_globals()
        self._init_other_tables()

    def _init_other_tables(self):
        pass

    def _init_table_bip32key(self):
        SQL = """create table if not exists BIP32Key (
id integer primary key,
slug text not null unique,
as_text text not null
);"""
        self._exec_sql(SQL)
        self.db.commit()

    def bip32node_for_slug(self, slug):
        c = self._exec_sql("select id, as_text from BIP32Key where slug=?", slug)
        r = c.fetchone()
        if r is None:
            return None
        bip32_node = BIP32Node.from_hwif(r[1])
        bip32_node.id = r[0]
        return bip32_node

    def create_bip32node(self, slug, random_bytes):
        bip32_node = BIP32Node.from_master_secret(random_bytes)
        bip32_text = bip32_node.as_text(as_private=True)
        self._exec_sql("insert into BIP32Key (slug, as_text) values (?, ?)", slug, bip32_text)
        return self.bip32node_for_slug(slug)

    def _init_table_bip32node(self):
        SQL = """create table if not exists BIP32Node (
path text not null,
key_id integer,
address text unique,
unique(path, key_id)
);"""
        self._exec_sql(SQL)
        self.db.commit()

    def add_bip32_path(self, bip32_node, path):
        address = bip32_node.subkey_for_path(path).address()
        key_id = bip32_node.id
        self._exec_sql("insert or ignore into BIP32Node values (?, ?, ?)", path, key_id, address)
        self.db.commit()
        return address

    def interesting_addresses(self):
        c = self._exec_sql("select address from BIP32Node")
        return (r[0] for r in c)

    def secret_exponent_for_address(self, bip32_node, address):
        c = self._exec_sql("select path from BIP32Node where key_id = ? and address = ?", bip32_node.id, address)
        r = c.fetchone()
        if r is None:
            return r
        path = r[0]
        return bip32_node.subkey_for_path(path).secret_exponent()

    def _init_table_globals(self):
        SQL = """create table if not exists Global (
slug text primary key,
data text
);"""
        self._exec_sql(SQL)
        self.db.commit()

    def set_global(self, slug, value):
        self._exec_sql("insert or replace into Global values (?, ?)", slug, value)

    def get_global(self, slug):
        c = self._exec_sql("select data from Global where slug = ?", slug)
        r = c.fetchone()
        if r is None:
            return r
        return r[0]

    def slugs(self):
        for r in self._exec_sql("select slug from Global"):
            yield r[0]

    def _init_table_spendable(self):
        SQL = ["""create table if not exists Spendable (
tx_hash text,
tx_out_index integer,
coin_value integer,
script text,
block_index_available integer,
does_seem_spent boolean,
block_index_spent integer,
unique(tx_hash, tx_out_index)
);""",
               "create index if not exists Spendable_cv on Spendable (coin_value);",
               "create index if not exists Spendable_bia on Spendable (block_index_available);",
               "create index if not exists Spendable_bis on Spendable (block_index_spent);"]

        for sql in SQL:
            self._exec_sql(sql)
        self.db.commit()

    def save_spendable(self, spendable):
        tx_hash = b2h_rev(spendable.tx_hash)
        script = b2h(spendable.script)
        self._exec_sql("insert or replace into Spendable values (?, ?, ?, ?, ?, ?, ?)", tx_hash,
                       spendable.tx_out_index, spendable.coin_value, script,
                       spendable.block_index_available, spendable.does_seem_spent,
                       spendable.block_index_spent)

    def delete_spendable(self, tx_hash, tx_out_index):
        self._exec_sql("delete from Spendable where tx_hash = ? and tx_out_index = ?",
                       b2h_rev(tx_hash), tx_out_index)

    def spendable_for_hash_index(self, tx_hash, tx_out_index, spendable_class):
        tx_hash_hex = b2h_rev(tx_hash)
        SQL = ("select coin_value, script, block_index_available, "
               "does_seem_spent, block_index_spent from Spendable where "
               "tx_hash = ? and tx_out_index = ?")
        c = self._exec_sql(SQL, tx_hash_hex, tx_out_index)
        r = c.fetchone()
        if r is None:
            return r
        return spendable_class(coin_value=r[0], script=h2b(r[1]), tx_hash=tx_hash,
                               tx_out_index=tx_out_index, block_index_available=r[2],
                               does_seem_spent=r[3], block_index_spent=r[4])

    @staticmethod
    def spendable_for_row(r, spendable_class):
        return spendable_class(coin_value=r[2], script=h2b(r[3]), tx_hash=h2b_rev(r[0]), tx_out_index=r[1],
                               block_index_available=r[4], does_seem_spent=r[5], block_index_spent=r[6])

    def all_spendables(self, spendable_class, qualifier_sql=""):
        SQL = ("select tx_hash, tx_out_index, coin_value, script, block_index_available, "
               "does_seem_spent, block_index_spent from Spendable " + qualifier_sql)
        c1 = self._exec_sql(SQL)
        while 1:
            r = next(c1)
            yield self.spendable_for_row(r, spendable_class)

    def unspent_spendables(self, last_block, spendable_class, confirmations=0):
        # we fetch spendables "old enough"
        # we alternate between "biggest" and "smallest" spendables
        SQL = ("select tx_hash, tx_out_index, coin_value, script, block_index_available, "
               "does_seem_spent, block_index_spent from Spendable where "
               "block_index_available > 0 and does_seem_spent = 0 and block_index_spent = 0 "
               "%s order by coin_value %s")

        if confirmations > 0:
            prior_to_block = last_block + 1 - confirmations
            t1 = "and block_index_available <= %d " % prior_to_block
        else:
            t1 = ""

        c1 = self._exec_sql(SQL % (t1, "desc"))
        c2 = self._exec_sql(SQL % (t1, "asc"))

        seen = set()
        while 1:
            r = next(c2)
            s = self.spendable_for_row(r, spendable_class)
            name = (s.tx_hash, s.tx_out_index)
            if name not in seen:
                yield s
            seen.add(name)
            r = next(c1)
            s = self.spendable_for_row(r, spendable_class)
            name = (s.tx_hash, s.tx_out_index)
            if name not in seen:
                yield s
            seen.add(name)

    def unspent_spendable_count(self):
        SQL = ("select count(*) from Spendable where does_seem_spent = 0"
               " and block_index_available > 0 and block_index_spent = 0")
        c = self._exec_sql(SQL)
        r = c.fetchone()
        return r[0]

    def rewind_spendables(self, block_index):
        SQL1 = ("update Spendable set block_index_available = 0 where block_index_available > ?")
        self._exec_sql(SQL1, block_index)

        SQL2 = ("update Spendable set block_index_spent = 0 where block_index_spent > ?")
        self._exec_sql(SQL2, block_index)
