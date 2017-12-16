import unittest

from pycoin.blockchain.ChainFinder import ChainFinder


class BHO(object):
    def __init__(self, h, previous_block_hash=None, difficulty=10):
        self.h = h
        if previous_block_hash is None:
            previous_block_hash = h-1
        self.previous_block_hash = previous_block_hash
        self.difficulty = difficulty

    def hash(self):
        return self.h

    def __repr__(self):
        return "<BHO: id:%s parent:%s difficulty:%s>" % \
            (self.h, self.previous_block_hash, self.difficulty)


def do_scramble(items, tfb, dbt):
    import itertools
    for c in itertools.permutations(items):
        cf = ChainFinder()
        load_items(cf, c)
        assert cf.trees_from_bottom == tfb
        assert cf.descendents_by_top == dbt
        cf = ChainFinder()
        for b in c:
            load_items(cf, [b])
        assert cf.trees_from_bottom == tfb
        assert cf.descendents_by_top == dbt


def load_items(cf, bhos):
    return cf.load_nodes((bh.h, bh.previous_block_hash) for bh in bhos)


class ChainFinderTestCase(unittest.TestCase):

    def test_basics(self):
        cf = ChainFinder()
        assert cf.trees_from_bottom == {}
        assert cf.descendents_by_top == {}
        ITEMS = [BHO(i) for i in range(6)]

        load_items(cf, [ITEMS[0]])
        assert cf.trees_from_bottom == {0: [0, -1]}
        assert cf.descendents_by_top == {-1: {0}}

        load_items(cf, [ITEMS[1]])
        assert cf.trees_from_bottom == {1: [1, 0, -1]}
        assert cf.descendents_by_top == {-1: {1}}

        load_items(cf, ITEMS[0:2])
        assert cf.trees_from_bottom == {1: [1, 0, -1]}
        assert cf.descendents_by_top == {-1: {1}}

        load_items(cf, [ITEMS[4]])
        assert cf.trees_from_bottom == {1: [1, 0, -1], 4: [4, 3]}
        assert cf.descendents_by_top == {-1: {1}, 3: {4}}

        load_items(cf, [ITEMS[3]])
        assert cf.trees_from_bottom == {1: [1, 0, -1], 4: [4, 3, 2]}
        assert cf.descendents_by_top == {-1: {1}, 2: {4}}

        load_items(cf, [ITEMS[5]])
        assert cf.trees_from_bottom == {1: [1, 0, -1], 5: [5, 4, 3, 2]}
        assert cf.descendents_by_top == {-1: {1}, 2: {5}}

        load_items(cf, [ITEMS[2]])
        assert cf.trees_from_bottom == {5: [5, 4, 3, 2, 1, 0, -1]}
        assert cf.descendents_by_top == {-1: {5}}

        do_scramble(ITEMS, cf.trees_from_bottom, cf.descendents_by_top)

    def test_branch(self):
        cf = ChainFinder()
        assert cf.trees_from_bottom == {}
        assert cf.descendents_by_top == {}
        ITEMS = [BHO(i) for i in range(7)]
        B301 = BHO(301, 3, 10)
        B302, B303, B304 = [BHO(i) for i in range(302, 305)]

        load_items(cf, [B302])
        assert cf.trees_from_bottom == {302: [302, 301]}
        assert cf.descendents_by_top == {301: {302}}

        load_items(cf, [B304])
        assert cf.trees_from_bottom == {302: [302, 301], 304: [304, 303]}
        assert cf.descendents_by_top == {301: {302}, 303: {304}}

        load_items(cf, [B303])
        assert cf.trees_from_bottom == {304: [304, 303, 302, 301]}
        assert cf.descendents_by_top == {301: {304}}

        load_items(cf, ITEMS)
        assert cf.trees_from_bottom == {
            6: [6, 5, 4, 3, 2, 1, 0, -1],
            304: [304, 303, 302, 301]
        }
        assert cf.descendents_by_top == {-1: {6}, 301: {304}}

        load_items(cf, [B301])
        assert cf.trees_from_bottom == {
            6: [6, 5, 4, 3, 2, 1, 0, -1],
            304: [304, 303, 302, 301, 3, 2, 1, 0, -1]
        }
        assert cf.descendents_by_top == {-1: {6, 304}}

    def test_0123(self):
        I0 = BHO(0)
        I1 = BHO(1)
        I2 = BHO(2)
        I3 = BHO(3, 1)
        cf = ChainFinder()
        load_items(cf, [I0, I2, I3, I1])
        assert cf.trees_from_bottom == {2: [2, 1, 0, -1], 3: [3, 1, 0, -1]}
        assert cf.descendents_by_top == {-1: {2, 3}}

    def test_all_orphans(self):
        I1 = BHO(1)
        I2 = BHO(2)
        I3 = BHO(3)
        cf = ChainFinder()
        load_items(cf, [I2, I3, I1])
        assert cf.trees_from_bottom == {3: [3, 2, 1, 0]}
        assert cf.descendents_by_top == {0: {3}}

    def test_scramble(self):
        ITEMS = [BHO(i, (i-1)//2, 10) for i in range(7)]
        tfb = {
            3: [3, 1, 0, -1],
            4: [4, 1, 0, -1],
            5: [5, 2, 0, -1],
            6: [6, 2, 0, -1]
        }
        dbt = {-1: {3, 4, 5, 6}}
        do_scramble(ITEMS, tfb, dbt)

    def test_branch_switch(self):
        cf = ChainFinder()
        assert cf.trees_from_bottom == {}
        assert cf.descendents_by_top == {}
        ITEMS = [BHO(i) for i in range(4)]
        B201 = BHO(201, 2, 10)
        B202, B203, B204 = [BHO(i) for i in range(202, 205)]

        items = ITEMS + [B201, B202, B203, B204]
        tfb = {204: [204, 203, 202, 201, 2, 1, 0, -1], 3: [3, 2, 1, 0, -1]}
        dbt = {-1: {3, 204}}
        do_scramble(items, tfb, dbt)

    def test_longest_chain_endpoint(self):
        cf = ChainFinder()
        ITEMS = [BHO(i) for i in range(5)]
        B201 = BHO(201, 2, 110)
        B202, B203, B204 = [BHO(i) for i in range(202, 205)]

        def node_weight_f(h):
            if h == -1:
                return 0
            if h == 201:
                return 110
            return 10

        items = ITEMS + [B201, B202, B203, B204]
        load_items(cf, items)
        # assert cf.difficulty(0, node_weight_f) == 10
        # assert cf.difficulty(1, node_weight_f) == 20
        # assert cf.difficulty(2, node_weight_f) == 30
        # assert cf.difficulty(3, node_weight_f) == 40
        # assert cf.difficulty(4, node_weight_f) == 50
        # assert cf.difficulty(201, node_weight_f) == 140
        # assert cf.difficulty(202, node_weight_f) == 150

    def test_find_ancestral_path(self):

        ITEMS = [BHO(i) for i in range(5)]
        B201 = BHO(201, 2, 110)
        B202, B203, B204 = [BHO(i) for i in range(202, 205)]

        cf = ChainFinder()
        items = ITEMS + [B202, B203, B204]
        load_items(cf, items)

        load_items(cf, [B201])

        old_chain_endpoint, new_chain_endpoint = 4, 204

        old_subpath, new_subpath = cf.find_ancestral_path(old_chain_endpoint, new_chain_endpoint)
        assert old_subpath == [4, 3, 2]
        assert new_subpath == [204, 203, 202, 201, 2]

    def test_large(self):
        ITEMS = [BHO(i) for i in range(10000)]
        cf = ChainFinder()
        load_items(cf, ITEMS)
        old_subpath, new_subpath = cf.find_ancestral_path(5000, 9000)
