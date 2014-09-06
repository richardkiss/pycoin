from threading import RLock

from pycoin.convention.tx_fee import TX_FEE_PER_THOUSAND_BYTES
from pycoin.tx.tx_utils import create_tx, sign_tx


DUST = 0

class SQLite3Wallet(object):

    def __init__(self, keychain, persistence, desired_spendable_count=None):
        self.keychain = keychain
        self.persistence = persistence
        self._desired_spendable_count = desired_spendable_count
        self._lock = RLock()

    def last_block_index(self):
        v = self.persistence.get_global("block_index")
        if v is None:
            v = -1
        return int(v)

    def set_last_block_index(self, index):
        self.persistence.set_global("block_index", index)

    def create_unsigned_send_tx(self, address, amount):
        total_input_value = 0
        estimated_fee = TX_FEE_PER_THOUSAND_BYTES
        with self._lock:
            confirmations = 7
            while confirmations > 0 and self.get_balance(confirmations=confirmations) < amount + estimated_fee:
                confirmations -= 1

            spendables = []
            for spendable in self.persistence.unspent_spendables(
                    self.last_block_index(), confirmations=1):
                spendables.append(spendable)
                total_input_value += spendable.coin_value
                if total_input_value >= amount + estimated_fee and len(spendables) > 1:
                    break
            if total_input_value < amount + estimated_fee:
                raise ValueError("insufficient funds: only %d available" % total_input_value)

            # mark the given spendables as "unconfirmed_spent"
            for spendable in spendables:
                spendable.does_seem_spent = True
                self.persistence.save_spendable(spendable)

            payables = [(address, amount)]
            change_amount = total_input_value - estimated_fee - amount
            if change_amount > DUST:
                change_address = self.keychain.get_change_address()
                payables.append(change_address)

            if self._desired_spendable_count is not None:
                if self.persistence.unspent_spendable_count() < self._desired_spendable_count:
                    desired_change_output_count = len(spendables) + 1
                    if change_amount > desired_change_output_count * DUST:
                        for i in range(desired_change_output_count):
                            change_address = self.keychain.get_change_address()
                            payables.append(change_address)

            tx = create_tx(spendables, payables, fee=estimated_fee)
            self.persistence.commit()
        return tx

    # for collecting spendables
    def got_mempool_tx_callback(self, tx):
        with self._lock:
            for tx_in in tx.txs_in:
                s = self.persistence.spendable_for_hash_index(tx_in.previous_hash, tx_in.previous_index)
                if s:
                    s.does_seem_spent = True
                    self.persistence.save_spendable(s)
            for spendable in tx.tx_outs_as_spendable():
                if self.keychain.is_spendable_interesting(spendable):
                    s = self.persistence.spendable_for_hash_index(tx_in.previous_hash, tx_in.previous_index)
                    self.persistence.save_spendable(spendable)

    def _process_confirmed_tx(self, tx, blockheader, block_index):
        for tx_in in tx.txs_in:
            spendable = self.persistence.spendable_for_hash_index(tx_in.previous_hash, tx_in.previous_index)
            if spendable:
                spendable.block_index_spent = block_index
                self.persistence.save_spendable(spendable)
        for spendable in tx.tx_outs_as_spendable():
            if self.keychain.is_spendable_interesting(spendable):
                spendable.block_index_available = block_index
                self.persistence.save_spendable(spendable)

    def _add_block(self, blockheader, block_index, txs):
        with self._lock:
            self.set_last_block_index(block_index)
            for tx in txs:
                self._process_confirmed_tx(tx, blockheader, block_index)

    def _rollback_block(self, blockheader, block_index):
        with self._lock:
            self.set_last_block_index(block_index-1)
            self.persistence.invalidate_block_index_for_wallet(block_index)

    def get_balance(self, confirmations=1):
        with self._lock:
            balance = 0
            for s in self.persistence.unspent_spendables(self.last_block_index(), confirmations=confirmations):
                # if it looks already spent, skip
                if s.does_seem_spent:
                    continue
                if confirmations > 0:
                    # if unconfirmed and we want confirmations, skip
                    if s.block_index_available is None:
                        continue
                    # if not enough confirmations have elapsed, skip
                    if self.last_block_index() - s.block_index_available + 1 < confirmations:
                        continue
                balance += s.coin_value
            return balance

    def got_ops_callback(self, ops):
        for op, blockheader, block_index, txs in ops:
            if op == 'add':
                self._add_block(blockheader, block_index, txs)
            elif op == 'remove':
                self._rollback_block(blockheader, block_index)
            else:
                raise Exception("unknown op: %s" % op)
