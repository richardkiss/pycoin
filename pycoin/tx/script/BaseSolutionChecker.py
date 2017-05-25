class TxContext(object):
    pass


class VMContext(object):
    pass


class SolutionChecker(object):
    @classmethod
    def check_solution(class_, tx_context, flags, traceback_f=None):
        """
        tx_context: information about the transaction that the VM may need
        flags: gives the VM hints about which additional constraints to check
        """
        raise NotImplemented()
