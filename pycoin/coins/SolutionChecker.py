
class ScriptError(Exception):
    def error_code(self):
        if len(self.args) > 1:
            return self.args[1]
        return None


class SolutionChecker(object):

    ScriptError = ScriptError

    def __init__(self, *args, **kwargs):
        raise

    def check_solution(self, tx_context, traceback_f=None, *args, **kwargs):
        """
        tx_context: information about the transaction that the VM may need
        traceback_f: a function invoked on occasion to check intermediate state
        """
        raise NotImplemented()
