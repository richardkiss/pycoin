class ScriptError(Exception):
    def error_code(self):
        if len(self.args) > 1:
            return self.args[1]
        return None
