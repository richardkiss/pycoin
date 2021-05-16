from pycoin.encoding.hexbytes import b2h


class Contract(object):
    """
    A script that encumbers coins.
    """
    def __init__(self, script_info, network):
        self._script_info = script_info
        self._network = network

    def info(self):
        return self._script_info

    def hash160(self):
        """
        Return a 20-byte hash corresponding to this script (or None if not applicable).
        """
        return self._script_info.get("hash160")

    def address(self):
        """
        Return a string with the address for this script (or None if this script does
        have a corresponding address).
        """
        return self._network.address.for_script_info(self._script_info)

    def script(self):
        """
        Return a :class:`bytes <bytes>` with a binary image of the script.
        """
        return self._network.contract.for_info(self._script_info)

    def disassemble(self):
        """
        Return a text string of the disassembly of the script.
        """
        return self._network.script.disassemble(self.script())

    def ku_output(self):
        """
        Return a 20-byte hash corresponding to this script (or None if not applicable).
        """
        hash160 = self._script_info.get("hash160", None)
        if hash160:
            yield ("hash160", b2h(hash160), None)

        address = self.address()
        yield ("address", address, "%s address" % self._network.network_name)
        yield ("%s_address" % self._network.symbol, address, "legacy")

    def override_network(self, override_network):
        return override_network.contract.new(self.info())

    def __repr__(self):
        return "<%s>" % self.address()
