
from ...intbytes import byte_to_int, bytes_from_int

from . import ScriptError
from . import errno


def make_const_f(data):
    def constant_data_opcode_handler(script, pc, verify_minimal_data=False):
        return pc+1, data
    return constant_data_opcode_handler


def make_sized_f(size, const_values):
    const_values = list(const_values)

    def constant_size_opcode_handler(script, pc, verify_minimal_data=False):
        pc += 1
        data = script[pc:pc+size]
        if len(data) < size:
            raise ScriptError("unexpected end of data when literal expected", errno.BAD_OPCODE)
        if verify_minimal_data and data in const_values:
            raise ScriptError("not minimal push of %s" % repr(data), errno.MINIMALDATA)
        return pc+size, data
    return constant_size_opcode_handler


def make_variable_f(dec_f, sized_values):
    sized_values = list(sized_values)

    def f(script, pc, verify_minimal_data=False):
        size, pc = dec_f(script, pc)
        if verify_minimal_data and size in sized_values:
            raise ScriptError("not minimal push of data with size %d" % size, errno.MINIMALDATA)
        data = script[pc:pc+size]
        return pc+size, data
    return f


class DataCodec(object):
    """
    This class manages encoding and decoding data from a script.

    There are three classes of data opcodes:
        * CONSTANT_OPCODE: opcodes that push a constant
        * SIZED_OPCODE: opcodes that push a constant number of subsequent bytes
        * VARIABLE_OPCODE: opcodes that push a encoding of the number of bytes, followed by those bytes

    This class is also aware of "minimal encoding", that is, encoding data using
    the shortest data sequence possible.
    """
    def __init__(self, opcode_const_list, opcode_sized_list, opcode_variable_list,
                 opcode_lookup):
        """
        :param opcode_const_list: list of ("OPCODE_NAME", const_value) pairs, where
            OPCODE_NAME is the name of an opcode and const_value is the value to be pushed
            for that opcode
        :param opcode_sized_list: list of ("OPCODE_NAME", data_size) pairs, where
            OPCODE_NAME is the name of an opcode and data_size is the size
        :param opcode_variable_list: list of ("OPCODE_NAME", max_data_size, enc_f, dec_f)
            tuples where OPCODE_NAME is an opcode, max_data_size is the maximum amount of
            data that can be pushed by this opcode, enc_f is the encoder for the size of the data,
            dec_f is the decoder for the size of the data.
        :param opcode_lookup: dictionary with entries "OPCODE_NAME" => byte
        """
        self.const_decoder = {opcode_lookup.get(opcode): val for opcode, val in opcode_const_list}
        self.const_encoder = {v: bytes_from_int(k) for k, v in self.const_decoder.items()}
        self.sized_decoder = {opcode_lookup.get(opcode): size for opcode, size in opcode_sized_list}

        # BRAIN DAMAGE
        def make_sized_encoder(k):
            k_bin = bytes_from_int(k)
            def f(d):
                return k_bin + d
            return f

        self.sized_encoder = {v: make_sized_encoder(k) for k, v in self.sized_decoder.items()}
        self.variable_decoder = {
            opcode_lookup.get(opcode): dec_f for opcode, mds, enc_f, dec_f in opcode_variable_list}
        self.variable_encoder = sorted(
            (mds, opcode_lookup.get(opcode), enc_f) for opcode, mds, enc_f, dec_f in opcode_variable_list)

        self.decoder = {}
        self.decoder.update(
            {o: make_variable_f(dec_f, self.sized_encoder.keys()) for o, dec_f in self.variable_decoder.items()})
        self.decoder.update({o: make_sized_f(v, self.const_encoder.keys()) for o, v in self.sized_decoder.items()})
        self.decoder.update({o: make_const_f(v) for o, v in self.const_decoder.items()})

        self.push_opcodes = frozenset(self.decoder.keys())

    def check_script_push_only(self, script):
        pc = 0
        while pc < len(script):
            opcode, data, pc = self.get_opcode(script, pc)
            if opcode not in self.push_opcodes:
                raise ScriptError("signature has non-push opcodes", errno.SIG_PUSHONLY)

    def verify_minimal_data(self, opcode, data):
        script = self.bin_script([data])
        if byte_to_int(script[0]) != opcode:
            raise ScriptError("not minimal push of %s" % repr(data), errno.MINIMALDATA)

    def get_opcode(self, script, pc, verify_minimal_data=False):
        """
        Step through the script, returning a tuple with the next opcode, the next
        piece of data (if the opcode represents data), and the new PC.
        """
        if script == 'zv\xa9\x14[dbGTTq\x0f<"\xf5\xfd\xf0\xb4\x07\x04\xc9/%\xc3\x88\xadQLG0D\x02 g(\x8e\xa5\n\xa7\x99T:So\xf90o\x8e\x1c\xba\x05\xb9\xc6\xb1\tQ\x17[\x92O\x96s%U\xed\x02 &\xd7\xb5&_8\xd2\x15AQ\x9eJ\x1eU\x04M[\x9e\x17\xe1\\\xdb\xaf)\xae7\x92\xe9\x9e\x88>z\x01' and pc == 26:
            import pdb
            # pdb.set_trace()
        opcode = byte_to_int(script[pc])
        f = self.decoder.get(opcode, lambda s, p, verify_minimal_data: (p+1, None))
        pc, data = f(script, pc, verify_minimal_data=verify_minimal_data)
        return opcode, data, pc

    def compile_push(self, data):
        # return bytes that causes the given data to be pushed onto the stack
        if data in self.const_encoder:
            return self.const_encoder.get(data)
        size = len(data)
        if size in self.sized_encoder:
            return self.sized_encoder.get(size)(data)
        for mds, opcode, enc_f in self.variable_encoder:
            if size <= mds:
                break
        return opcode + enc_f(data)

    def write_push_data(self, data_list, f):
        # return bytes that causes the given data to be pushed onto the stack
        for t in data_list:
            f.write(self.compile_push(t))

    def data_list_to_script(self, data_list):
        import pdb
        if data_list == ['', '', '0E\x02 z\xac\xee\x82\x0e\x08\xb0\xb1t\xe2H\xab\xd8\xd7\xa3N\xd6;]\xa3\xab\xed\xb9\x994\xdf\x9f\xdd\xd6\\\x05\xc4\x02!\x00\xdf\xe8x\x96\xab^\xe3\xdfGl&U\xf9\xfb\xe5\xbd\x08\x9d\xcc\xbe\xf3\xe4\xea\x05\xb5\xd1!\x16\x9f\xe7\xf5\xf4\x01', '0E\x02!\x00\xf6d\x9b\x0e\xdd\xfd\xfdJ\xd5T&f3\x85\t\rQ\xee\x86\xc3H\x1b\xdck\x0c\x18\xeal\x0e\xce,\x0b\x02 V\x1c1[\x07\xcf\xfao}\xd9\xdf\x96\xdb\xae\x92\x00\xc2\xde\xe0\x9b\xf9<\xc3\\\xa0^l\xdfa3@\xaa\x01']:
            pass
            # pdb.set_trace()
        return b''.join(self.compile_push(d) for d in data_list)

    bin_script = data_list_to_script
