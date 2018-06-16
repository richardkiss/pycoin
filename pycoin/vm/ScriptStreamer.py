from ..encoding.hexbytes import bytes_as_hex
from ..intbytes import indexbytes, int2byte


def make_const_handler(data):
    """
    Create a handler for a data opcode that returns a constant.
    """
    data = bytes_as_hex(data)

    def constant_data_opcode_handler(script, pc, verify_minimal_data=False):
        return pc+1, data
    return constant_data_opcode_handler


def make_sized_handler(size, const_values, non_minimal_data_handler):
    """
    Create a handler for a data opcode that returns literal data of a fixed size.
    """
    const_values = list(const_values)

    def constant_size_opcode_handler(script, pc, verify_minimal_data=False):
        pc += 1
        data = bytes_as_hex(script[pc:pc+size])
        if len(data) < size:
            return pc+1, None
        if verify_minimal_data and data in const_values:
            non_minimal_data_handler("not minimal push of %s" % repr(data))
        return pc+size, data
    return constant_size_opcode_handler


def make_variable_handler(dec_f, sized_values, min_size, non_minimal_data_handler):
    """
    Create a handler for a data opcode that returns literal data of a variable size
    that's fetched and decoded by the function dec_f.
    """
    sized_values = list(sized_values)

    def f(script, pc, verify_minimal_data=False):
        size, pc = dec_f(script, pc)
        data = bytes_as_hex(script[pc:pc+size])
        if len(data) < size:
            return pc+1, None
        if verify_minimal_data:
            if size in sized_values or size <= min_size:
                non_minimal_data_handler("not minimal push of data with size %d" % size)
        return pc+size, data
    return f


def make_sized_encoder(opcode_value):
    """
    Create an encoder that encodes the given opcode value as binary data
    and appends the given data.
    """
    opcode_bin = int2byte(opcode_value)

    def f(data):
        return opcode_bin + data
    return f


class ScriptStreamer(object):
    """
    This class manages encoding and decoding instructions and data from a script.

    Most instructions operate on existing stack data. Then there are some opcodes that
    push constant data onto the stack. These are data opcodes.
    There are three classes of data opcodes:
        * CONSTANT_OPCODE: opcodes that push a constant
        * SIZED_OPCODE: opcodes that push a constant number of subsequent bytes
        * VARIABLE_OPCODE: opcodes that push an encoding of the number of bytes, followed by those bytes

    This class is also aware of "minimal encoding", that is, encoding data using
    the shortest data sequence possible, and can verify that scripts use it.
    This gives a "canonical" version of solution scripts, which can be used to
    help reduce the impact of malleability.
    """
    def __init__(self, opcode_const_list, opcode_sized_list, opcode_variable_list,
                 opcode_lookup, non_minimal_data_handler):
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
            enc_f should have signature (bin_data) and return an integer (length)
            dec_f should have signature (bin_data) and return offset, data where
                offset is the integer count of bytes consumed and data the decoded result

        :param opcode_lookup: dictionary with entries "OPCODE_NAME" => byte
        :param non_minimal_data_handler: function called when data encoded non-minimally
        """

        # build encoders
        const_pairs = [(opcode_lookup.get(opcode), val) for opcode, val in opcode_const_list]
        self.const_encoder = {v: int2byte(k) for k, v in const_pairs}

        sized_pairs = [(opcode_lookup.get(opcode), size) for opcode, size in opcode_sized_list]
        self.sized_encoder = {v: make_sized_encoder(k) for k, v in sized_pairs}
        opcode_variable_list = sorted(opcode_variable_list, key=lambda o: o[0])
        self.variable_encoder = list(
            (max_size, opcode_lookup.get(opcode), enc_f)
            for opcode, max_size, enc_f, dec_f in opcode_variable_list)

        # build decoder

        self.decoder = {}

        # deal with variable data opcodes

        min_size = 0
        for o, max_size, enc_f, dec_f in opcode_variable_list:
            self.decoder[opcode_lookup.get(o)] = make_variable_handler(
                dec_f, self.sized_encoder.keys(), min_size, non_minimal_data_handler)
            min_size = max_size + 1

        # deal with sized data opcodes

        self.decoder.update(
            {o: make_sized_handler(
                v, self.const_encoder.keys(), non_minimal_data_handler) for o, v in sized_pairs})

        # deal with constant data opcodes

        self.decoder.update({o: make_const_handler(v) for o, v in const_pairs})

        self.data_opcodes = frozenset(self.decoder.keys())

    def get_opcode(self, script, pc, verify_minimal_data=False):
        """
        Step through the script, returning a tuple with the next opcode, the next
        piece of data (if the opcode represents data), the new PC, and a boolean indicated
        valid parsing.
        """
        opcode = indexbytes(script, pc)
        decoder = self.decoder.get(opcode)
        # lambda s, p, verify_minimal_data: (p+1, None))
        if decoder:
            pc, data = decoder(script, pc, verify_minimal_data=verify_minimal_data)
            is_ok = (data is not None)
        else:
            pc += 1
            data = None
            is_ok = True
        return opcode, data, pc, is_ok

    def compile_push_data(self, data):
        # return bytes that causes the given data to be pushed onto the stack
        if data in self.const_encoder:
            return self.const_encoder.get(data)
        size = len(data)
        if size in self.sized_encoder:
            return self.sized_encoder.get(size)(data)
        for max_size, opcode, enc_f in self.variable_encoder:
            if size <= max_size:
                break
        return int2byte(opcode) + enc_f(len(data)) + data
