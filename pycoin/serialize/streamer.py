
import io


class Streamer(object):
    def __init__(self):
        self.parse_lookup = {}
        self.stream_lookup = {}

    def register_functions(self, lookup):
        for c, v in lookup:
            parse_f, stream_f = v
            self.parse_lookup[c] = parse_f
            self.stream_lookup[c] = stream_f

    def register_array_count_parse(self, array_count_parse_f):
        self.array_count_parse_f = array_count_parse_f

    def parse_struct(self, fmt, f):
        items = []
        i = 0
        while i < len(fmt):
            c = fmt[i]
            if c == "[":
                end = fmt.find("]", i)
                if end < 0:
                    raise ValueError("no closing ] character")
                subfmt = fmt[i+1:end]
                count = self.array_count_parse_f(f)
                array = []
                for j in range(count):
                    if len(subfmt) == 1:
                        array.append(self.parse_struct(subfmt, f)[0])
                    else:
                        array.append(self.parse_struct(subfmt, f))
                items.append(tuple(array))
                i = end
            else:
                items.append(self.parse_lookup[c](f))
            i += 1
        return tuple(items)

    def parse_as_dict(self, attribute_list, pack_list, f):
        return dict(list(zip(attribute_list, self.parse_struct(pack_list, f))))

    def stream_struct(self, fmt, f, *args):
        for c, v in zip(fmt, args):
            self.stream_lookup[c](f, v)

    def unpack_struct(self, fmt, b):
        return self.parse_struct(fmt, io.BytesIO(b))

    def pack_struct(self, fmt, *args):
        b = io.BytesIO()
        self.stream_struct(fmt, b, *args)
        return b.getvalue()
