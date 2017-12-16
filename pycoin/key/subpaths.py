import itertools


def subpaths_for_path_range(path_range, hardening_chars="'pH"):
    """
    Return an iterator of paths

        # examples:
        #   0/1H/0-4 => ['0/1H/0', '0/1H/1', '0/1H/2', '0/1H/3', '0/1H/4']
        #   0/2,5,9-11 => ['0/2', '0/5', '0/9', '0/10', '0/11']
        #   3H/2/5/15-20p => ['3H/2/5/15p', '3H/2/5/16p', '3H/2/5/17p', '3H/2/5/18p',
        #          '3H/2/5/19p', '3H/2/5/20p']
        #   5-6/7-8p,15/1-2 => ['5/7H/1', '5/7H/2', '5/8H/1', '5/8H/2',
        #         '5/15/1', '5/15/2', '6/7H/1', '6/7H/2', '6/8H/1', '6/8H/2', '6/15/1', '6/15/2']
    """
    if path_range == '':
        yield ''
        return

    def range_iterator(the_range):
        for r in the_range.split(","):
            is_hardened = r[-1] in hardening_chars
            hardened_char = hardening_chars[-1] if is_hardened else ''
            if is_hardened:
                r = r[:-1]
            if '-' in r:
                low, high = [int(x) for x in r.split("-", 1)]
                for t in range(low, high+1):
                    yield "%d%s" % (t, hardened_char)
            else:
                yield "%s%s" % (r, hardened_char)

    components = path_range.split("/")
    iterators = [range_iterator(c) for c in components]
    for v in itertools.product(*iterators):
        yield '/'.join(v)


"""
The MIT License (MIT)

Copyright (c) 2013 by Richard Kiss

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""
