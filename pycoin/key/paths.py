import itertools


def path_iterator_for_path(path):
    """
    Return multiple paths
    examples:
      0/1H/0-4 => ['0/1H/0', '0/1H/1', '0/1H/2', '0/1H/3', '0/1H/4']
      0/2,5,9-11 => ['0/2', '0/5', '0/9', '0/10', '0/11']
      3H/2/5/15-20p => ['3H/2/5/15p', '3H/2/5/16p', '3H/2/5/17p', '3H/2/5/18p',
          '3H/2/5/19p', '3H/2/5/20p']
      5-6/7-8p,15/1-2 => ['5/7H/1', '5/7H/2', '5/8H/1', '5/8H/2',
         '5/15/1', '5/15/2', '6/7H/1', '6/7H/2', '6/8H/1', '6/8H/2', '6/15/1', '6/15/2']
    """

    def range_iterator(the_range):
        for r in the_range.split(","):
            is_hardened = r[-1] in "'pH"
            if is_hardened:
                r = r[:-1]
            hardened_char = "H" if is_hardened else ''
            if '-' in r:
                low, high = [int(x) for x in r.split("-", 1)]
                for t in range(low, high+1):
                    yield "%d%s" % (t, hardened_char)
            else:
                yield "%s%s" % (r, hardened_char)

    if len(path) == 0:
        yield path
        return
    components = path.split("/")
    iterators = [range_iterator(c) for c in components]
    for v in itertools.product(*iterators):
        yield '/'.join(v)
