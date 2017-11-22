
DEFAULT_ARGS_ORDER = (
    'code', 'network_name', 'subnet_name',
    'tx', 'block',
    'magic_header', 'default_port', 'dns_bootstrap',
    'ui', 'extras'
)


class Network(object):
    def __init__(self, *args, **kwargs):
        for arg, name in zip(args, DEFAULT_ARGS_ORDER):
            kwargs[name] = arg
        for k, v in kwargs.items():
            if k not in DEFAULT_ARGS_ORDER:
                raise TypeError("unexpected argument %s" % k)
        for name in DEFAULT_ARGS_ORDER:
            setattr(self, name, kwargs.get(name, None))

    def __repr__(self):
        return "<Network %s %s>" % (self.network_name, self.subnet_name)
