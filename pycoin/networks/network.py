from collections import namedtuple

Network = namedtuple(
    'Network', (
        'code', 'network_name', 'subnet_name',
        'wif', 'address', 'pay_to_script', 'prv32', 'pub32',
        'tx', 'block',
        'magic_header', 'default_port', 'dns_bootstrap'
    )
)
