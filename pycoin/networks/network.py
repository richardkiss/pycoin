from collections import namedtuple

Network = namedtuple(
    'Network', (
        'code', 'network_name', 'subnet_name',
        'wif', 'address', 'pay_to_script', 'prv32', 'pub32',
        'address_wit', 'pay_to_script_wit',
        'tx', 'block',
        'magic_header', 'default_port', 'dns_bootstrap'
    )
)
