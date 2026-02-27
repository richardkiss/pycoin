from pycoin import version
from urllib import request
from urllib.parse import urlencode  # noqa


PYCOIN_AGENT = 'pycoin/%s' % version


def urlopen(url, data=None):
    req = request.Request(url, data=data)
    req.add_header('User-agent', PYCOIN_AGENT)
    return request.urlopen(req)
