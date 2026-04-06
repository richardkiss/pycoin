from __future__ import annotations

from pycoin import version

from typing import Any
from urllib import request
from urllib.parse import urlencode  # noqa


PYCOIN_AGENT = "pycoin/%s" % version


def urlopen(url: str, data: bytes | None = None) -> Any:
    req = request.Request(url, data=data)
    req.add_header("User-agent", PYCOIN_AGENT)
    return request.urlopen(req)
