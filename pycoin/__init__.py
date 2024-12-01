version = "unknown"

try:
    from pkg_resources import get_distribution

    version = get_distribution(__name__).version
except ImportError:
    try:
        from importlib import metadata

        version = metadata.version("pycoin")
    except Exception:
        pass
except Exception:
    pass

__title__ = "pycoin"
__author__ = "Richard Kiss"
__version__ = version
__license__ = "MIT"
__copyright__ = "Copyright 2018 Richard Kiss"

"""
:copyright: (c) 2018 by Richard Kiss
:license: MIT, see LICENSE for more details.
"""
