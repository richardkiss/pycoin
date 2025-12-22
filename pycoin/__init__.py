version = "unknown"

try:
    from importlib.metadata import version as get_version, PackageNotFoundError

    try:
        version = get_version("pycoin")
    except PackageNotFoundError:
        pass
except ImportError:
    # importlib.metadata not available (Python < 3.8)
    try:
        from pkg_resources import get_distribution, DistributionNotFound

        try:
            version = get_distribution(__name__).version
        except DistributionNotFound:
            pass
    except ImportError:
        # pkg_resources not available
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
