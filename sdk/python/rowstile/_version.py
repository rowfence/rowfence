"""The version, read from the compiler's (core/authzlib/__init__.py, the one place it is written)."""
import os
import re

_here = os.path.dirname(os.path.abspath(__file__))
_candidates = (os.path.join(_here, "_command", "authzlib", "__init__.py"),
               os.path.join(_here, "..", "..", "..", "core", "authzlib", "__init__.py"))
__version__ = "0.0.0"
for _path in _candidates:
    if os.path.isfile(_path):
        with open(_path, encoding="utf-8") as _fh:
            _m = re.search(r'^__version__ = "([^"]+)"', _fh.read(), re.M)
        if _m:
            __version__ = _m.group(1)
            break
