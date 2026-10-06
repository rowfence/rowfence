"""authzlib: compile a .authz policy file into PostgreSQL (views, closure tables,
triggers, row-level security policies and an API for app code)."""

from .devtools import DevMixin
from .output import OutputMixin
from .parse import Loc, PolicyError, parse_policy
from .testing import TestMixin


class Compiler(TestMixin, DevMixin, OutputMixin):
    """A policy compiled: each part of the output is one of its bases (OutputMixin assembles them)."""


# set with packaging/version.py (the packages copy it); authz.policy_versions records it on each apply
__version__ = "0.1.0-alpha.5"


def _build() -> str:
    """The version apply records and trusts: a release's own, and for a build of the next one (X.Y.Z-dev)
    the version with a hash of the compiler's sources, since two such builds may make different SQL."""
    if not __version__.endswith("-dev"):
        return __version__
    import hashlib
    import os

    here, h = os.path.dirname(os.path.abspath(__file__)), hashlib.sha256()
    for name in sorted(os.listdir(here)):
        if name.endswith(".py"):
            with open(os.path.join(here, name), "rb") as fh:
                h.update(name.encode() + b"\0" + fh.read().replace(b"\r\n", b"\n") + b"\0")
    return f"{__version__}+{h.hexdigest()[:12]}"


BUILD = _build()

__all__ = ["BUILD", "Compiler", "Loc", "PolicyError", "__version__", "parse_policy"]
