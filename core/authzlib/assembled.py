"""The compiler, its parts stacked: authzlib.Compiler, imported when first asked for (see __init__.py)."""

from .devtools import DevMixin
from .output import OutputMixin
from .testing import TestMixin


class Compiler(TestMixin, DevMixin, OutputMixin):
    """A policy compiled: each part of the output is one of its bases (OutputMixin assembles them)."""
