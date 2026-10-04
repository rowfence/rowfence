"""The rowfence command, as the `rowfence` script and `python -m rowfence` run it.

The command is standard library only. In an installed package it is in rowfence/_command; in a checkout of the
repository (an editable install), it is core/cli beside sdk/python.
"""
import importlib
import os
import sys
from collections.abc import Sequence


def command_dir() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    bundled = os.path.join(here, "_command", "cli")
    if os.path.isfile(os.path.join(bundled, "rowfence_cli.py")):
        return bundled
    checkout = os.path.normpath(os.path.join(here, "..", "..", "..", "core", "cli"))
    if os.path.isfile(os.path.join(checkout, "rowfence_cli.py")):
        return checkout
    raise SystemExit("rowfence: the command is missing from this installation (rowfence/_command); reinstall rowfence")


def main(argv: Sequence[str] | None = None) -> None:
    sys.path.insert(0, command_dir())
    rowfence_cli = importlib.import_module("rowfence_cli")    # it puts authzlib, beside it, on the path too
    rowfence_cli.main(list(sys.argv[1:] if argv is None else argv))


if __name__ == "__main__":
    main()
