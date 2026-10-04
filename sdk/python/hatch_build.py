"""Puts the rowfence command into the package (rowfence/_command) when building from the repository: authzlib,
every module of core/cli and Studio's page (cli/studio). A build from the sdist has it there already."""
import os
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CommandHook(BuildHookInterface):
    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        checkout = os.path.normpath(os.path.join(self.root, "..", "..", "core"))
        if not os.path.isdir(os.path.join(checkout, "authzlib")):
            return
        build_data["force_include"][os.path.join(checkout, "authzlib")] = "rowfence/_command/authzlib"
        cli = os.path.join(checkout, "cli")
        for name in sorted(os.listdir(cli)):
            if name.endswith(".py"):
                build_data["force_include"][os.path.join(cli, name)] = "rowfence/_command/cli/" + name
        build_data["force_include"][os.path.join(cli, "studio")] = "rowfence/_command/cli/studio"    # Studio's page
