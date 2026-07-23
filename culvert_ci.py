#  Project:      culvert
#  File:         culvert_ci.py
#  Purpose:      CI-only entry point for hyperi-ci's deployment-artefact stage
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""CI entry point for hyperi-ci's deployment-artefact generation.

hyperi-ci's Build job runs ``<cli> generate-artefacts --output-dir DIR``
against every project whose ``pyproject.toml`` depends on scalo, expecting
a scalo ServiceApp CLI that emits a container manifest. culvert is NOT a
ServiceApp - it is a VPN container built from its own Dockerfile
(``container: mode: custom``) and it ships its deployment artefacts
pre-generated under ``deploy/`` (see ``scripts/generate-deploy-artefacts.py``,
the authoritative emitter). So there is nothing for the ServiceApp generator
to produce here.

This module satisfies the CLI contract that step requires: it accepts the
``generate-artefacts`` subcommand, ensures the output directory exists, and
exits 0 - the honest "custom container, no ServiceApp manifest to emit"
outcome. custom-mode container builds read the repo Dockerfile, not this
step's output, so nothing downstream depends on it.

Not shipped in the image (the container installs only the pinned runtime
deps); it exists purely so ``uv run culvert`` resolves during CI.
"""

import argparse
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    """Handle the hyperi-ci generate-artefacts contract; exit 0."""
    parser = argparse.ArgumentParser(prog="culvert")
    subparsers = parser.add_subparsers(dest="command")

    gen = subparsers.add_parser(
        "generate-artefacts",
        help="No-op for culvert: custom-mode container, artefacts committed",
    )
    gen.add_argument("--output-dir", default="ci-tmp")

    args, _ = parser.parse_known_args(argv)

    if args.command == "generate-artefacts":
        Path(args.output_dir).mkdir(parents=True, exist_ok=True)
        print(
            "culvert: custom-mode container - no ServiceApp manifest to emit "
            "(deployment artefacts are committed under deploy/)."
        )
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
