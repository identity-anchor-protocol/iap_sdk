#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import shlex
from pathlib import Path

from iap_sdk.cli.main import _build_parser


def _extract_iap_commands(text: str) -> list[str]:
    pattern = re.compile(r"```bash\s*(.*?)```", re.DOTALL | re.IGNORECASE)
    commands: list[str] = []
    for block in pattern.findall(text):
        for line in block.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith("iap-agent "):
                commands.append(stripped)
    return commands


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--paths",
        nargs="+",
        default=["README.md", "docs/*.md"],
        help="Markdown file globs to validate",
    )
    args = parser.parse_args()

    markdown_files: list[Path] = []
    for raw in args.paths:
        if any(char in raw for char in "*?[]"):
            markdown_files.extend(sorted(Path(".").glob(raw)))
        else:
            markdown_files.append(Path(raw))

    cli_parser = _build_parser()
    errors: list[str] = []
    checked = 0

    for path in markdown_files:
        if not path.exists():
            errors.append(f"{path}: not found")
            continue
        commands = _extract_iap_commands(path.read_text(encoding="utf-8"))
        for command in commands:
            checked += 1
            argv = shlex.split(command)
            if argv and argv[0] == "iap-agent":
                argv = argv[1:]
            if any(token.startswith("<") and token.endswith(">") for token in argv):
                continue
            try:
                cli_parser.parse_args(argv)
            except SystemExit:
                errors.append(f"{path}: invalid command snippet: {command}")

    if errors:
        print("doc command validation failed:")
        for item in errors:
            print(f"- {item}")
        return 1

    print(f"doc command validation passed ({checked} command snippets)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
