#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import io
import re
import shlex
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from iap_sdk.cli.main import _build_parser  # noqa: E402


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
                with contextlib.redirect_stdout(io.StringIO()):
                    with contextlib.redirect_stderr(io.StringIO()):
                        cli_parser.parse_args(argv)
            except SystemExit as exc:
                if exc.code not in (0, None):
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
