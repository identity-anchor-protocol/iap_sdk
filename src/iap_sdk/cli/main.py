"""Command-line interface for iap-agent."""

from __future__ import annotations

import argparse
import json
import sys
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as pkg_version
from typing import Sequence

from iap_sdk.certificates import PROTOCOL_VERSION
from iap_sdk.cli.config import CLIConfig, ConfigError, load_cli_config


def _sdk_version() -> str:
    try:
        return pkg_version("iap-sdk")
    except PackageNotFoundError:
        return "0.0.0+local"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="iap-agent")
    parser.add_argument(
        "--config",
        default=None,
        help="Path to CLI config TOML (default: ~/.iap_agent/config.toml)",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    version = sub.add_parser("version", help="Show CLI and protocol version")
    version.add_argument("--json", action="store_true", help="Print version details as JSON")

    sub.add_parser("init", help="Initialize local agent identity (coming soon)")
    sub.add_parser("verify", help="Verify certificate offline (coming soon)")

    anchor = sub.add_parser("anchor", help="Identity-anchor operations")
    anchor_sub = anchor.add_subparsers(dest="anchor_command", required=True)
    anchor_sub.add_parser("issue", help="Issue identity anchor (coming soon)")

    continuity = sub.add_parser("continuity", help="Continuity operations")
    continuity_sub = continuity.add_subparsers(dest="continuity_command", required=True)
    continuity_sub.add_parser("request", help="Submit continuity request (coming soon)")
    continuity_sub.add_parser("pay", help="Show/open payment instructions (coming soon)")
    continuity_sub.add_parser("wait", help="Wait for certification (coming soon)")
    continuity_sub.add_parser("cert", help="Fetch issued certificate (coming soon)")

    flow = sub.add_parser("flow", help="High-level guided flows")
    flow_sub = flow.add_subparsers(dest="flow_command", required=True)
    flow_sub.add_parser("run", help="Run full end-to-end flow (coming soon)")

    return parser


def _emit_beta_warning(config: CLIConfig, command: str, stderr) -> None:
    if command == "version":
        return
    if not config.beta_mode:
        return
    print(
        "[beta] iap-agent is in beta mode; commands and outputs may change.",
        file=stderr,
    )


def _run_version(*, config: CLIConfig, as_json: bool, stdout) -> int:
    payload = {
        "cli": "iap-agent",
        "sdk_version": _sdk_version(),
        "protocol_version": PROTOCOL_VERSION,
        "maturity_level": config.maturity_level,
        "beta_mode": config.beta_mode,
        "default_registry_base": config.registry_base,
    }
    if as_json:
        print(json.dumps(payload, sort_keys=True), file=stdout)
    else:
        beta_mode_str = str(payload["beta_mode"]).lower()
        print(f"iap-agent {payload['sdk_version']}", file=stdout)
        print(f"protocol: {payload['protocol_version']}", file=stdout)
        print(
            f"maturity: {payload['maturity_level']} (beta_mode={beta_mode_str})",
            file=stdout,
        )
        print(f"default registry: {payload['default_registry_base']}", file=stdout)
    return 0


def _coming_soon(*, path: str, stdout) -> int:
    print(f"{path}: coming soon", file=stdout)
    return 2


def main(argv: Sequence[str] | None = None, *, stdout=sys.stdout, stderr=sys.stderr) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        config = load_cli_config(args.config)
    except ConfigError as exc:
        print(f"config error: {exc}", file=stderr)
        return 1

    _emit_beta_warning(config, args.command, stderr)

    if args.command == "version":
        return _run_version(config=config, as_json=args.json, stdout=stdout)

    if args.command == "init":
        return _coming_soon(path="init", stdout=stdout)

    if args.command == "verify":
        return _coming_soon(path="verify", stdout=stdout)

    if args.command == "anchor":
        return _coming_soon(path=f"anchor {args.anchor_command}", stdout=stdout)

    if args.command == "continuity":
        return _coming_soon(path=f"continuity {args.continuity_command}", stdout=stdout)

    if args.command == "flow":
        return _coming_soon(path=f"flow {args.flow_command}", stdout=stdout)

    print("unknown command", file=stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
