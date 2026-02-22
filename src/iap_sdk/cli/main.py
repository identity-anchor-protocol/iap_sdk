"""Command-line interface for iap-agent."""

from __future__ import annotations

import argparse
import json
import sys
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as pkg_version
from typing import Sequence

from iap_sdk.certificates import PROTOCOL_VERSION
from iap_sdk.cli.amcs import AMCSError, get_amcs_root
from iap_sdk.cli.config import CLIConfig, ConfigError, load_cli_config
from iap_sdk.cli.identity import IdentityError, load_identity, load_or_create_identity


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

    init = sub.add_parser("init", help="Initialize or load local agent identity")
    init.add_argument(
        "--identity-file",
        default=None,
        help="Path to local identity file (default: ~/.iap_agent/identity/ed25519.json)",
    )
    init.add_argument(
        "--show-public",
        action="store_true",
        help="Print only public fields (agent_id + public_key_b64)",
    )
    init.add_argument("--json", action="store_true", help="Print identity details as JSON")
    sub.add_parser("verify", help="Verify certificate offline (coming soon)")

    amcs = sub.add_parser("amcs", help="Local AMCS operations")
    amcs_sub = amcs.add_subparsers(dest="amcs_command", required=True)
    amcs_root = amcs_sub.add_parser("root", help="Read memory root and sequence from local AMCS DB")
    amcs_root.add_argument("--amcs-db", default=None, help="Path to local AMCS SQLite DB")
    amcs_root.add_argument("--agent-id", default=None, help="Agent id to query in AMCS")
    amcs_root.add_argument(
        "--identity-file",
        default=None,
        help="Path to local identity file when deriving agent_id fallback",
    )
    amcs_root.add_argument("--json", action="store_true", help="Print AMCS root details as JSON")

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


def _run_init(*, args, stdout, stderr) -> int:
    try:
        identity, created, identity_path = load_or_create_identity(args.identity_file)
    except IdentityError as exc:
        print(f"identity error: {exc}", file=stderr)
        return 1

    payload = {
        "identity_path": str(identity_path),
        "created": created,
        "agent_id": identity.agent_id,
        "public_key_b64": identity.public_key_b64,
    }
    if not args.show_public:
        payload["private_key_b64"] = identity.private_key_b64

    if args.json:
        print(json.dumps(payload, sort_keys=True), file=stdout)
        return 0

    print(f"identity_path: {payload['identity_path']}", file=stdout)
    print(f"created: {str(payload['created']).lower()}", file=stdout)
    print(f"agent_id: {payload['agent_id']}", file=stdout)
    print(f"public_key_b64: {payload['public_key_b64']}", file=stdout)
    if not args.show_public:
        print("private_key_b64: [hidden in non-json output]", file=stdout)
    return 0


def _run_amcs_root(*, args, config: CLIConfig, stdout, stderr) -> int:
    amcs_db_path = args.amcs_db or config.amcs_db_path

    agent_id = args.agent_id
    if not agent_id:
        try:
            identity, _ = load_identity(args.identity_file)
            agent_id = identity.agent_id
        except IdentityError as exc:
            print(f"identity error: {exc}", file=stderr)
            return 1

    try:
        result = get_amcs_root(amcs_db_path=amcs_db_path, agent_id=agent_id)
    except AMCSError as exc:
        print(f"amcs error: {exc}", file=stderr)
        return 1

    payload = {
        "agent_id": result.agent_id,
        "amcs_db_path": result.amcs_db_path,
        "memory_root": result.memory_root,
        "sequence": result.sequence,
    }
    if args.json:
        print(json.dumps(payload, sort_keys=True), file=stdout)
        return 0

    print(f"agent_id: {payload['agent_id']}", file=stdout)
    print(f"amcs_db_path: {payload['amcs_db_path']}", file=stdout)
    print(f"sequence: {payload['sequence']}", file=stdout)
    print(f"memory_root: {payload['memory_root']}", file=stdout)
    return 0


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
        return _run_init(args=args, stdout=stdout, stderr=stderr)

    if args.command == "verify":
        return _coming_soon(path="verify", stdout=stdout)

    if args.command == "amcs":
        if args.amcs_command == "root":
            return _run_amcs_root(args=args, config=config, stdout=stdout, stderr=stderr)
        return _coming_soon(path=f"amcs {args.amcs_command}", stdout=stdout)

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
