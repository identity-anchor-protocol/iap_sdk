"""Command-line interface for iap-agent."""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import sys
import time
import webbrowser
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as pkg_version
from pathlib import Path
from types import SimpleNamespace
from typing import Sequence
from uuid import uuid4

from iap_sdk.certificates import PROTOCOL_VERSION
from iap_sdk.cli.amcs import AMCSError, append_files_to_amcs, get_amcs_root
from iap_sdk.cli.config import CLIConfig, ConfigError, load_cli_config, save_cli_setting
from iap_sdk.cli.identity import (
    DEFAULT_IDENTITY_PATH,
    IdentityError,
    load_identity,
    load_or_create_identity,
)
from iap_sdk.cli.sessions import SessionError, save_session_record
from iap_sdk.cli.tracking import (
    append_tracking_events,
    build_file_record,
    collect_tracked_files,
    ensure_tracking_config,
    load_track_config,
)
from iap_sdk.client import RegistryClient
from iap_sdk.errors import RegistryRequestError, RegistryUnavailableError, SDKTimeoutError
from iap_sdk.manifest import build_identity_manifest
from iap_sdk.requests import (
    build_continuity_request,
    build_identity_anchor_request,
    sign_continuity_request,
    sign_identity_anchor_request,
)
from iap_sdk.verify import verify_certificate_file

EXIT_SUCCESS = 0
EXIT_VALIDATION_ERROR = 1
EXIT_NETWORK_ERROR = 2
EXIT_TIMEOUT = 3
EXIT_VERIFICATION_FAILED = 4
LOCAL_STATE_SCHEMA_VERSION = 1
LOCAL_META_SCHEMA_VERSION = 1

_SENSITIVE_FIELDS = (
    "private_key_b64",
    "registry_signing_key_b64",
    "webhook_secret",
    "lnbits_admin_key",
    "lnbits_invoice_read_key",
    "stripe_api_key",
    "stripe_webhook_secret",
    "secret",
    "token",
    "authorization",
    "api_key",
)


def _sdk_version() -> str:
    try:
        return pkg_version("iap-agent")
    except PackageNotFoundError:
        try:
            return pkg_version("iap-sdk")
        except PackageNotFoundError:
            return "0.0.0+local"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="iap")
    parser.add_argument(
        "--version",
        action="version",
        version=f"iap-agent {_sdk_version()}",
    )
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
        "--project-local",
        action="store_true",
        help="Store identity under ./.iap/identity/ed25519.json for this project",
    )
    init.add_argument(
        "--show-public",
        action="store_true",
        help="Print only public fields (agent_id + public_key_b64)",
    )
    init.add_argument(
        "--export-private-key",
        action="store_true",
        help="Include private_key_b64 in output (sensitive; avoid in shared logs)",
    )
    init.add_argument("--json", action="store_true", help="Print identity details as JSON")

    track = sub.add_parser("track", help="Canonicalize tracked files and append AMCS state events")
    track.add_argument("--config-file", default="iap.yaml", help="Tracking config YAML path")
    track.add_argument("--identity-file", default=None)
    track.add_argument("--amcs-db", default=None, help="Path to local AMCS SQLite DB")
    track.add_argument("--json", action="store_true")

    commit = sub.add_parser("commit", help="Record a state mutation commit")
    commit.add_argument("message", help="Commit message")
    commit.add_argument("--config-file", default="iap.yaml", help="Tracking config YAML path")
    commit.add_argument("--identity-file", default=None)
    commit.add_argument("--amcs-db", default=None, help="Path to local AMCS SQLite DB")
    commit.add_argument("--json", action="store_true")

    setup = sub.add_parser("setup", help="Bootstrap registry access settings in one command")
    setup_registry_base_group = setup.add_mutually_exclusive_group()
    setup_registry_base_group.add_argument(
        "--registry-base",
        default=None,
        help="Registry base URL to store in the selected CLI config",
    )
    setup_registry_base_group.add_argument(
        "--clear-registry-base",
        action="store_true",
        help="Remove the stored registry base from the selected CLI config",
    )
    setup_registry_api_key_group = setup.add_mutually_exclusive_group()
    setup_registry_api_key_group.add_argument(
        "--registry-api-key",
        default=None,
        help="Registry entitlement API key to store in the selected CLI config",
    )
    setup_registry_api_key_group.add_argument(
        "--clear-registry-api-key",
        action="store_true",
        help="Remove the stored registry API key from the selected CLI config",
    )
    setup_account_token_group = setup.add_mutually_exclusive_group()
    setup_account_token_group.add_argument(
        "--account-token",
        default=None,
        help="Account token to store in the selected CLI config",
    )
    setup_account_token_group.add_argument(
        "--clear-account-token",
        action="store_true",
        help="Remove the stored account token from the selected CLI config",
    )
    setup.add_argument(
        "--check",
        action="store_true",
        help="Run `registry check` immediately after writing config changes",
    )
    setup.add_argument("--json", action="store_true")

    registry = sub.add_parser("registry", help="Inspect registry state")
    registry_sub = registry.add_subparsers(dest="registry_command", required=True)
    registry_status = registry_sub.add_parser(
        "status", help="Show registry status for an agent_id"
    )
    registry_status.add_argument(
        "--registry-base",
        default=None,
        help="Registry base URL override (default from config)",
    )
    registry_status.add_argument("--agent-id", default=None, help="Agent id to inspect")
    registry_status.add_argument(
        "--identity-file",
        default=None,
        help="Path to local identity file when deriving agent_id fallback",
    )
    registry_status.add_argument("--json", action="store_true")
    registry_check = registry_sub.add_parser(
        "check", help="Validate registry reachability and configured credentials"
    )
    registry_check.add_argument(
        "--registry-base",
        default=None,
        help="Registry base URL override (default from config)",
    )
    registry_check.add_argument(
        "--identity-file",
        default=None,
        help="Path to local identity file when deriving agent_id fallback",
    )
    registry_check.add_argument(
        "--project-local",
        action="store_true",
        help="Prefer ./.iap/identity/ed25519.json for this project",
    )
    registry_check.add_argument("--json", action="store_true")
    registry_set_base = registry_sub.add_parser(
        "set-base", help="Store or clear the default registry base URL in the CLI config"
    )
    registry_set_base_group = registry_set_base.add_mutually_exclusive_group(required=True)
    registry_set_base_group.add_argument(
        "--base",
        default=None,
        help="Registry base URL to store in the selected CLI config",
    )
    registry_set_base_group.add_argument(
        "--clear",
        action="store_true",
        help="Reset the stored registry base to the default value",
    )
    registry_set_base.add_argument("--json", action="store_true")
    registry_set_api_key = registry_sub.add_parser(
        "set-api-key", help="Store or clear the registry API key in the CLI config"
    )
    registry_set_api_key_group = registry_set_api_key.add_mutually_exclusive_group(required=True)
    registry_set_api_key_group.add_argument(
        "--api-key",
        default=None,
        help="Registry entitlement API key to store in the selected CLI config",
    )
    registry_set_api_key_group.add_argument(
        "--clear",
        action="store_true",
        help="Remove the stored registry API key from the selected CLI config",
    )
    registry_set_api_key.add_argument("--json", action="store_true")

    account = sub.add_parser("account", help="Inspect account-scoped quota and usage")
    account_sub = account.add_subparsers(dest="account_command", required=True)
    account_usage = account_sub.add_parser(
        "usage", help="Show usage for the configured account token"
    )
    account_usage.add_argument(
        "--registry-base",
        default=None,
        help="Registry base URL override (default from config)",
    )
    account_usage.add_argument("--json", action="store_true")
    account_set_token = account_sub.add_parser(
        "set-token", help="Store or clear the account token in the CLI config"
    )
    account_set_token_group = account_set_token.add_mutually_exclusive_group(required=True)
    account_set_token_group.add_argument(
        "--token",
        default=None,
        help="Account token value to store in the selected CLI config",
    )
    account_set_token_group.add_argument(
        "--clear",
        action="store_true",
        help="Remove the stored account token from the selected CLI config",
    )
    account_set_token.add_argument("--json", action="store_true")

    upgrade = sub.add_parser("upgrade", help="Inspect upgrade readiness and compatibility")
    upgrade_sub = upgrade.add_subparsers(dest="upgrade_command", required=True)
    upgrade_status = upgrade_sub.add_parser(
        "status",
        help="Show local identity context and registry capabilities before upgrading",
    )
    upgrade_status.add_argument(
        "--registry-base",
        default=None,
        help="Registry base URL override (default from config)",
    )
    upgrade_status.add_argument(
        "--identity-file",
        default=None,
        help="Path to local identity file override",
    )
    upgrade_status.add_argument(
        "--project-local",
        action="store_true",
        help="Prefer ./.iap/identity/ed25519.json for this project",
    )
    upgrade_status.add_argument("--json", action="store_true")

    upgrade_migrate = upgrade_sub.add_parser(
        "migrate",
        help="Inspect or apply safe local .iap metadata migrations",
    )
    upgrade_migrate.add_argument(
        "--identity-file",
        default=None,
        help="Path to local identity file override",
    )
    upgrade_migrate.add_argument(
        "--project-local",
        action="store_true",
        help="Prefer ./.iap/identity/ed25519.json for this project",
    )
    upgrade_migrate.add_argument(
        "--apply",
        action="store_true",
        help="Write safe local metadata/schema updates when needed",
    )
    upgrade_migrate.add_argument("--json", action="store_true")

    verify = sub.add_parser("verify", help="Verify continuity record offline")
    verify.add_argument("certificate_json")
    verify.add_argument("--registry-public-key-b64", default=None)
    verify.add_argument("--registry-base", default=None)
    verify.add_argument("--identity-anchor", default=None)
    verify.add_argument("--profile", choices=("basic", "strict"), default="basic")
    verify.add_argument("--previous-certificate", default=None)
    verify.add_argument("--witness-bundle", default=None, help="Path to JSON witness bundle list")
    verify.add_argument("--min-witnesses", type=int, default=0)
    verify.add_argument("--json", action="store_true")

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
    amcs_append = amcs_sub.add_parser("append", help="Append local files into AMCS as state events")
    amcs_append.add_argument("--amcs-db", default=None, help="Path to local AMCS SQLite DB")
    amcs_append.add_argument("--agent-id", default=None, help="Agent id for AMCS append")
    amcs_append.add_argument(
        "--identity-file",
        default=None,
        help="Path to local identity file when deriving agent_id fallback",
    )
    amcs_append.add_argument(
        "--file",
        dest="files",
        action="append",
        default=[],
        help="File path to append (repeat flag for multiple files)",
    )
    # Legacy aliases used by earlier walkthrough/scripts.
    amcs_append.add_argument("--agent-file", default=None, help="Alias for --file")
    amcs_append.add_argument("--soul-file", default=None, help="Alias for --file")
    amcs_append.add_argument("--json", action="store_true", help="Print append details as JSON")

    anchor = sub.add_parser("anchor", help="Create a state anchor (or legacy identity-anchor ops)")
    anchor.add_argument(
        "--registry-base",
        default=None,
        help="Registry base URL override (default from config)",
    )
    anchor.add_argument(
        "--identity-file",
        default=None,
        help="Path to local identity file (default: ~/.iap_agent/identity/ed25519.json)",
    )
    anchor.add_argument("--agent-name", default=None)
    anchor.add_argument("--agent-custody-class", default=None)
    anchor.add_argument("--memory-root", default=None)
    anchor.add_argument("--sequence", type=int, default=None)
    anchor.add_argument("--amcs-db", default=None, help="Path to local AMCS SQLite DB")
    anchor.add_argument(
        "--payment-provider",
        choices=("auto", "stripe", "lightning-btc", "lnbits"),
        default="auto",
        help="Choose payment handoff provider (lnbits is legacy alias for lightning-btc)",
    )
    anchor.add_argument("--success-url", default=None)
    anchor.add_argument("--cancel-url", default=None)
    anchor.add_argument("--open-browser", action="store_true")
    anchor.add_argument("--json", action="store_true")
    anchor.add_argument(
        "--local-only",
        action="store_true",
        help="Create local signed state_root only, do not submit to registry",
    )
    anchor_sub = anchor.add_subparsers(dest="anchor_command", required=False)
    anchor_sub.add_parser("state", help="Create state anchor (default behavior)")
    anchor_issue = anchor_sub.add_parser("issue", help="Issue identity anchor certificate")
    anchor_identity = anchor_sub.add_parser("identity", help="Alias for `anchor issue`")
    anchor_identity.add_argument(
        "--registry-base",
        default=None,
        help="Registry base URL override (default from config)",
    )
    anchor_identity.add_argument(
        "--identity-file",
        default=None,
        help="Path to local identity file (default: ~/.iap_agent/identity/ed25519.json)",
    )
    anchor_identity.add_argument(
        "--agent-name",
        default=None,
        help="Optional agent display name metadata",
    )
    anchor_identity.add_argument(
        "--payment-provider",
        choices=("auto", "stripe", "lightning-btc", "lnbits"),
        default="auto",
        help="Choose payment handoff provider (lnbits is legacy alias for lightning-btc)",
    )
    anchor_identity.add_argument("--success-url", default=None)
    anchor_identity.add_argument("--cancel-url", default=None)
    anchor_identity.add_argument("--open-browser", action="store_true")
    anchor_identity.add_argument(
        "--wait",
        action="store_true",
        help="Wait until request is CERTIFIED",
    )
    anchor_identity.add_argument("--timeout-seconds", type=int, default=300)
    anchor_identity.add_argument("--poll-seconds", type=int, default=5)
    anchor_identity.add_argument("--json", action="store_true", help="Print response as JSON")
    anchor_issue.add_argument(
        "--registry-base",
        default=None,
        help="Registry base URL override (default from config)",
    )
    anchor_issue.add_argument(
        "--identity-file",
        default=None,
        help="Path to local identity file (default: ~/.iap_agent/identity/ed25519.json)",
    )
    anchor_issue.add_argument(
        "--agent-name",
        default=None,
        help="Optional agent display name metadata",
    )
    anchor_issue.add_argument(
        "--payment-provider",
        choices=("auto", "stripe", "lightning-btc", "lnbits"),
        default="auto",
        help="Choose payment handoff provider (lnbits is legacy alias for lightning-btc)",
    )
    anchor_issue.add_argument("--success-url", default=None)
    anchor_issue.add_argument("--cancel-url", default=None)
    anchor_issue.add_argument("--open-browser", action="store_true")
    anchor_issue.add_argument("--wait", action="store_true", help="Wait until request is CERTIFIED")
    anchor_issue.add_argument("--timeout-seconds", type=int, default=300)
    anchor_issue.add_argument("--poll-seconds", type=int, default=5)
    anchor_issue.add_argument("--json", action="store_true", help="Print response as JSON")
    anchor_cert = anchor_sub.add_parser("cert", help="Fetch and save identity-anchor certificate")
    anchor_cert.add_argument("--request-id", required=True)
    anchor_cert.add_argument(
        "--registry-base",
        default=None,
        help="Registry base URL override (default from config)",
    )
    anchor_cert.add_argument(
        "--output-file",
        default=None,
        help=(
            "Path for certificate bundle JSON "
            "(default: <sessions_dir>/certificates/identity_anchor_<request_id>.json)"
        ),
    )
    anchor_cert.add_argument("--json", action="store_true")

    continuity = sub.add_parser("continuity", help="Continuity operations")
    continuity_sub = continuity.add_subparsers(dest="continuity_command", required=True)
    continuity_request = continuity_sub.add_parser(
        "request", help="Submit signed continuity request"
    )
    continuity_request.add_argument(
        "--registry-base",
        default=None,
        help="Registry base URL override (default from config)",
    )
    continuity_request.add_argument(
        "--identity-file",
        default=None,
        help="Path to local identity file (default: ~/.iap_agent/identity/ed25519.json)",
    )
    continuity_request.add_argument("--agent-name", default=None)
    continuity_request.add_argument("--agent-custody-class", default=None)
    continuity_request.add_argument("--memory-root", default=None)
    continuity_request.add_argument("--sequence", type=int, default=None)
    continuity_request.add_argument("--amcs-db", default=None, help="Path to local AMCS SQLite DB")
    continuity_request.add_argument(
        "--sessions-dir",
        default=None,
        help="Directory to store request session artifacts (default from config)",
    )
    continuity_request.add_argument("--json", action="store_true", help="Print response as JSON")
    continuity_pay = continuity_sub.add_parser("pay", help="Show payment instructions for request")
    continuity_pay.add_argument("--request-id", required=True)
    continuity_pay.add_argument(
        "--registry-base",
        default=None,
        help="Registry base URL override (default from config)",
    )
    continuity_pay.add_argument("--success-url", default=None)
    continuity_pay.add_argument("--cancel-url", default=None)
    continuity_pay.add_argument(
        "--payment-provider",
        choices=("auto", "stripe", "lightning-btc", "lnbits"),
        default="auto",
        help="Choose payment handoff provider (lnbits is legacy alias for lightning-btc)",
    )
    continuity_pay.add_argument("--open-browser", action="store_true")
    continuity_pay.add_argument("--json", action="store_true", help="Print payment details as JSON")
    continuity_wait = continuity_sub.add_parser("wait", help="Wait until request is CERTIFIED")
    continuity_wait.add_argument("--request-id", required=True)
    continuity_wait.add_argument(
        "--registry-base",
        default=None,
        help="Registry base URL override (default from config)",
    )
    continuity_wait.add_argument("--timeout-seconds", type=int, default=300)
    continuity_wait.add_argument("--poll-seconds", type=int, default=5)
    continuity_wait.add_argument("--json", action="store_true")

    continuity_cert = continuity_sub.add_parser("cert", help="Fetch and save issued certificate")
    continuity_cert.add_argument("--request-id", required=True)
    continuity_cert.add_argument(
        "--registry-base",
        default=None,
        help="Registry base URL override (default from config)",
    )
    continuity_cert.add_argument(
        "--output-file",
        default=None,
        help=(
            "Path for certificate bundle JSON "
            "(default: <sessions_dir>/certificates/<request_id>.json)"
        ),
    )
    continuity_cert.add_argument("--json", action="store_true")

    flow = sub.add_parser("flow", help="High-level guided flows")
    flow_sub = flow.add_subparsers(dest="flow_command", required=True)
    flow_run = flow_sub.add_parser("run", help="Run full end-to-end flow")
    flow_run.add_argument(
        "--registry-base",
        default=None,
        help="Registry base URL override (default from config)",
    )
    flow_run.add_argument(
        "--identity-file",
        default=None,
        help="Path to local identity file (default: ~/.iap_agent/identity/ed25519.json)",
    )
    flow_run.add_argument(
        "--agent-name",
        default=None,
        help="Optional agent display name metadata",
    )
    flow_run.add_argument("--agent-custody-class", default=None)
    flow_run.add_argument("--amcs-db", default=None, help="Path to local AMCS SQLite DB")
    flow_run.add_argument("--memory-root", default=None)
    flow_run.add_argument("--sequence", type=int, default=None)
    flow_run.add_argument("--request-timeout-seconds", type=int, default=300)
    flow_run.add_argument("--poll-seconds", type=int, default=5)
    flow_run.add_argument(
        "--payment-provider",
        choices=("auto", "stripe", "lightning-btc", "lnbits"),
        default="auto",
        help="Choose payment handoff provider (lnbits is legacy alias for lightning-btc)",
    )
    flow_run.add_argument("--open-browser", action="store_true")
    flow_run.add_argument(
        "--output-dir",
        default=None,
        help="Directory for flow artifacts (default: <sessions_dir>/flows/<request_id>)",
    )
    flow_run.add_argument("--json", action="store_true")

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


def _sanitize_error_text(value: str) -> str:
    redacted = value
    for field in _SENSITIVE_FIELDS:
        redacted = re.sub(
            rf"(?i)({field}\s*[=:]\s*)([^,\s]+)",
            r"\1[REDACTED]",
            redacted,
        )
    redacted = re.sub(r"(?i)([?&](?:secret|token|api_key)=)([^&\s]+)", r"\1[REDACTED]", redacted)
    return redacted


def _print_error(stderr, prefix: str, message: str, *, code: int) -> int:
    print(f"{prefix}: {_sanitize_error_text(message)}", file=stderr)
    return code


def _print_registry_request_error(stderr, exc: RegistryRequestError, *, code: int) -> int:
    if exc.status_code == 401 and exc.detail == "invalid api key":
        return _print_error(
            stderr,
            "registry error",
            (
                "invalid registry API key. Update `IAP_REGISTRY_API_KEY` or the "
                "`registry_api_key` value in your config, or remove it to use the payment flow."
            ),
            code=code,
        )
    if exc.status_code == 403 and exc.detail == "account inactive":
        return _print_error(
            stderr,
            "registry error",
            (
                "the account linked to this registry API key is inactive. Ask your operator to "
                "reactivate the account or issue a different API key."
            ),
            code=code,
        )
    if exc.status_code == 429 and exc.detail == "api key quota exceeded":
        return _print_error(
            stderr,
            "registry error",
            (
                "registry API key quota exceeded for this billing window. Use a different API key, "
                "wait for quota reset, or retry without the API key to use the payment flow."
            ),
            code=code,
        )
    if exc.status_code == 429 and exc.detail == "account tier quota exceeded":
        return _print_error(
            stderr,
            "registry error",
            (
                "the linked account has reached its monthly tier limit. Ask your operator to "
                "increase the account quota, use a different entitled account, or retry without "
                "the API key to use the payment flow."
            ),
            code=code,
        )
    return _print_error(stderr, "registry error", str(exc), code=code)


def _run_version(*, config: CLIConfig, as_json: bool, stdout) -> int:
    payload = {
        "cli": "iap-agent",
        "sdk_version": _sdk_version(),
        "protocol_version": PROTOCOL_VERSION,
        "maturity_level": config.maturity_level,
        "beta_mode": config.beta_mode,
        "default_registry_base": config.registry_base,
        "has_pinned_registry_public_key": bool(config.registry_public_key_b64),
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
    return EXIT_SUCCESS


def _coming_soon(*, path: str, stdout) -> int:
    print(f"{path}: coming soon", file=stdout)
    return EXIT_NETWORK_ERROR


def _run_init(*, args, stdout, stderr) -> int:
    identity_file = args.identity_file
    if args.project_local:
        if identity_file:
            return _print_error(
                stderr,
                "identity error",
                "cannot use --project-local together with --identity-file",
                code=EXIT_VALIDATION_ERROR,
            )
        identity_file = str(Path.cwd() / ".iap" / "identity" / "ed25519.json")

    try:
        identity, created, identity_path = load_or_create_identity(identity_file)
    except IdentityError as exc:
        return _print_error(stderr, "identity error", str(exc), code=EXIT_VALIDATION_ERROR)

    project_root = Path.cwd()
    meta_path, meta_schema_version = _ensure_local_meta(
        project_root=project_root,
        identity_path=identity_path,
    )

    payload = {
        "identity_path": str(identity_path),
        "created": created,
        "agent_id": identity.agent_id,
        "public_key_b64": identity.public_key_b64,
        "meta_file": str(meta_path),
        "meta_schema_version": meta_schema_version,
    }
    if args.export_private_key:
        payload["private_key_b64"] = identity.private_key_b64

    state_dir = project_root / ".iap" / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    secret_path = state_dir / "agent_secret"
    if not secret_path.exists():
        secret_path.write_text(uuid4().hex, encoding="utf-8")
        if os.name == "posix":
            secret_path.chmod(0o600)

    state_root_path = state_dir / "state_root.json"
    if not state_root_path.exists():
        state_root_payload = {
            "schema_version": LOCAL_STATE_SCHEMA_VERSION,
            "agent_id": identity.agent_id,
            "sequence": 0,
            "memory_root": None,
            "status": "initialized",
            "updated_at": _utc_now_iso(),
        }
        state_root_path.write_text(
            json.dumps(state_root_payload, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )

    tracking_config_path = project_root / "iap.yaml"
    created_tracking_config = ensure_tracking_config(tracking_config_path)

    if args.json:
        payload["agent_secret_path"] = str(secret_path)
        payload["state_dir"] = str(state_dir)
        payload["state_root_file"] = str(state_root_path)
        payload["tracking_config_file"] = str(tracking_config_path)
        payload["tracking_config_created"] = created_tracking_config
        print(json.dumps(payload, sort_keys=True), file=stdout)
        return EXIT_SUCCESS

    print(f"identity_path: {payload['identity_path']}", file=stdout)
    print(f"created: {str(payload['created']).lower()}", file=stdout)
    print(f"agent_id: {payload['agent_id']}", file=stdout)
    print(f"public_key_b64: {payload['public_key_b64']}", file=stdout)
    print(f"meta_file: {payload['meta_file']}", file=stdout)
    print(f"state_dir: {state_dir}", file=stdout)
    print(f"state_root_file: {state_root_path}", file=stdout)
    print(f"tracking_config_file: {tracking_config_path}", file=stdout)
    if args.export_private_key:
        print("private_key_b64: [hidden in non-json output]", file=stdout)
    return EXIT_SUCCESS


def _run_track(*, args, config: CLIConfig, stdout, stderr) -> int:
    try:
        identity, _ = load_identity(args.identity_file)
    except IdentityError as exc:
        return _print_error(stderr, "identity error", str(exc), code=EXIT_VALIDATION_ERROR)

    config_path = Path(args.config_file)
    try:
        track_config = load_track_config(config_path)
    except AMCSError as exc:
        return _print_error(stderr, "track error", str(exc), code=EXIT_VALIDATION_ERROR)

    project_root = Path.cwd()
    files = collect_tracked_files(project_root=project_root, config=track_config)
    records = [
        build_file_record(project_root=project_root, file_path=file_path)
        for file_path in files
    ]

    amcs_db_path = args.amcs_db or config.amcs_db_path
    try:
        result = append_tracking_events(
            amcs_db_path=amcs_db_path,
            agent_id=identity.agent_id,
            file_records=records,
        )
    except AMCSError as exc:
        return _print_error(stderr, "amcs error", str(exc), code=EXIT_VALIDATION_ERROR)

    if args.json:
        print(json.dumps(result, sort_keys=True), file=stdout)
        return EXIT_SUCCESS

    print(f"agent_id: {result['agent_id']}", file=stdout)
    print(f"tracked_file_count: {result['tracked_file_count']}", file=stdout)
    print(f"sequence_end: {result['sequence_end']}", file=stdout)
    print(f"memory_root: {result['memory_root']}", file=stdout)
    return EXIT_SUCCESS


def _run_commit(*, args, config: CLIConfig, stdout, stderr) -> int:
    try:
        identity, _ = load_identity(args.identity_file)
    except IdentityError as exc:
        return _print_error(stderr, "identity error", str(exc), code=EXIT_VALIDATION_ERROR)

    config_path = Path(args.config_file)
    try:
        track_config = load_track_config(config_path)
    except AMCSError as exc:
        return _print_error(stderr, "track error", str(exc), code=EXIT_VALIDATION_ERROR)

    project_root = Path.cwd()
    files = collect_tracked_files(project_root=project_root, config=track_config)
    records = [
        build_file_record(project_root=project_root, file_path=file_path)
        for file_path in files
    ]
    amcs_db_path = args.amcs_db or config.amcs_db_path
    try:
        result = append_tracking_events(
            amcs_db_path=amcs_db_path,
            agent_id=identity.agent_id,
            file_records=records,
        )
    except AMCSError as exc:
        return _print_error(stderr, "amcs error", str(exc), code=EXIT_VALIDATION_ERROR)

    # Record explicit mutation intent as a dedicated commit event.
    try:
        from amcs import AMCSClient, SQLiteEventStore
    except Exception as exc:  # pragma: no cover
        return _print_error(
            stderr,
            "amcs error",
            f"AMCS unavailable for commit event append: {exc}",
            code=EXIT_VALIDATION_ERROR,
        )
    store = SQLiteEventStore(amcs_db_path)
    client = AMCSClient(store=store, agent_id=identity.agent_id)
    commit_result = client.append(
        "state.commit",
        {"message": args.message, "tracked_file_count": result["tracked_file_count"]},
    )
    memory_root = client.get_memory_root()

    output = {
        "agent_id": identity.agent_id,
        "message": args.message,
        "tracked_file_count": result["tracked_file_count"],
        "sequence": commit_result.sequence,
        "event_hash": commit_result.event_hash,
        "memory_root": memory_root,
    }

    if args.json:
        print(json.dumps(output, sort_keys=True), file=stdout)
        return EXIT_SUCCESS
    print(f"agent_id: {output['agent_id']}", file=stdout)
    print(f"message: {output['message']}", file=stdout)
    print(f"sequence: {output['sequence']}", file=stdout)
    print(f"memory_root: {output['memory_root']}", file=stdout)
    return EXIT_SUCCESS


def _project_local_identity_path() -> Path:
    return Path.cwd() / ".iap" / "identity" / "ed25519.json"


def _resolve_upgrade_identity_path(args) -> Path:
    if args.project_local and args.identity_file:
        raise IdentityError("cannot use --project-local together with --identity-file")
    if args.identity_file:
        return Path(args.identity_file)
    if args.project_local:
        return _project_local_identity_path()
    project_local = _project_local_identity_path()
    if project_local.exists():
        return project_local
    return DEFAULT_IDENTITY_PATH


def _classify_identity_scope(identity_path: Path) -> str:
    resolved_identity = identity_path.expanduser().resolve(strict=False)
    project_local = _project_local_identity_path().expanduser().resolve(strict=False)
    global_path = DEFAULT_IDENTITY_PATH.expanduser().resolve(strict=False)
    if resolved_identity == project_local:
        return "project-local"
    if resolved_identity == global_path:
        return "global"
    return "custom"


def _parse_version_tuple(raw: str) -> tuple[int, ...]:
    parts: list[int] = []
    for piece in re.split(r"[.+-]", raw):
        if not piece:
            continue
        if piece.isdigit():
            parts.append(int(piece))
            continue
        digits = "".join(ch for ch in piece if ch.isdigit())
        if digits:
            parts.append(int(digits))
            break
        break
    return tuple(parts)


def _ensure_local_meta(*, project_root: Path, identity_path: Path) -> tuple[Path, int]:
    meta_path = project_root / ".iap" / "meta.json"
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    if meta_path.exists():
        try:
            payload = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            payload = {}
        schema_version = payload.get("schema_version")
        if isinstance(schema_version, int) and schema_version >= 1:
            return meta_path, schema_version
    payload = {
        "schema_version": LOCAL_META_SCHEMA_VERSION,
        "identity_path": str(identity_path),
        "updated_at": _utc_now_iso(),
    }
    meta_path.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return meta_path, LOCAL_META_SCHEMA_VERSION


def _read_local_state_summary() -> dict[str, object]:
    state_root_path = Path.cwd() / ".iap" / "state" / "state_root.json"
    meta_path = Path.cwd() / ".iap" / "meta.json"
    meta_exists = meta_path.exists()
    meta_schema_version = 0
    if meta_exists:
        try:
            meta_payload = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            meta_payload = {}
        schema_version = meta_payload.get("schema_version")
        meta_schema_version = int(schema_version) if isinstance(schema_version, int) else 0
    if not state_root_path.exists():
        return {
            "meta_file": str(meta_path),
            "meta_exists": meta_exists,
            "meta_schema_version": meta_schema_version,
            "state_root_file": str(state_root_path),
            "exists": False,
            "schema_version": 0,
            "sequence": None,
        }
    try:
        payload = json.loads(state_root_path.read_text(encoding="utf-8"))
    except Exception:
        return {
            "meta_file": str(meta_path),
            "meta_exists": meta_exists,
            "meta_schema_version": meta_schema_version,
            "state_root_file": str(state_root_path),
            "exists": True,
            "schema_version": 0,
            "sequence": None,
        }
    sequence = payload.get("sequence")
    sequence_value = int(sequence) if isinstance(sequence, int) else None
    schema_version = payload.get("schema_version")
    schema_value = int(schema_version) if isinstance(schema_version, int) else 0
    return {
        "meta_file": str(meta_path),
        "meta_exists": meta_exists,
        "meta_schema_version": meta_schema_version,
        "state_root_file": str(state_root_path),
        "exists": True,
        "schema_version": schema_value,
        "sequence": sequence_value,
    }


def _plan_local_migration(
    *,
    project_root: Path,
    identity_path: Path,
) -> tuple[dict[str, object], list[str]]:
    meta_path = project_root / ".iap" / "meta.json"
    state_root_path = project_root / ".iap" / "state" / "state_root.json"
    actions: list[str] = []

    meta_schema_version = 0
    meta_identity_path = None
    if meta_path.exists():
        try:
            meta_payload = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            meta_payload = {}
        schema_version = meta_payload.get("schema_version")
        meta_schema_version = int(schema_version) if isinstance(schema_version, int) else 0
        raw_identity_path = meta_payload.get("identity_path")
        if isinstance(raw_identity_path, str) and raw_identity_path.strip():
            meta_identity_path = raw_identity_path

    normalized_identity_path = str(identity_path)
    if (project_root / ".iap").exists() and (
        not meta_path.exists()
        or meta_schema_version < LOCAL_META_SCHEMA_VERSION
        or meta_identity_path != normalized_identity_path
    ):
        actions.append("refresh_local_meta")

    state_schema_version = 0
    if state_root_path.exists():
        try:
            state_payload = json.loads(state_root_path.read_text(encoding="utf-8"))
        except Exception:
            state_payload = {}
        schema_version = state_payload.get("schema_version")
        state_schema_version = int(schema_version) if isinstance(schema_version, int) else 0
        if state_schema_version < LOCAL_STATE_SCHEMA_VERSION:
            actions.append("upgrade_state_root_schema")

    summary = {
        "project_root": str(project_root),
        "identity_path": normalized_identity_path,
        "meta_file": str(meta_path),
        "meta_exists": meta_path.exists(),
        "meta_schema_version": meta_schema_version,
        "state_root_file": str(state_root_path),
        "state_root_exists": state_root_path.exists(),
        "state_root_schema_version": state_schema_version,
    }
    return summary, actions


def _apply_local_migration(
    *,
    project_root: Path,
    identity_path: Path,
    actions: list[str],
) -> list[str]:
    applied: list[str] = []
    if "refresh_local_meta" in actions:
        _ensure_local_meta(project_root=project_root, identity_path=identity_path)
        applied.append("refresh_local_meta")

    state_root_path = project_root / ".iap" / "state" / "state_root.json"
    if "upgrade_state_root_schema" in actions and state_root_path.exists():
        try:
            payload = json.loads(state_root_path.read_text(encoding="utf-8"))
        except Exception:
            payload = {}
        payload["schema_version"] = LOCAL_STATE_SCHEMA_VERSION
        state_root_path.parent.mkdir(parents=True, exist_ok=True)
        state_root_path.write_text(
            json.dumps(payload, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        applied.append("upgrade_state_root_schema")

    return applied


def _build_registry_client(*, registry_base: str, config: CLIConfig) -> RegistryClient:
    kwargs = {
        "base_url": registry_base,
        "api_key": config.registry_api_key,
    }
    if config.account_token:
        kwargs["account_token"] = config.account_token
    return RegistryClient(**kwargs)


def _write_account_usage_snapshot(*, config: CLIConfig, payload: dict) -> Path:
    snapshot_path = Path(config.sessions_dir) / "account_usage_last.json"
    snapshot_path.parent.mkdir(parents=True, exist_ok=True)
    snapshot_path.write_text(
        json.dumps(payload, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return snapshot_path


def _run_registry_status(*, args, config: CLIConfig, stdout, stderr) -> int:
    agent_id = args.agent_id
    if not agent_id:
        try:
            identity, _ = load_identity(args.identity_file)
            agent_id = identity.agent_id
        except IdentityError as exc:
            return _print_error(stderr, "identity error", str(exc), code=EXIT_VALIDATION_ERROR)

    registry_base = args.registry_base or config.registry_base
    client = _build_registry_client(registry_base=registry_base, config=config)
    try:
        status = client.get_agent_registry_status(agent_id)
    except RegistryUnavailableError as exc:
        return _print_error(stderr, "registry error", str(exc), code=EXIT_NETWORK_ERROR)

    payload = {
        "agent_id": agent_id,
        "registry_base": registry_base,
        "has_identity_anchor": bool(status.get("has_identity_anchor")),
        "identity_anchor_request_id": status.get("identity_anchor_request_id"),
        "identity_anchor_issued_at": status.get("identity_anchor_issued_at"),
        "latest_continuity_sequence": status.get("latest_continuity_sequence"),
        "latest_continuity_memory_root": status.get("latest_continuity_memory_root"),
        "latest_continuity_request_id": status.get("latest_continuity_request_id"),
        "latest_continuity_issued_at": status.get("latest_continuity_issued_at"),
    }
    if args.json:
        print(json.dumps(payload, sort_keys=True), file=stdout)
        return EXIT_SUCCESS

    print(f"agent_id: {payload['agent_id']}", file=stdout)
    print(f"registry_base: {payload['registry_base']}", file=stdout)
    print(f"has_identity_anchor: {payload['has_identity_anchor']}", file=stdout)
    print(f"identity_anchor_request_id: {payload['identity_anchor_request_id']}", file=stdout)
    print(f"identity_anchor_issued_at: {payload['identity_anchor_issued_at']}", file=stdout)
    print(f"latest_continuity_sequence: {payload['latest_continuity_sequence']}", file=stdout)
    print(
        f"latest_continuity_memory_root: {payload['latest_continuity_memory_root']}",
        file=stdout,
    )
    print(f"latest_continuity_request_id: {payload['latest_continuity_request_id']}", file=stdout)
    print(f"latest_continuity_issued_at: {payload['latest_continuity_issued_at']}", file=stdout)
    return EXIT_SUCCESS


def _run_registry_check(*, args, config: CLIConfig, stdout, stderr) -> int:
    try:
        identity_target = _resolve_upgrade_identity_path(args)
    except IdentityError as exc:
        return _print_error(stderr, "identity error", str(exc), code=EXIT_VALIDATION_ERROR)

    identity = None
    identity_path = identity_target
    identity_error = None
    try:
        identity, identity_path = load_identity(identity_target)
    except IdentityError as exc:
        identity_error = str(exc)

    registry_base = args.registry_base or config.registry_base
    client = _build_registry_client(registry_base=registry_base, config=config)

    registry_info = None
    registry_error = None
    try:
        registry_info = client.get_registry_info()
    except (RegistryRequestError, RegistryUnavailableError) as exc:
        registry_error = str(exc)

    agent_status = None
    if identity is not None and registry_error is None:
        try:
            agent_status = client.get_agent_registry_status(identity.agent_id)
        except (RegistryRequestError, RegistryUnavailableError) as exc:
            registry_error = str(exc)

    account_usage = None
    account_error = None
    if config.account_token and registry_error is None:
        try:
            account_usage = client.get_account_usage()
        except (RegistryRequestError, RegistryUnavailableError) as exc:
            account_error = str(exc)

    warnings: list[str] = []
    next_actions: list[str] = []
    if registry_error:
        warnings.append(f"registry lookup unavailable: {registry_error}")
        next_actions.append("verify the registry base URL and network reachability")
    if identity_error:
        warnings.append("no usable local identity was found for agent-level status checks")
        next_actions.append("run `iap-agent init --project-local` or select the correct identity")
    if config.registry_api_key:
        next_actions.append(
            "registry API key is configured; issuance will prefer the "
            "entitlement path when supported"
        )
    if config.account_token and account_error:
        warnings.append(f"account token check failed: {account_error}")
        next_actions.append(
            "refresh the account token with `iap-agent account set-token --token ...` if needed"
        )
    elif config.account_token and account_usage is not None:
        next_actions.append("account token is usable for self-service account usage reads")

    payload = {
        "registry_base": registry_base,
        "registry_reachable": registry_info is not None,
        "registry_version": registry_info.get("version") if registry_info else None,
        "minimum_recommended_sdk_version": (
            registry_info.get("minimum_recommended_sdk_version") if registry_info else None
        ),
        "supported_features": registry_info.get("supported_features", []) if registry_info else [],
        "identity_checked": identity is not None,
        "identity_path": str(identity_path),
        "agent_id": identity.agent_id if identity is not None else None,
        "has_identity_anchor": (
            agent_status.get("has_identity_anchor") if isinstance(agent_status, dict) else None
        ),
        "latest_continuity_sequence": (
            agent_status.get("latest_continuity_sequence")
            if isinstance(agent_status, dict)
            else None
        ),
        "registry_api_key_configured": bool(config.registry_api_key),
        "account_token_configured": bool(config.account_token),
        "account_token_valid": account_usage is not None if config.account_token else None,
        "linked_key_count": (
            account_usage.get("linked_key_count") if isinstance(account_usage, dict) else None
        ),
        "effective_remaining_identity_anchor": (
            account_usage.get("effective_remaining_identity_anchor")
            if isinstance(account_usage, dict)
            else None
        ),
        "effective_remaining_continuity": (
            account_usage.get("effective_remaining_continuity")
            if isinstance(account_usage, dict)
            else None
        ),
        "effective_remaining_lineage": (
            account_usage.get("effective_remaining_lineage")
            if isinstance(account_usage, dict)
            else None
        ),
        "warnings": warnings,
        "next_actions": next_actions,
    }
    if args.json:
        print(json.dumps(payload, sort_keys=True), file=stdout)
        return EXIT_SUCCESS

    print(f"registry_base: {payload['registry_base']}", file=stdout)
    print(f"registry_reachable: {payload['registry_reachable']}", file=stdout)
    print(f"registry_version: {payload['registry_version']}", file=stdout)
    print(
        f"minimum_recommended_sdk_version: {payload['minimum_recommended_sdk_version']}",
        file=stdout,
    )
    print(f"registry_api_key_configured: {payload['registry_api_key_configured']}", file=stdout)
    print(f"account_token_configured: {payload['account_token_configured']}", file=stdout)
    print(f"account_token_valid: {payload['account_token_valid']}", file=stdout)
    print(f"agent_id: {payload['agent_id']}", file=stdout)
    print(f"has_identity_anchor: {payload['has_identity_anchor']}", file=stdout)
    print(f"latest_continuity_sequence: {payload['latest_continuity_sequence']}", file=stdout)
    print(
        "effective_remaining_identity_anchor: "
        f"{payload['effective_remaining_identity_anchor']}",
        file=stdout,
    )
    print(
        "effective_remaining_continuity: "
        f"{payload['effective_remaining_continuity']}",
        file=stdout,
    )
    print(
        "effective_remaining_lineage: "
        f"{payload['effective_remaining_lineage']}",
        file=stdout,
    )
    if warnings:
        print(f"warnings: {' | '.join(warnings)}", file=stdout)
    if next_actions:
        print(f"next_actions: {' | '.join(next_actions)}", file=stdout)
    return EXIT_SUCCESS


def _run_registry_set_base(*, args, stdout, stderr) -> int:
    base_value = None if args.clear else (args.base or "").strip()
    if not args.clear and not base_value:
        return _print_error(
            stderr,
            "registry error",
            "registry base URL must not be empty",
            code=EXIT_VALIDATION_ERROR,
        )
    try:
        config_path = save_cli_setting(args.config, "registry_base", base_value)
    except ConfigError as exc:
        return _print_error(stderr, "config error", str(exc), code=EXIT_VALIDATION_ERROR)

    payload = {
        "config_file": str(config_path),
        "registry_base_stored": not args.clear,
        "registry_base_cleared": bool(args.clear),
        "registry_base_env_override": bool(os.getenv("IAP_REGISTRY_BASE")),
    }
    if args.json:
        print(json.dumps(payload, sort_keys=True), file=stdout)
        return EXIT_SUCCESS

    print(f"config_file: {payload['config_file']}", file=stdout)
    print("registry_base: cleared" if args.clear else "registry_base: stored", file=stdout)
    if payload["registry_base_env_override"]:
        print(
            "warning: IAP_REGISTRY_BASE is currently set in the environment and will override "
            "the stored config value in this shell",
            file=stderr,
        )
    return EXIT_SUCCESS


def _run_registry_set_api_key(*, args, stdout, stderr) -> int:
    api_key_value = None if args.clear else (args.api_key or "").strip()
    if not args.clear and not api_key_value:
        return _print_error(
            stderr,
            "registry error",
            "registry API key must not be empty",
            code=EXIT_VALIDATION_ERROR,
        )
    try:
        config_path = save_cli_setting(args.config, "registry_api_key", api_key_value)
    except ConfigError as exc:
        return _print_error(stderr, "config error", str(exc), code=EXIT_VALIDATION_ERROR)

    payload = {
        "config_file": str(config_path),
        "registry_api_key_stored": not args.clear,
        "registry_api_key_cleared": bool(args.clear),
        "registry_api_key_env_override": bool(os.getenv("IAP_REGISTRY_API_KEY")),
    }
    if args.json:
        print(json.dumps(payload, sort_keys=True), file=stdout)
        return EXIT_SUCCESS

    print(f"config_file: {payload['config_file']}", file=stdout)
    print("registry_api_key: cleared" if args.clear else "registry_api_key: stored", file=stdout)
    if payload["registry_api_key_env_override"]:
        print(
            "warning: IAP_REGISTRY_API_KEY is currently set in the environment and will override "
            "the stored config value in this shell",
            file=stderr,
        )
    return EXIT_SUCCESS


def _run_setup(*, args, stdout, stderr) -> int:
    actions_requested = bool(
        args.registry_base is not None
        or args.clear_registry_base
        or args.registry_api_key is not None
        or args.clear_registry_api_key
        or args.account_token is not None
        or args.clear_account_token
        or args.check
    )
    if not actions_requested:
        return _print_error(
            stderr,
            "setup error",
            "no setup action requested; provide at least one setting or use --check",
            code=EXIT_VALIDATION_ERROR,
        )

    mutations: list[str] = []
    if args.registry_base is not None or args.clear_registry_base:
        base_value = None if args.clear_registry_base else args.registry_base.strip()
        if args.registry_base is not None and not base_value:
            return _print_error(
                stderr,
                "setup error",
                "registry base URL must not be empty",
                code=EXIT_VALIDATION_ERROR,
            )
        try:
            save_cli_setting(args.config, "registry_base", base_value)
        except ConfigError as exc:
            return _print_error(stderr, "config error", str(exc), code=EXIT_VALIDATION_ERROR)
        mutations.append(
            "registry_base cleared" if args.clear_registry_base else "registry_base stored"
        )

    if args.registry_api_key is not None or args.clear_registry_api_key:
        api_key_value = None if args.clear_registry_api_key else args.registry_api_key.strip()
        if args.registry_api_key is not None and not api_key_value:
            return _print_error(
                stderr,
                "setup error",
                "registry API key must not be empty",
                code=EXIT_VALIDATION_ERROR,
            )
        try:
            save_cli_setting(args.config, "registry_api_key", api_key_value)
        except ConfigError as exc:
            return _print_error(stderr, "config error", str(exc), code=EXIT_VALIDATION_ERROR)
        mutations.append(
            "registry_api_key cleared" if args.clear_registry_api_key else "registry_api_key stored"
        )

    if args.account_token is not None or args.clear_account_token:
        account_token_value = None if args.clear_account_token else args.account_token.strip()
        if args.account_token is not None and not account_token_value:
            return _print_error(
                stderr,
                "setup error",
                "account token must not be empty",
                code=EXIT_VALIDATION_ERROR,
            )
        try:
            save_cli_setting(args.config, "account_token", account_token_value)
        except ConfigError as exc:
            return _print_error(stderr, "config error", str(exc), code=EXIT_VALIDATION_ERROR)
        mutations.append(
            "account_token cleared" if args.clear_account_token else "account_token stored"
        )

    try:
        updated_config = load_cli_config(args.config)
    except ConfigError as exc:
        return _print_error(stderr, "config error", str(exc), code=EXIT_VALIDATION_ERROR)

    config_file = Path(args.config) if args.config else Path.home() / ".iap_agent" / "config.toml"
    payload = {
        "config_file": str(config_file),
        "mutations": mutations,
        "registry_base_env_override": bool(os.getenv("IAP_REGISTRY_BASE")),
        "registry_api_key_env_override": bool(os.getenv("IAP_REGISTRY_API_KEY")),
        "account_token_env_override": bool(os.getenv("IAP_ACCOUNT_TOKEN")),
        "registry_check": None,
    }

    if args.check:
        check_out = io.StringIO()
        check_args = SimpleNamespace(
            registry_base=None,
            identity_file=None,
            project_local=False,
            json=True,
        )
        check_rc = _run_registry_check(
            args=check_args,
            config=updated_config,
            stdout=check_out,
            stderr=stderr,
        )
        if check_rc != EXIT_SUCCESS:
            return check_rc
        payload["registry_check"] = json.loads(check_out.getvalue())

    if args.json:
        print(json.dumps(payload, sort_keys=True), file=stdout)
        return EXIT_SUCCESS

    print(f"config_file: {payload['config_file']}", file=stdout)
    if mutations:
        print("mutations:", file=stdout)
        for item in mutations:
            print(f"- {item}", file=stdout)
    else:
        print("mutations: none", file=stdout)
    if payload["registry_base_env_override"]:
        print(
            "warning: IAP_REGISTRY_BASE is currently set in the environment and will override "
            "the stored config value in this shell",
            file=stderr,
        )
    if payload["registry_api_key_env_override"]:
        print(
            "warning: IAP_REGISTRY_API_KEY is currently set in the environment and will override "
            "the stored config value in this shell",
            file=stderr,
        )
    if payload["account_token_env_override"]:
        print(
            "warning: IAP_ACCOUNT_TOKEN is currently set in the environment and will override "
            "the stored config value in this shell",
            file=stderr,
        )
    if payload["registry_check"] is not None:
        print("registry_check: completed", file=stdout)
    return EXIT_SUCCESS


def _run_account_usage(*, args, config: CLIConfig, stdout, stderr) -> int:
    if not config.account_token:
        return _print_error(
            stderr,
            "account error",
            (
                "missing account token; set cli.account_token in config or export "
                "IAP_ACCOUNT_TOKEN before using account commands"
            ),
            code=EXIT_VALIDATION_ERROR,
        )

    registry_base = args.registry_base or config.registry_base
    client = _build_registry_client(registry_base=registry_base, config=config)
    try:
        usage = client.get_account_usage()
    except RegistryRequestError as exc:
        detail_text = exc.detail if isinstance(exc.detail, str) else ""
        if exc.status_code == 401 and "account token" in detail_text.lower():
            return _print_error(
                stderr,
                "account error",
                (
                    f"{detail_text}. Update cli.account_token / IAP_ACCOUNT_TOKEN, or ask "
                    "your operator to issue a fresh account token."
                ),
                code=EXIT_NETWORK_ERROR,
            )
        return _print_registry_request_error(stderr, exc, code=EXIT_NETWORK_ERROR)
    except RegistryUnavailableError as exc:
        return _print_error(stderr, "registry error", str(exc), code=EXIT_NETWORK_ERROR)

    payload = {
        "registry_base": registry_base,
        "account": usage.get("account"),
        "linked_key_count": usage.get("linked_key_count"),
        "quota_periods": usage.get("quota_periods"),
        "total_monthly_identity_anchor_quota": usage.get("total_monthly_identity_anchor_quota"),
        "total_monthly_continuity_quota": usage.get("total_monthly_continuity_quota"),
        "total_monthly_lineage_quota": usage.get("total_monthly_lineage_quota"),
        "total_used_identity_anchor": usage.get("total_used_identity_anchor"),
        "total_used_continuity": usage.get("total_used_continuity"),
        "total_used_lineage": usage.get("total_used_lineage"),
        "total_remaining_identity_anchor": usage.get("total_remaining_identity_anchor"),
        "total_remaining_continuity": usage.get("total_remaining_continuity"),
        "total_remaining_lineage": usage.get("total_remaining_lineage"),
        "keys": usage.get("keys", []),
    }
    snapshot_path = _write_account_usage_snapshot(config=config, payload=payload)
    payload["snapshot_file"] = str(snapshot_path)
    if args.json:
        print(json.dumps(payload, sort_keys=True), file=stdout)
        return EXIT_SUCCESS

    account = payload["account"] or {}
    print(f"registry_base: {payload['registry_base']}", file=stdout)
    print(f"account_id: {account.get('account_id')}", file=stdout)
    print(f"email: {account.get('email')}", file=stdout)
    print(f"tier: {account.get('tier')}", file=stdout)
    print(f"linked_key_count: {payload['linked_key_count']}", file=stdout)
    print(
        "quota_periods: "
        f"{','.join(str(item) for item in (payload['quota_periods'] or []))}",
        file=stdout,
    )
    print(
        "remaining_identity_anchor: "
        f"{payload['total_remaining_identity_anchor']}",
        file=stdout,
    )
    print(
        "remaining_continuity: "
        f"{payload['total_remaining_continuity']}",
        file=stdout,
    )
    print(
        "remaining_lineage: "
        f"{payload['total_remaining_lineage']}",
        file=stdout,
    )
    print(f"snapshot_file: {payload['snapshot_file']}", file=stdout)
    return EXIT_SUCCESS


def _run_account_set_token(*, args, stdout, stderr) -> int:
    token_value = None if args.clear else (args.token or "").strip()
    if not args.clear and not token_value:
        return _print_error(
            stderr,
            "account error",
            "account token must not be empty",
            code=EXIT_VALIDATION_ERROR,
        )

    try:
        config_path = save_cli_setting(args.config, "account_token", token_value)
    except ConfigError as exc:
        return _print_error(stderr, "config error", str(exc), code=EXIT_VALIDATION_ERROR)

    payload = {
        "config_file": str(config_path),
        "account_token_stored": not args.clear,
        "account_token_cleared": bool(args.clear),
        "account_token_env_override": bool(os.getenv("IAP_ACCOUNT_TOKEN")),
    }
    if args.json:
        print(json.dumps(payload, sort_keys=True), file=stdout)
        return EXIT_SUCCESS

    print(f"config_file: {payload['config_file']}", file=stdout)
    print("account_token: cleared" if args.clear else "account_token: stored", file=stdout)
    if payload["account_token_env_override"]:
        print(
            "warning: IAP_ACCOUNT_TOKEN is currently set in the environment and will override "
            "the stored config value in this shell",
            file=stderr,
        )
    return EXIT_SUCCESS


def _run_upgrade_status(*, args, config: CLIConfig, stdout, stderr) -> int:
    try:
        identity_target = _resolve_upgrade_identity_path(args)
    except IdentityError as exc:
        return _print_error(stderr, "identity error", str(exc), code=EXIT_VALIDATION_ERROR)

    identity = None
    identity_path = identity_target
    identity_scope = _classify_identity_scope(identity_target)
    identity_error = None
    try:
        identity, identity_path = load_identity(identity_target)
        identity_scope = _classify_identity_scope(identity_path)
    except IdentityError as exc:
        identity_error = str(exc)

    registry_base = args.registry_base or config.registry_base
    client = _build_registry_client(registry_base=registry_base, config=config)

    registry_info = None
    registry_error = None
    try:
        registry_info = client.get_registry_info()
    except (RegistryRequestError, RegistryUnavailableError) as exc:
        registry_error = str(exc)

    agent_status = None
    if identity is not None and registry_error is None:
        try:
            agent_status = client.get_agent_registry_status(identity.agent_id)
        except (RegistryRequestError, RegistryUnavailableError) as exc:
            registry_error = str(exc)

    local_state = _read_local_state_summary()
    warnings: list[str] = []
    next_actions: list[str] = []

    if identity_scope == "global":
        warnings.append(
            "current identity is global; if you expected a fresh agent for this project, use "
            "`iap-agent init --project-local` before continuing"
        )
    if identity_error:
        warnings.append("no usable local identity was found at the selected path")
        next_actions.append(
            "initialize or point to the correct identity before upgrade-sensitive operations"
        )
    if int(local_state.get("meta_schema_version", 0)) < LOCAL_META_SCHEMA_VERSION:
        warnings.append(
            "local .iap metadata is older than the current SDK expectation; recreate project "
            "metadata with `iap-agent init --project-local` in this folder before future layout "
            "changes ship"
        )
    if registry_info is not None:
        recommended = str(registry_info.get("minimum_recommended_sdk_version", "")).strip()
        if recommended:
            if _parse_version_tuple(_sdk_version()) < _parse_version_tuple(recommended):
                warnings.append(
                    f"installed SDK {_sdk_version()} is older than the registry minimum "
                    f"recommended version {recommended}"
                )
                next_actions.append("upgrade iap-agent before requesting new certificates")
    if registry_error:
        warnings.append(f"registry lookup unavailable: {registry_error}")
        next_actions.append("retry with a reachable registry before upgrade-sensitive flows")

    local_sequence = local_state.get("sequence")
    latest_registry_sequence = (
        agent_status.get("latest_continuity_sequence") if isinstance(agent_status, dict) else None
    )
    if isinstance(local_sequence, int) and isinstance(latest_registry_sequence, int):
        if latest_registry_sequence > local_sequence:
            warnings.append(
                "registry continuity sequence is ahead of local state; local assumptions are stale"
            )
            next_actions.append(
                "resume the same identity and continue from the registry sequence, or initialize "
                "a new project-local identity if this should be a separate agent"
            )

    payload = {
        "sdk_version": _sdk_version(),
        "config_schema_version": config.config_schema_version,
        "local_state_schema_version": LOCAL_STATE_SCHEMA_VERSION,
        "local_meta_schema_version": LOCAL_META_SCHEMA_VERSION,
        "registry_base": registry_base,
        "identity_path": str(identity_path),
        "identity_scope": identity_scope,
        "agent_id": identity.agent_id if identity is not None else None,
        "identity_error": identity_error,
        "local_meta_file": local_state["meta_file"],
        "local_meta_exists": local_state["meta_exists"],
        "local_meta_detected_schema_version": local_state["meta_schema_version"],
        "state_root_file": local_state["state_root_file"],
        "local_state_exists": local_state["exists"],
        "local_state_detected_schema_version": local_state["schema_version"],
        "local_state_sequence": local_sequence,
        "registry_version": registry_info.get("version") if registry_info else None,
        "protocol_version": (
            registry_info.get("protocol_version") if registry_info else PROTOCOL_VERSION
        ),
        "minimum_recommended_sdk_version": (
            registry_info.get("minimum_recommended_sdk_version") if registry_info else None
        ),
        "supported_features": (
            registry_info.get("supported_features") if registry_info else []
        ),
        "has_identity_anchor": agent_status.get("has_identity_anchor") if agent_status else None,
        "latest_registry_sequence": latest_registry_sequence,
        "latest_registry_memory_root": (
            agent_status.get("latest_continuity_memory_root") if agent_status else None
        ),
        "warnings": warnings,
        "next_actions": next_actions,
    }
    if args.json:
        print(json.dumps(payload, sort_keys=True), file=stdout)
        return EXIT_SUCCESS

    print(f"sdk_version: {payload['sdk_version']}", file=stdout)
    print(f"config_schema_version: {payload['config_schema_version']}", file=stdout)
    print(f"local_meta_schema_version: {payload['local_meta_schema_version']}", file=stdout)
    print(f"local_state_schema_version: {payload['local_state_schema_version']}", file=stdout)
    print(f"registry_base: {payload['registry_base']}", file=stdout)
    print(f"identity_path: {payload['identity_path']}", file=stdout)
    print(f"identity_scope: {payload['identity_scope']}", file=stdout)
    print(f"local_meta_file: {payload['local_meta_file']}", file=stdout)
    print(
        "local_meta_detected_schema_version: "
        f"{payload['local_meta_detected_schema_version']}",
        file=stdout,
    )
    print(f"agent_id: {payload['agent_id']}", file=stdout)
    print(f"local_state_sequence: {payload['local_state_sequence']}", file=stdout)
    print(f"registry_version: {payload['registry_version']}", file=stdout)
    print(f"protocol_version: {payload['protocol_version']}", file=stdout)
    print(
        "minimum_recommended_sdk_version: "
        f"{payload['minimum_recommended_sdk_version']}",
        file=stdout,
    )
    print(f"supported_features: {','.join(payload['supported_features'])}", file=stdout)
    print(f"has_identity_anchor: {payload['has_identity_anchor']}", file=stdout)
    print(f"latest_registry_sequence: {payload['latest_registry_sequence']}", file=stdout)
    if warnings:
        print("warnings:", file=stdout)
        for warning in warnings:
            print(f"- {warning}", file=stdout)
    if next_actions:
        print("next_actions:", file=stdout)
        for action in next_actions:
            print(f"- {action}", file=stdout)
    return EXIT_SUCCESS


def _run_upgrade_migrate(*, args, stdout, stderr) -> int:
    try:
        identity_path = _resolve_upgrade_identity_path(args)
    except IdentityError as exc:
        return _print_error(stderr, "identity error", str(exc), code=EXIT_VALIDATION_ERROR)

    project_root = Path.cwd()
    summary, actions = _plan_local_migration(project_root=project_root, identity_path=identity_path)
    warnings: list[str] = []

    if not actions:
        warnings.append("no local migration changes are needed")
    elif not args.apply:
        warnings.append(
            "dry run only; rerun with `iap-agent upgrade migrate --apply` to write changes"
        )

    applied: list[str] = []
    if args.apply and actions:
        applied = _apply_local_migration(
            project_root=project_root,
            identity_path=identity_path,
            actions=actions,
        )

    payload = {
        **summary,
        "apply_requested": bool(args.apply),
        "actions_pending": [] if args.apply else actions,
        "actions_applied": applied,
        "changed": bool(applied),
        "warnings": warnings,
    }
    if args.json:
        print(json.dumps(payload, sort_keys=True), file=stdout)
        return EXIT_SUCCESS

    print(f"project_root: {payload['project_root']}", file=stdout)
    print(f"identity_path: {payload['identity_path']}", file=stdout)
    print(f"meta_file: {payload['meta_file']}", file=stdout)
    print(f"state_root_file: {payload['state_root_file']}", file=stdout)
    print(f"changed: {payload['changed']}", file=stdout)
    if payload["actions_pending"]:
        print("actions_pending:", file=stdout)
        for item in payload["actions_pending"]:
            print(f"- {item}", file=stdout)
    if payload["actions_applied"]:
        print("actions_applied:", file=stdout)
        for item in payload["actions_applied"]:
            print(f"- {item}", file=stdout)
    if warnings:
        print("warnings:", file=stdout)
        for item in warnings:
            print(f"- {item}", file=stdout)
    return EXIT_SUCCESS


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
        return _print_error(stderr, "amcs error", str(exc), code=EXIT_VALIDATION_ERROR)

    payload = {
        "agent_id": result.agent_id,
        "amcs_db_path": result.amcs_db_path,
        "memory_root": result.memory_root,
        "sequence": result.sequence,
    }
    if args.json:
        print(json.dumps(payload, sort_keys=True), file=stdout)
        return EXIT_SUCCESS

    print(f"agent_id: {payload['agent_id']}", file=stdout)
    print(f"amcs_db_path: {payload['amcs_db_path']}", file=stdout)
    print(f"sequence: {payload['sequence']}", file=stdout)
    print(f"memory_root: {payload['memory_root']}", file=stdout)
    return EXIT_SUCCESS


def _run_amcs_append(*, args, config: CLIConfig, stdout, stderr) -> int:
    amcs_db_path = args.amcs_db or config.amcs_db_path

    agent_id = args.agent_id
    if not agent_id:
        try:
            identity, _ = load_identity(args.identity_file)
            agent_id = identity.agent_id
        except IdentityError as exc:
            return _print_error(stderr, "identity error", str(exc), code=EXIT_VALIDATION_ERROR)

    file_paths = list(args.files or [])
    if args.agent_file:
        file_paths.append(args.agent_file)
    if args.soul_file:
        file_paths.append(args.soul_file)
    if not file_paths:
        return _print_error(
            stderr,
            "amcs error",
            "no files provided; use --file (or --agent-file/--soul-file)",
            code=EXIT_VALIDATION_ERROR,
        )

    try:
        result = append_files_to_amcs(
            amcs_db_path=amcs_db_path,
            agent_id=agent_id,
            file_paths=file_paths,
        )
    except AMCSError as exc:
        return _print_error(stderr, "amcs error", str(exc), code=EXIT_VALIDATION_ERROR)

    payload = {
        "agent_id": result.agent_id,
        "amcs_db_path": result.amcs_db_path,
        "sequence": result.sequence,
        "memory_root": result.memory_root,
        "items": [
            {"path": item.path, "sequence": item.sequence, "event_hash": item.event_hash}
            for item in result.items
        ],
    }
    if args.json:
        print(json.dumps(payload, sort_keys=True), file=stdout)
        return EXIT_SUCCESS

    print(f"agent_id: {payload['agent_id']}", file=stdout)
    print(f"amcs_db_path: {payload['amcs_db_path']}", file=stdout)
    print(f"sequence: {payload['sequence']}", file=stdout)
    print(f"memory_root: {payload['memory_root']}", file=stdout)
    for item in payload["items"]:
        print(
            f"appended: path={item['path']} sequence={item['sequence']} hash={item['event_hash']}",
            file=stdout,
        )
    return EXIT_SUCCESS


def _resolve_agent_name(args, config: CLIConfig) -> str:
    value = getattr(args, "agent_name", None)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return config.agent_name


def _run_anchor_issue(*, args, config: CLIConfig, stdout, stderr) -> int:
    try:
        identity, _ = load_identity(args.identity_file)
    except IdentityError as exc:
        return _print_error(stderr, "identity error", str(exc), code=EXIT_VALIDATION_ERROR)

    registry_base = args.registry_base or config.registry_base
    agent_name = _resolve_agent_name(args, config)
    client = _build_registry_client(registry_base=registry_base, config=config)
    payload = sign_identity_anchor_request(
        build_identity_anchor_request(
            agent_public_key_b64=identity.public_key_b64,
            agent_id=identity.agent_id,
            metadata={"agent_name": agent_name},
        ),
        identity.private_key_bytes,
    )

    try:
        response = client.submit_identity_anchor(payload)
    except RegistryRequestError as exc:
        return _print_registry_request_error(stderr, exc, code=EXIT_NETWORK_ERROR)
    except RegistryUnavailableError as exc:
        return _print_error(stderr, "registry error", str(exc), code=EXIT_NETWORK_ERROR)

    request_id = response.get("request_id")
    if not isinstance(request_id, str) or not request_id:
        return _print_error(
            stderr,
            "registry error",
            "invalid response (missing request_id)",
            code=EXIT_NETWORK_ERROR,
        )

    try:
        payment = _resolve_payment_handoff(
            client=client,
            request_id=request_id,
            registry_base=registry_base,
            payment_provider=args.payment_provider,
            status_fetcher=lambda rid: client.get_identity_anchor_status(rid),
            success_url=args.success_url,
            cancel_url=args.cancel_url,
            open_browser=args.open_browser,
        )
    except RegistryUnavailableError as exc:
        return _print_error(stderr, "registry error", str(exc), code=EXIT_NETWORK_ERROR)

    certificate = None
    final_status = response.get("status")
    if args.wait:
        try:
            status = client.wait_for_identity_anchor(
                request_id=request_id,
                timeout=max(1, int(args.timeout_seconds)),
                interval=max(1, int(args.poll_seconds)),
            )
        except RegistryUnavailableError as exc:
            return _print_error(stderr, "registry error", str(exc), code=EXIT_NETWORK_ERROR)
        except SDKTimeoutError as exc:
            return _print_error(stderr, "timeout error", str(exc), code=EXIT_TIMEOUT)
        final_status = status.get("status")
        if final_status == "CERTIFIED":
            try:
                cert_bundle = client.get_identity_anchor_certificate(request_id)
                certificate = cert_bundle.get("certificate")
            except RegistryUnavailableError as exc:
                return _print_error(stderr, "registry error", str(exc), code=EXIT_NETWORK_ERROR)

    output = {
        "registry_base": registry_base,
        "agent_id": identity.agent_id,
        "request_id": request_id,
        "status": final_status,
        "payment": payment,
        "certificate": certificate,
    }
    if args.json:
        print(json.dumps(output, sort_keys=True), file=stdout)
        return EXIT_SUCCESS

    print(f"registry_base: {registry_base}", file=stdout)
    print(f"agent_id: {identity.agent_id}", file=stdout)
    print(f"request_id: {request_id}", file=stdout)
    print(f"status: {final_status}", file=stdout)
    print(f"payment_method: {payment['payment_method']}", file=stdout)
    return EXIT_SUCCESS


def _run_anchor_cert(*, args, config: CLIConfig, stdout, stderr) -> int:
    registry_base = args.registry_base or config.registry_base
    client = _build_registry_client(registry_base=registry_base, config=config)
    try:
        bundle = client.get_identity_anchor_certificate(args.request_id)
    except RegistryUnavailableError as exc:
        return _print_error(stderr, "registry error", str(exc), code=EXIT_NETWORK_ERROR)

    if args.output_file:
        output_path = Path(args.output_file)
    else:
        output_path = (
            Path(config.sessions_dir) / "certificates" / f"identity_anchor_{args.request_id}.json"
        )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(bundle, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    output = {
        "request_id": args.request_id,
        "registry_base": registry_base,
        "output_file": str(output_path),
        "certificate_type": (bundle.get("certificate") or {}).get("certificate_type"),
    }
    if args.json:
        print(json.dumps(output, sort_keys=True), file=stdout)
        return EXIT_SUCCESS
    print(f"request_id: {output['request_id']}", file=stdout)
    print(f"certificate_type: {output['certificate_type']}", file=stdout)
    print(f"output_file: {output['output_file']}", file=stdout)
    return EXIT_SUCCESS


def _run_anchor_state(*, args, config: CLIConfig, stdout, stderr) -> int:
    if args.local_only:
        try:
            identity, _ = load_identity(args.identity_file)
        except IdentityError as exc:
            return _print_error(stderr, "identity error", str(exc), code=EXIT_VALIDATION_ERROR)

        memory_root = args.memory_root
        sequence = args.sequence
        if memory_root is None or sequence is None:
            amcs_db_path = args.amcs_db or config.amcs_db_path
            try:
                amcs = get_amcs_root(amcs_db_path=amcs_db_path, agent_id=identity.agent_id)
            except AMCSError as exc:
                return _print_error(stderr, "amcs error", str(exc), code=EXIT_VALIDATION_ERROR)
            if memory_root is None:
                memory_root = amcs.memory_root
            if sequence is None:
                sequence = amcs.sequence

        local_anchor_id = f"local:{identity.agent_id}:{sequence}"
        payload = {
            "anchor_id": local_anchor_id,
            "agent_id": identity.agent_id,
            "memory_root": memory_root,
            "sequence": sequence,
            "registry_submitted": False,
        }
        if args.json:
            print(json.dumps(payload, sort_keys=True), file=stdout)
            return EXIT_SUCCESS
        print(f"anchor_id: {payload['anchor_id']}", file=stdout)
        print(f"agent_id: {payload['agent_id']}", file=stdout)
        print(f"sequence: {payload['sequence']}", file=stdout)
        print(f"memory_root: {payload['memory_root']}", file=stdout)
        print("registry_submitted: false", file=stdout)
        return EXIT_SUCCESS

    continuity_args = argparse.Namespace(
        registry_base=args.registry_base,
        identity_file=args.identity_file,
        agent_name=_resolve_agent_name(args, config),
        agent_custody_class=args.agent_custody_class,
        memory_root=args.memory_root,
        sequence=args.sequence,
        amcs_db=args.amcs_db,
        sessions_dir=None,
        json=True,
    )
    from io import StringIO
    buf = StringIO()
    rc = _run_continuity_request(args=continuity_args, config=config, stdout=buf, stderr=stderr)
    if rc != EXIT_SUCCESS:
        return rc
    payload = json.loads(buf.getvalue())
    output = {
        "anchor_id": payload["request_id"],
        "agent_id": payload["agent_id"],
        "memory_root": payload["memory_root"],
        "sequence": payload["sequence"],
        "registry_submitted": True,
        "status": payload.get("status"),
    }
    if args.json:
        print(json.dumps(output, sort_keys=True), file=stdout)
    else:
        print(f"anchor_id: {output['anchor_id']}", file=stdout)
        print(f"agent_id: {output['agent_id']}", file=stdout)
        print(f"sequence: {output['sequence']}", file=stdout)
        print(f"memory_root: {output['memory_root']}", file=stdout)
        print(f"status: {output['status']}", file=stdout)
        print("registry_submitted: true", file=stdout)
    return EXIT_SUCCESS


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _resolve_payment_handoff(
    *,
    client: RegistryClient,
    request_id: str,
    registry_base: str,
    payment_provider: str,
    status_fetcher,
    success_url: str | None,
    cancel_url: str | None,
    open_browser: bool,
) -> dict:
    canonical_payment_provider = (
        "lightning-btc" if payment_provider == "lnbits" else payment_provider
    )

    if canonical_payment_provider in {"auto", "stripe"}:
        try:
            stripe_session = client.create_stripe_checkout_session(
                request_id=request_id,
                success_url=success_url,
                cancel_url=cancel_url,
            )
        except RegistryUnavailableError:
            stripe_session = None

        if stripe_session is not None:
            checkout_url = stripe_session.get("checkout_url")
            if open_browser and isinstance(checkout_url, str):
                try:
                    webbrowser.open(checkout_url, new=2)
                except Exception:  # pragma: no cover
                    pass
            return {
                "payment_method": "stripe",
                "method": "stripe",
                "request_id": request_id,
                "registry_base": registry_base,
                "session_id": stripe_session.get("session_id"),
                "checkout_url": checkout_url,
                "payment_status": stripe_session.get("payment_status"),
            }
        if canonical_payment_provider == "stripe":
            raise RegistryUnavailableError("registry request failed: stripe checkout unavailable")

    status = status_fetcher(request_id)
    return {
        "payment_method": "lightning-btc",
        "method": "lightning-btc",
        "provider_backend": "lnbits",
        "request_id": request_id,
        "registry_base": registry_base,
        "status": status.get("status"),
        "lnbits_payment_hash": status.get("lnbits_payment_hash"),
        "lightning_invoice": status.get("lightning_invoice"),
    }


def _run_continuity_request(*, args, config: CLIConfig, stdout, stderr) -> int:
    try:
        identity, _ = load_identity(args.identity_file)
    except IdentityError as exc:
        return _print_error(stderr, "identity error", str(exc), code=EXIT_VALIDATION_ERROR)

    memory_root = args.memory_root
    sequence = args.sequence
    if memory_root is None or sequence is None:
        amcs_db_path = args.amcs_db or config.amcs_db_path
        try:
            amcs = get_amcs_root(amcs_db_path=amcs_db_path, agent_id=identity.agent_id)
        except AMCSError as exc:
            return _print_error(stderr, "amcs error", str(exc), code=EXIT_VALIDATION_ERROR)
        if memory_root is None:
            memory_root = amcs.memory_root
        if sequence is None:
            sequence = amcs.sequence

    agent_name = _resolve_agent_name(args, config)
    manifest = build_identity_manifest(
        {
            "AGENT.md": f"{agent_name}\n",
            "SOUL.md": "Purpose: continuity certification via iap-agent CLI\n",
        }
    )

    payload = build_continuity_request(
        agent_public_key_b64=identity.public_key_b64,
        agent_id=identity.agent_id,
        agent_name=agent_name,
        agent_custody_class=args.agent_custody_class,
        memory_root=memory_root,
        sequence=sequence,
        manifest_version=manifest["manifest_version"],
        manifest_hash=manifest["manifest_hash"],
    )
    signed_payload = sign_continuity_request(payload, identity.private_key_bytes)

    registry_base = args.registry_base or config.registry_base
    client = _build_registry_client(registry_base=registry_base, config=config)
    try:
        response = client.submit_continuity_request(signed_payload)
    except RegistryRequestError as exc:
        if (
            exc.status_code == 409
            and isinstance(exc.detail, str)
            and "latest registry sequence is" in exc.detail
        ):
            return _print_error(
                stderr,
                "registry error",
                (
                    f"{exc.detail}. Run `iap-agent registry status --agent-id {identity.agent_id}` "
                    "to inspect the current registry state, or initialize a new identity."
                ),
                code=EXIT_NETWORK_ERROR,
            )
        return _print_registry_request_error(stderr, exc, code=EXIT_NETWORK_ERROR)
    except RegistryUnavailableError as exc:
        return _print_error(stderr, "registry error", str(exc), code=EXIT_NETWORK_ERROR)

    request_id = response.get("request_id")
    if not isinstance(request_id, str) or not request_id:
        return _print_error(
            stderr,
            "registry error",
            "invalid response (missing request_id)",
            code=EXIT_NETWORK_ERROR,
        )

    session_payload = {
        "created_at": _utc_now_iso(),
        "registry_base": registry_base,
        "agent_id": identity.agent_id,
        "request_id": request_id,
        "request_payload": signed_payload,
        "response": response,
    }
    sessions_dir = args.sessions_dir or config.sessions_dir
    try:
        session_path = save_session_record(
            sessions_dir=sessions_dir,
            request_id=request_id,
            payload=session_payload,
        )
    except SessionError as exc:
        return _print_error(stderr, "session error", str(exc), code=EXIT_VALIDATION_ERROR)

    output = {
        "request_id": request_id,
        "status": response.get("status"),
        "agent_id": identity.agent_id,
        "memory_root": memory_root,
        "sequence": sequence,
        "session_file": str(session_path),
        "registry_base": registry_base,
        "payment": {
            "lnbits_payment_hash": response.get("lnbits_payment_hash"),
            "lightning_invoice": response.get("lightning_invoice"),
            "amount_sats": response.get("amount_sats"),
        },
    }
    if args.json:
        print(json.dumps(output, sort_keys=True), file=stdout)
        return EXIT_SUCCESS

    print(f"request_id: {output['request_id']}", file=stdout)
    print(f"status: {output['status']}", file=stdout)
    print(f"agent_id: {output['agent_id']}", file=stdout)
    print(f"memory_root: {output['memory_root']}", file=stdout)
    print(f"sequence: {output['sequence']}", file=stdout)
    print(f"session_file: {output['session_file']}", file=stdout)
    print(f"registry_base: {output['registry_base']}", file=stdout)
    return EXIT_SUCCESS


def _run_continuity_pay(*, args, config: CLIConfig, stdout, stderr) -> int:
    registry_base = args.registry_base or config.registry_base
    client = _build_registry_client(registry_base=registry_base, config=config)

    try:
        output = _resolve_payment_handoff(
            client=client,
            request_id=args.request_id,
            registry_base=registry_base,
            payment_provider=args.payment_provider,
            status_fetcher=client.get_continuity_status,
            success_url=args.success_url,
            cancel_url=args.cancel_url,
            open_browser=args.open_browser,
        )
    except RegistryUnavailableError as exc:
        return _print_error(stderr, "registry error", str(exc), code=EXIT_NETWORK_ERROR)

    if args.json:
        print(json.dumps(output, sort_keys=True), file=stdout)
        return EXIT_SUCCESS

    print(f"payment_method: {output['payment_method']}", file=stdout)
    print(f"request_id: {output['request_id']}", file=stdout)
    if output["payment_method"] == "stripe":
        print(f"checkout_url: {output.get('checkout_url')}", file=stdout)
        print(f"session_id: {output.get('session_id')}", file=stdout)
    else:
        print(f"status: {output.get('status')}", file=stdout)
        print(f"lnbits_payment_hash: {output.get('lnbits_payment_hash')}", file=stdout)
        print(f"lightning_invoice: {output.get('lightning_invoice')}", file=stdout)
    return EXIT_SUCCESS


def _run_continuity_wait(*, args, config: CLIConfig, stdout, stderr) -> int:
    registry_base = args.registry_base or config.registry_base
    timeout_seconds = max(1, int(args.timeout_seconds))
    poll_seconds = max(1, int(args.poll_seconds))
    client = _build_registry_client(registry_base=registry_base, config=config)

    deadline = time.time() + timeout_seconds
    latest = None
    while time.time() < deadline:
        try:
            latest = client.get_continuity_status(args.request_id)
        except RegistryUnavailableError as exc:
            return _print_error(stderr, "registry error", str(exc), code=EXIT_NETWORK_ERROR)
        status = latest.get("status")
        if status == "CERTIFIED":
            break
        time.sleep(poll_seconds)

    if not latest or latest.get("status") != "CERTIFIED":
        return _print_error(
            stderr,
            "timeout error",
            "waiting for CERTIFIED status",
            code=EXIT_TIMEOUT,
        )

    output = {
        "request_id": args.request_id,
        "registry_base": registry_base,
        "status": latest.get("status"),
        "paid_at": latest.get("paid_at"),
    }
    if args.json:
        print(json.dumps(output, sort_keys=True), file=stdout)
        return EXIT_SUCCESS
    print(f"request_id: {output['request_id']}", file=stdout)
    print(f"status: {output['status']}", file=stdout)
    print(f"paid_at: {output['paid_at']}", file=stdout)
    return EXIT_SUCCESS


def _run_continuity_cert(*, args, config: CLIConfig, stdout, stderr) -> int:
    registry_base = args.registry_base or config.registry_base
    client = _build_registry_client(registry_base=registry_base, config=config)
    try:
        bundle = client.get_continuity_certificate(args.request_id)
    except RegistryUnavailableError as exc:
        return _print_error(stderr, "registry error", str(exc), code=EXIT_NETWORK_ERROR)

    if args.output_file:
        output_path = Path(args.output_file)
    else:
        output_path = Path(config.sessions_dir) / "certificates" / f"{args.request_id}.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(bundle, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    output = {
        "request_id": args.request_id,
        "registry_base": registry_base,
        "output_file": str(output_path),
        "certificate_type": (bundle.get("certificate") or {}).get("certificate_type"),
    }
    if args.json:
        print(json.dumps(output, sort_keys=True), file=stdout)
        return EXIT_SUCCESS
    print(f"request_id: {output['request_id']}", file=stdout)
    print(f"certificate_type: {output['certificate_type']}", file=stdout)
    print(f"output_file: {output['output_file']}", file=stdout)
    return EXIT_SUCCESS


def _run_verify(*, args, config: CLIConfig, stdout, stderr) -> int:
    registry_public_key_b64 = args.registry_public_key_b64 or config.registry_public_key_b64
    if registry_public_key_b64 is None:
        if args.profile == "strict":
            return _print_error(
                stderr,
                "verify error",
                (
                    "strict profile requires a pinned registry key; provide "
                    "--registry-public-key-b64 or set cli.registry_public_key_b64 in config"
                ),
                code=EXIT_VALIDATION_ERROR,
            )
        registry_base = args.registry_base or config.registry_base
        client = _build_registry_client(registry_base=registry_base, config=config)
        try:
            key_payload = client.get_public_registry_key()
        except RegistryUnavailableError as exc:
            return _print_error(stderr, "registry error", str(exc), code=EXIT_NETWORK_ERROR)
        registry_public_key_b64 = key_payload.get("public_key_b64")
        if not isinstance(registry_public_key_b64, str) or not registry_public_key_b64:
            return _print_error(
                stderr,
                "registry error",
                "missing public_key_b64 in registry response",
                code=EXIT_NETWORK_ERROR,
            )

    witnesses = None
    if args.witness_bundle:
        try:
            witnesses = json.loads(Path(args.witness_bundle).read_text(encoding="utf-8"))
        except Exception as exc:
            return _print_error(
                stderr,
                "verify error",
                f"invalid witness bundle: {exc}",
                code=EXIT_VALIDATION_ERROR,
            )

    ok, reason = verify_certificate_file(
        args.certificate_json,
        registry_public_key_b64=registry_public_key_b64,
        profile=args.profile,
        identity_anchor_path=args.identity_anchor,
        previous_certificate_path=args.previous_certificate,
        witness_bundle=witnesses,
        min_witnesses=args.min_witnesses,
    )
    if args.json:
        print(json.dumps({"ok": ok, "reason": reason}, sort_keys=True), file=stdout)
    else:
        if ok:
            print("Continuity verified ✓", file=stdout)
            print("No fork detected.", file=stdout)
            print("State root matches registry anchor.", file=stdout)
            if reason and reason != "ok":
                print(f"detail: {reason}", file=stdout)
        else:
            print(reason, file=stdout)
    return EXIT_SUCCESS if ok else EXIT_VERIFICATION_FAILED


def _print_step(stdout, *, index: int, total: int, title: str) -> None:
    print(f"Step {index}/{total}: {title}", file=stdout)


def _run_flow(*, args, config: CLIConfig, stdout, stderr) -> int:
    total_steps = 8
    agent_name = _resolve_agent_name(args, config)
    registry_base = args.registry_base or config.registry_base
    timeout_seconds = max(1, int(args.request_timeout_seconds))
    poll_seconds = max(1, int(args.poll_seconds))

    _print_step(stdout, index=1, total=total_steps, title="ensuring local identity")
    try:
        identity, _, _ = load_or_create_identity(args.identity_file)
    except IdentityError as exc:
        return _print_error(stderr, "identity error", str(exc), code=EXIT_VALIDATION_ERROR)

    client = _build_registry_client(registry_base=registry_base, config=config)

    _print_step(stdout, index=2, total=total_steps, title="ensuring identity anchor")
    try:
        anchor_response = client.submit_identity_anchor(
            {
                "agent_public_key_b64": identity.public_key_b64,
                "agent_id": identity.agent_id,
                "metadata": {"agent_name": agent_name},
            }
        )
    except RegistryUnavailableError as exc:
        return _print_error(stderr, "registry error", str(exc), code=EXIT_NETWORK_ERROR)

    anchor_request_id = anchor_response.get("request_id")
    if not isinstance(anchor_request_id, str) or not anchor_request_id:
        return _print_error(
            stderr,
            "registry error",
            "invalid identity-anchor response (missing request_id)",
            code=EXIT_NETWORK_ERROR,
        )
    try:
        anchor_payment = _resolve_payment_handoff(
            client=client,
            request_id=anchor_request_id,
            registry_base=registry_base,
            payment_provider=args.payment_provider,
            status_fetcher=client.get_identity_anchor_status,
            success_url=None,
            cancel_url=None,
            open_browser=args.open_browser,
        )
        client.wait_for_identity_anchor(
            request_id=anchor_request_id,
            timeout=timeout_seconds,
            interval=poll_seconds,
        )
    except RegistryUnavailableError as exc:
        return _print_error(stderr, "registry error", str(exc), code=EXIT_NETWORK_ERROR)
    except Exception as exc:
        return _print_error(stderr, "timeout error", str(exc), code=EXIT_TIMEOUT)

    _print_step(stdout, index=3, total=total_steps, title="computing AMCS root and sequence")
    memory_root = args.memory_root
    sequence = args.sequence
    if memory_root is None or sequence is None:
        amcs_db_path = args.amcs_db or config.amcs_db_path
        try:
            amcs = get_amcs_root(amcs_db_path=amcs_db_path, agent_id=identity.agent_id)
        except AMCSError as exc:
            return _print_error(stderr, "amcs error", str(exc), code=EXIT_VALIDATION_ERROR)
        if memory_root is None:
            memory_root = amcs.memory_root
        if sequence is None:
            sequence = amcs.sequence

    _print_step(stdout, index=4, total=total_steps, title="submitting continuity request")
    manifest = build_identity_manifest(
        {
            "AGENT.md": f"{agent_name}\n",
            "SOUL.md": "Purpose: continuity certification via iap-agent CLI\n",
        }
    )
    payload = build_continuity_request(
        agent_public_key_b64=identity.public_key_b64,
        agent_id=identity.agent_id,
        agent_name=agent_name,
        agent_custody_class=args.agent_custody_class,
        memory_root=memory_root,
        sequence=sequence,
        manifest_version=manifest["manifest_version"],
        manifest_hash=manifest["manifest_hash"],
    )
    signed_payload = sign_continuity_request(payload, identity.private_key_bytes)
    try:
        request_response = client.submit_continuity_request(signed_payload)
    except RegistryUnavailableError as exc:
        return _print_error(stderr, "registry error", str(exc), code=EXIT_NETWORK_ERROR)

    request_id = request_response.get("request_id")
    if not isinstance(request_id, str) or not request_id:
        return _print_error(
            stderr,
            "registry error",
            "invalid response (missing request_id)",
            code=EXIT_NETWORK_ERROR,
        )

    if args.output_dir:
        output_dir = Path(args.output_dir)
    else:
        output_dir = Path(config.sessions_dir) / "flows" / request_id
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        save_session_record(
            sessions_dir=str(output_dir),
            request_id=request_id,
            payload={
                "created_at": _utc_now_iso(),
                "registry_base": registry_base,
                "agent_id": identity.agent_id,
                "request_id": request_id,
                "request_payload": signed_payload,
                "response": request_response,
            },
        )
    except SessionError as exc:
        return _print_error(stderr, "session error", str(exc), code=EXIT_VALIDATION_ERROR)

    _print_step(stdout, index=5, total=total_steps, title="resolving payment handoff")
    try:
        payment_info = _resolve_payment_handoff(
            client=client,
            request_id=request_id,
            registry_base=registry_base,
            payment_provider=args.payment_provider,
            status_fetcher=client.get_continuity_status,
            success_url=None,
            cancel_url=None,
            open_browser=args.open_browser,
        )
    except RegistryUnavailableError as exc:
        return _print_error(stderr, "registry error", str(exc), code=EXIT_NETWORK_ERROR)

    _print_step(stdout, index=6, total=total_steps, title="waiting for certification")
    deadline = time.time() + timeout_seconds
    latest_status = None
    while time.time() < deadline:
        try:
            latest_status = client.get_continuity_status(request_id)
        except RegistryUnavailableError as exc:
            return _print_error(stderr, "registry error", str(exc), code=EXIT_NETWORK_ERROR)
        if latest_status.get("status") == "CERTIFIED":
            break
        time.sleep(poll_seconds)
    if not latest_status or latest_status.get("status") != "CERTIFIED":
        return _print_error(
            stderr,
            "timeout error",
            "waiting for CERTIFIED status",
            code=EXIT_TIMEOUT,
        )

    _print_step(stdout, index=7, total=total_steps, title="fetching certificate")
    try:
        cert_bundle = client.get_continuity_certificate(request_id)
    except RegistryUnavailableError as exc:
        return _print_error(stderr, "registry error", str(exc), code=EXIT_NETWORK_ERROR)
    cert_path = output_dir / "certificate.json"
    cert_path.write_text(json.dumps(cert_bundle, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    _print_step(stdout, index=8, total=total_steps, title="verifying certificate")
    try:
        key_payload = client.get_public_registry_key()
    except RegistryUnavailableError as exc:
        return _print_error(stderr, "registry error", str(exc), code=EXIT_NETWORK_ERROR)
    registry_public_key_b64 = key_payload.get("public_key_b64")
    if not isinstance(registry_public_key_b64, str) or not registry_public_key_b64:
        return _print_error(
            stderr,
            "registry error",
            "missing public_key_b64 in registry response",
            code=EXIT_NETWORK_ERROR,
        )

    ok, reason = verify_certificate_file(
        str(cert_path),
        registry_public_key_b64=registry_public_key_b64,
    )
    if not ok:
        return _print_error(
            stderr,
            "verification failed",
            reason,
            code=EXIT_VERIFICATION_FAILED,
        )

    flow_summary = {
        "request_id": request_id,
        "agent_id": identity.agent_id,
        "registry_base": registry_base,
        "memory_root": memory_root,
        "sequence": sequence,
        "status": latest_status.get("status"),
        "payment": payment_info,
        "anchor_payment": anchor_payment,
        "certificate_file": str(cert_path),
        "output_dir": str(output_dir),
        "verify_result": reason,
    }
    summary_path = output_dir / "flow_summary.json"
    summary_path.write_text(
        json.dumps(flow_summary, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )

    if args.json:
        print(json.dumps(flow_summary, sort_keys=True), file=stdout)
    else:
        print(f"request_id: {request_id}", file=stdout)
        print(f"status: {latest_status.get('status')}", file=stdout)
        print(f"certificate_file: {cert_path}", file=stdout)
        print(f"output_dir: {output_dir}", file=stdout)
    return EXIT_SUCCESS


def main(argv: Sequence[str] | None = None, *, stdout=sys.stdout, stderr=sys.stderr) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        config = load_cli_config(args.config)
    except ConfigError as exc:
        return _print_error(stderr, "config error", str(exc), code=EXIT_VALIDATION_ERROR)

    _emit_beta_warning(config, args.command, stderr)

    if args.command == "version":
        return _run_version(config=config, as_json=args.json, stdout=stdout)

    if args.command == "init":
        return _run_init(args=args, stdout=stdout, stderr=stderr)

    if args.command == "setup":
        return _run_setup(args=args, stdout=stdout, stderr=stderr)

    if args.command == "track":
        return _run_track(args=args, config=config, stdout=stdout, stderr=stderr)

    if args.command == "commit":
        return _run_commit(args=args, config=config, stdout=stdout, stderr=stderr)

    if args.command == "registry":
        if args.registry_command == "status":
            return _run_registry_status(args=args, config=config, stdout=stdout, stderr=stderr)
        if args.registry_command == "check":
            return _run_registry_check(args=args, config=config, stdout=stdout, stderr=stderr)
        if args.registry_command == "set-base":
            return _run_registry_set_base(args=args, stdout=stdout, stderr=stderr)
        if args.registry_command == "set-api-key":
            return _run_registry_set_api_key(args=args, stdout=stdout, stderr=stderr)
        return _coming_soon(path=f"registry {args.registry_command}", stdout=stdout)

    if args.command == "account":
        if args.account_command == "usage":
            return _run_account_usage(args=args, config=config, stdout=stdout, stderr=stderr)
        if args.account_command == "set-token":
            return _run_account_set_token(args=args, stdout=stdout, stderr=stderr)
        return _coming_soon(path=f"account {args.account_command}", stdout=stdout)

    if args.command == "upgrade":
        if args.upgrade_command == "status":
            return _run_upgrade_status(args=args, config=config, stdout=stdout, stderr=stderr)
        if args.upgrade_command == "migrate":
            return _run_upgrade_migrate(args=args, stdout=stdout, stderr=stderr)
        return _coming_soon(path=f"upgrade {args.upgrade_command}", stdout=stdout)

    if args.command == "verify":
        return _run_verify(args=args, config=config, stdout=stdout, stderr=stderr)

    if args.command == "amcs":
        if args.amcs_command == "root":
            return _run_amcs_root(args=args, config=config, stdout=stdout, stderr=stderr)
        if args.amcs_command == "append":
            return _run_amcs_append(args=args, config=config, stdout=stdout, stderr=stderr)
        return _coming_soon(path=f"amcs {args.amcs_command}", stdout=stdout)

    if args.command == "anchor":
        if args.anchor_command is None or args.anchor_command == "state":
            return _run_anchor_state(args=args, config=config, stdout=stdout, stderr=stderr)
        if args.anchor_command == "issue":
            return _run_anchor_issue(args=args, config=config, stdout=stdout, stderr=stderr)
        if args.anchor_command == "identity":
            return _run_anchor_issue(args=args, config=config, stdout=stdout, stderr=stderr)
        if args.anchor_command == "cert":
            return _run_anchor_cert(args=args, config=config, stdout=stdout, stderr=stderr)
        return _coming_soon(path=f"anchor {args.anchor_command}", stdout=stdout)

    if args.command == "continuity":
        if args.continuity_command == "request":
            return _run_continuity_request(args=args, config=config, stdout=stdout, stderr=stderr)
        if args.continuity_command == "pay":
            return _run_continuity_pay(args=args, config=config, stdout=stdout, stderr=stderr)
        if args.continuity_command == "wait":
            return _run_continuity_wait(args=args, config=config, stdout=stdout, stderr=stderr)
        if args.continuity_command == "cert":
            return _run_continuity_cert(args=args, config=config, stdout=stdout, stderr=stderr)
        return _coming_soon(path=f"continuity {args.continuity_command}", stdout=stdout)

    if args.command == "flow":
        if args.flow_command == "run":
            return _run_flow(args=args, config=config, stdout=stdout, stderr=stderr)
        return _coming_soon(path=f"flow {args.flow_command}", stdout=stdout)

    print("unknown command", file=stderr)
    return EXIT_NETWORK_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
