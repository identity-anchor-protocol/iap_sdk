# iap-sdk

Python SDK for Identity Anchor Protocol (IAP) request signing, state continuity tracking, and offline verification.

## Install

Published package:

```bash
python -m pip install -U pip
python -m pip install iap-agent
iap version
iap-agent version
```

Local editable development install:

```bash
python -m pip install -e ".[dev]"
```

For clean public installs, use `iap-agent >= 0.1.5`. That is the first release that depends on the
correct PyPI package name for AMCS (`iap-amcs`).

## What this package provides

- Deterministic `agent_id` derivation from Ed25519 public keys
- Canonical request builders and signers for continuity, lineage, key rotation
- Registry API client helpers
- Offline certificate verification (including identity-anchor checks)
- Liveness and transparency helper utilities

IAP tracks agent state evolution.
It does not reduce LLM sampling randomness.

## Quick example

```python
from iap_sdk import build_continuity_request, sign_continuity_request

payload = build_continuity_request(
    agent_public_key_b64="...",
    agent_id="ed25519:...",
    memory_root="a" * 64,
    sequence=1,
    manifest_version="IAM-1",
    manifest_hash="b" * 64,
)
signed = sign_continuity_request(payload, private_key_bytes=b"...")
```

## Run tests

```bash
pytest
```

## Reproducible install

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e ".[dev]"
iap-agent version
```

For a clean-room install smoke test, run:

```bash
./scripts/smoke_install.sh
```

Run the hardened closeout verification script against a live registry and issued records:

```bash
python scripts/final_live_test.py \
  --registry-base https://registry.ia-protocol.com \
  --identity-anchor ./identity_anchor_record.json \
  --continuity-record ./continuity_record.json
```

Validate CLI snippets in docs:

```bash
python scripts/validate_doc_commands.py
```

## CLI (beta)

Install editable and run:

```bash
python -m pip install -e ".[dev]"
iap version
iap init
iap track
iap anchor
iap commit "updated agent objective"
iap verify ./continuity_record.json --registry-public-key-b64 <key>

# Legacy CLI remains supported in v0.1.x:
iap-agent continuity request --registry-base https://registry.ia-protocol.com --json
iap-agent registry status --registry-base https://registry.ia-protocol.com --json
```

### Fresh identity vs existing identity

- `iap-agent init --project-local` creates a new identity in the current project at
  `./.iap/identity/ed25519.json`.
- `iap-agent init` without `--project-local` uses the global identity at
  `~/.iap_agent/identity/ed25519.json` if it already exists.

Use `--project-local` when you want a genuinely new agent. Use the global identity only when you
intentionally want to continue the same agent across different folders.

### Upgrade safety

- `python -m pip install -U iap-agent` updates the SDK package only; it does not change `agent_id`.
- `iap-agent upgrade status --json` checks the current identity path, local state sequence, and
  registry capabilities before you request new certificates.
- `iap-agent upgrade migrate --json` previews safe local `.iap` metadata migrations; rerun with
  `--apply` only when you want the SDK to normalize local metadata/schema markers.
- Routine software upgrades should normally continue with a new continuity event, not lineage.

If a continuity request fails with:

- `ledger_sequence must strictly increase; latest registry sequence is X`

inspect the current registry state:

```bash
iap-agent registry status --registry-base https://registry.ia-protocol.com --json
```

That shows whether this `agent_id` already has an identity anchor and what the latest certified
continuity sequence is.

### CLI exit codes

- `0`: success
- `1`: validation/config/user input error
- `2`: network/registry unavailable
- `3`: timeout waiting for certification
- `4`: verification failure

### Version compatibility

See `/COMPATIBILITY.md` for pinned SDK/protocol/registry API assumptions.

## Support / Feedback

If you hit a bug, an upgrade issue, or have recommendations for improvement, contact:

- `admin@ia-protocol.com`

## Docs

- `/docs/quickstart-first-certificate.md`
- `/docs/e2e-user-walkthrough.md`
- `/docs/e2e-dev-local-walkthrough.md`
- `/docs/operator-runbook-payments.md`
- `/docs/local-amcs-privacy-model.md`
- `/docs/lnbits-vs-stripe-flow.md`
- `/docs/troubleshooting.md`
- `/docs/migration-cli-first.md`
- `/docs/transition-terminology.md`
- `/docs/final-live-test.md`
- `/docs/upgrade-guide.md`
- `/docs/security-assumptions.md`
- `/examples/state-drift-demo/README.md`
- `/RELEASE.md`
- `/RELEASE_NOTES_TEMPLATE.md`

## Drift demo

Run the transition demo in under 5 minutes:

```bash
python examples/state-drift-demo/demo.py
```

Expected:
- `verify_before_ok=True`
- `verify_after_ok=False`

### Beta mode config

Default config path:

`~/.iap_agent/config.toml`

Example:

```toml
beta_mode = true
maturity_level = "beta"
registry_base = "https://registry.ia-protocol.com"
registry_api_key = "iap_live_optional"
account_token = "iapt_live_optional"
amcs_db_path = "./amcs.db"
```

To bootstrap just the account token without editing TOML manually:

```bash
iap-agent account set-token --token "iapt_live_optional"
```

Environment override:

```bash
export IAP_REGISTRY_BASE="https://registry.ia-protocol.com"
export IAP_REGISTRY_API_KEY="iap_live_optional"
export IAP_ACCOUNT_TOKEN="iapt_live_optional"
```

With an account token configured, you can inspect your current quota usage:

```bash
iap-agent account usage --json
```

The CLI also writes the latest successful account usage response to:

- `<sessions_dir>/account_usage_last.json`

Local development override example:

```toml
registry_base = "http://localhost:8080"
```
