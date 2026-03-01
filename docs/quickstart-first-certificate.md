# Quickstart: First Continuity Record in 10 Minutes

Run from your `iap-sdk` environment.

## 1) Install

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e ".[dev]"
```

## 2) Initialize local identity

```bash
iap-agent init --project-local --show-public --json
iap-agent upgrade status --registry-base https://registry.ia-protocol.com --json
iap-agent upgrade migrate --json
```

Use `--project-local` for a fresh agent. It creates a new identity in this folder instead of
reusing the global identity at `~/.iap_agent/identity/ed25519.json`.

If you were given an account token for quota-based access, set it once before running the rest of
the flow:

```bash
export IAP_ACCOUNT_TOKEN="iapt_live_optional"
iap-agent account usage --registry-base https://registry.ia-protocol.com --json
```

## 3) Ensure identity anchor at registry

```bash
iap-agent anchor issue --registry-base https://registry.ia-protocol.com --agent-name "Atlas"
```

## 4) Create continuity request from local AMCS

```bash
iap-agent continuity request --registry-base https://registry.ia-protocol.com --json
```

If the registry replies with:

- `ledger_sequence must strictly increase; latest registry sequence is X`

inspect the current registry state for your agent:

```bash
iap-agent registry status --registry-base https://registry.ia-protocol.com --json
```

That means either:

- you are continuing an existing agent and need a higher continuity sequence, or
- you intended a fresh agent and should re-run `iap-agent init --project-local ...` in a clean
  folder to create a new keypair and `agent_id`.

## 5) Payment + certification + continuity record

```bash
iap-agent continuity pay --request-id <request-id>
iap-agent continuity wait --request-id <request-id>
iap-agent continuity cert --request-id <request-id> --output-file ./continuity_record.json --json
```

## 6) Offline verify certificate

```bash
REGISTRY_PUBLIC_KEY_B64="$(curl -s https://registry.ia-protocol.com/registry/public-key | jq -r .public_key_b64)"
iap-agent verify ./continuity_record.json --registry-public-key-b64 "$REGISTRY_PUBLIC_KEY_B64"
```

The registry public key is the trust anchor for offline verification. With that pinned locally, the
certificate signature can be validated without calling the registry during verification.

## One-command path

```bash
iap-agent flow run --registry-base https://registry.ia-protocol.com --output-dir ./artifacts
```
