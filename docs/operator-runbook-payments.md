# Operator Runbook: Entitlements, Stripe, and Lightning/OpenNode

This runbook gives exact command sequences for:

1. Identity-anchor request + certification via API-key entitlements
2. Identity-anchor request + payment + certification
3. Continuity request + payment + certification
4. Continuity record fetch + offline verify

Use the same local identity for all steps.

## Preconditions

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e ".[dev]"
iap-agent version
```

Set your registry URL:

```bash
export REGISTRY_BASE="http://localhost:8080"
```

Optional: set an entitlement API key for quota-based issuance. When this value is present,
`iap-agent` sends it as `x-iap-api-key` automatically on registry requests:

```bash
export IAP_REGISTRY_API_KEY="iap_live_replace_me"
```

Equivalent config-file form:

```toml
[cli]
registry_api_key = "iap_live_replace_me"
```

Create/load local identity:

```bash
iap-agent init --project-local --show-public --json
```

## A) API-key entitlement path (preferred for beta/quota users)

If `IAP_REGISTRY_API_KEY` (or `registry_api_key` in config) is set and the key still has quota,
identity-anchor and continuity requests can certify immediately without opening a payment flow.

### 1) Create identity-anchor request

```bash
iap-agent anchor issue --registry-base "$REGISTRY_BASE" --agent-name "Atlas" --json
```

If quota is available, the response status may already be `CERTIFIED`.

### 2) Create continuity request

```bash
iap-agent continuity request --registry-base "$REGISTRY_BASE" --json
```

If quota is available, the response status may already be `CERTIFIED`.

### 3) Fetch record and verify

```bash
iap-agent continuity cert --registry-base "$REGISTRY_BASE" --request-id <request-id> --output-file ./continuity_record.json --json
REGISTRY_PUBLIC_KEY_B64="$(curl -s "$REGISTRY_BASE/registry/public-key" | jq -r .public_key_b64)"
iap-agent verify ./continuity_record.json --registry-public-key-b64 "$REGISTRY_PUBLIC_KEY_B64" --json
```

## B) Stripe path (explicit)

### 1) Create identity-anchor request and open Stripe checkout

```bash
iap-agent anchor issue --registry-base "$REGISTRY_BASE" --agent-name "Atlas" --payment-provider stripe --open-browser --json
```

Copy `request_id` from output, then wait:

```bash
iap-agent anchor issue --registry-base "$REGISTRY_BASE" --agent-name "Atlas" --payment-provider stripe --wait --timeout-seconds 600 --poll-seconds 5 --json
```

### 2) Create continuity request

```bash
iap-agent continuity request --registry-base "$REGISTRY_BASE" --json
```

Copy `request_id` from output.

### 3) Pay continuity with Stripe

```bash
iap-agent continuity pay --registry-base "$REGISTRY_BASE" --request-id <request-id> --payment-provider stripe --open-browser --json
```

### 4) Wait, fetch continuity record, verify

```bash
iap-agent continuity wait --registry-base "$REGISTRY_BASE" --request-id <request-id> --timeout-seconds 600 --poll-seconds 5 --json
iap-agent continuity cert --registry-base "$REGISTRY_BASE" --request-id <request-id> --output-file ./continuity_record.json --json
REGISTRY_PUBLIC_KEY_B64="$(curl -s "$REGISTRY_BASE/registry/public-key" | jq -r .public_key_b64)"
iap-agent verify ./continuity_record.json --registry-public-key-b64 "$REGISTRY_PUBLIC_KEY_B64" --json
```

## C) Lightning/OpenNode path (explicit)

### 1) Create identity-anchor request and get LN invoice

```bash
iap-agent anchor issue --registry-base "$REGISTRY_BASE" --agent-name "Atlas" --payment-provider lightning-btc --json
```

Use `payment.lightning_invoice` from output in your Lightning wallet.

### 2) Wait for identity-anchor certification

```bash
iap-agent anchor issue --registry-base "$REGISTRY_BASE" --agent-name "Atlas" --payment-provider lightning-btc --wait --timeout-seconds 600 --poll-seconds 5 --json
```

### 3) Create continuity request

```bash
iap-agent continuity request --registry-base "$REGISTRY_BASE" --json
```

Copy `request_id` from output.

### 4) Get LN payment handoff for continuity

```bash
iap-agent continuity pay --registry-base "$REGISTRY_BASE" --request-id <request-id> --payment-provider lightning-btc --json
```

Pay `lightning_invoice` from the output.

### 5) Wait, fetch continuity record, verify

```bash
iap-agent continuity wait --registry-base "$REGISTRY_BASE" --request-id <request-id> --timeout-seconds 600 --poll-seconds 5 --json
iap-agent continuity cert --registry-base "$REGISTRY_BASE" --request-id <request-id> --output-file ./continuity_record.json --json
REGISTRY_PUBLIC_KEY_B64="$(curl -s "$REGISTRY_BASE/registry/public-key" | jq -r .public_key_b64)"
iap-agent verify ./continuity_record.json --registry-public-key-b64 "$REGISTRY_PUBLIC_KEY_B64" --json
```

## Notes

- If an API key is configured and has remaining quota, it takes precedence over the payment path.
- If the API key is missing, invalid, or out of quota, the registry returns a structured error
  instead of silently falling back to payment.
- `--payment-provider auto` tries Stripe first and falls back to Lightning/OpenNode.
- `iap-agent flow run` now also pays/waits for identity-anchor before continuity:

```bash
iap-agent flow run --registry-base "$REGISTRY_BASE" --payment-provider auto --open-browser --output-dir ./artifacts --json
```
