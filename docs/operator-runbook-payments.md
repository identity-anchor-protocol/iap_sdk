# Operator Runbook: Stripe and LNBits End-to-End

This runbook gives exact command sequences for:

1. Identity-anchor request + payment + certification
2. Continuity request + payment + certification
3. Certificate fetch + offline verify

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

Create/load local identity:

```bash
iap-agent init --show-public --json
```

## A) Stripe path (explicit)

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

### 4) Wait, fetch certificate, verify

```bash
iap-agent continuity wait --registry-base "$REGISTRY_BASE" --request-id <request-id> --timeout-seconds 600 --poll-seconds 5 --json
iap-agent continuity cert --registry-base "$REGISTRY_BASE" --request-id <request-id> --output-file ./certificate.json --json
iap-agent verify ./certificate.json --registry-base "$REGISTRY_BASE" --json
```

## B) LNBits path (explicit)

### 1) Create identity-anchor request and get LN invoice

```bash
iap-agent anchor issue --registry-base "$REGISTRY_BASE" --agent-name "Atlas" --payment-provider lnbits --json
```

Use `payment.lightning_invoice` from output in your Lightning wallet.

### 2) Wait for identity-anchor certification

```bash
iap-agent anchor issue --registry-base "$REGISTRY_BASE" --agent-name "Atlas" --payment-provider lnbits --wait --timeout-seconds 600 --poll-seconds 5 --json
```

### 3) Create continuity request

```bash
iap-agent continuity request --registry-base "$REGISTRY_BASE" --json
```

Copy `request_id` from output.

### 4) Get LN payment handoff for continuity

```bash
iap-agent continuity pay --registry-base "$REGISTRY_BASE" --request-id <request-id> --payment-provider lnbits --json
```

Pay `lightning_invoice` from the output.

### 5) Wait, fetch certificate, verify

```bash
iap-agent continuity wait --registry-base "$REGISTRY_BASE" --request-id <request-id> --timeout-seconds 600 --poll-seconds 5 --json
iap-agent continuity cert --registry-base "$REGISTRY_BASE" --request-id <request-id> --output-file ./certificate.json --json
iap-agent verify ./certificate.json --registry-base "$REGISTRY_BASE" --json
```

## Notes

- `--payment-provider auto` tries Stripe first and falls back to LNBits.
- `iap-agent flow run` now also pays/waits for identity-anchor before continuity:

```bash
iap-agent flow run --registry-base "$REGISTRY_BASE" --payment-provider auto --open-browser --output-dir ./artifacts --json
```
