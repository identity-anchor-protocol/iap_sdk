# End-to-End Walkthrough (Developer Local, No Ambiguity)

This version is explicit about:

- which app runs in which terminal
- which virtual environment to activate
- where files are stored
- how to complete payment in Stripe or Lightning/OpenNode mode

Assumed folders:

- `IAP-Registry` repo: `/Users/Dirk/code/IAP/IAP-Registry`
- `iap-sdk` repo: `/Users/Dirk/code/IAP/iap-sdk`
- `AMCS` repo: `/Users/Dirk/code/IAP/AMCS-0.1`

## Terminal map

- Terminal A: run Registry API server
- Terminal B: run SDK CLI commands
- Terminal C (optional): Stripe CLI forwarder or debug curls

## Terminal A: Start Registry API

```bash
cd /Users/Dirk/code/IAP/IAP-Registry
source .venv/bin/activate
set -a
source .env
set +a
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

Keep this running.

Quick health check (from any terminal):

```bash
curl -s http://localhost:8080/health
```

## Terminal B: Prepare SDK + AMCS

```bash
cd /Users/Dirk/code/IAP/iap-sdk
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e ".[dev]"
python -m pip install -e /Users/Dirk/code/IAP/AMCS-0.1
```

Set local registry target:

```bash
export REGISTRY_BASE="http://localhost:8080"
```

## Step 1: Create agent key pair

```bash
iap-agent init --show-public --json
```

Copy `agent_id` from output.

## Step 2: Create and store identity files in AMCS

Create files:

```bash
cat > AGENT.md <<'EOF'
# Atlas
Role: Local dev test agent
EOF

cat > SOUL.md <<'EOF'
# Purpose
Preserve identity continuity over time.
EOF
```

Append into `./amcs.db`:

```bash
python scripts/append_agent_files_to_amcs.py --amcs-db ./amcs.db --agent-id <agent_id> --agent-file ./AGENT.md --soul-file ./SOUL.md
```

Confirm root + sequence:

```bash
iap-agent amcs root --amcs-db ./amcs.db --agent-id <agent_id> --json
```

## Step 3: Identity Anchor request + payment

Lightning local-dev path:

```bash
iap-agent anchor issue --registry-base "$REGISTRY_BASE" --agent-name "Atlas" --payment-provider lightning-btc --json
```

From the JSON output, copy:

- `request_id`
- `payment.lnbits_payment_hash` (legacy field name; backend may be OpenNode)
- `payment.lightning_invoice`

Pay invoice in your Lightning wallet.

Check anchor status:

```bash
curl -s "http://localhost:8080/v1/certificates/identity-anchor/requests/<anchor_request_id>"
```

When status is `CERTIFIED`, fetch anchor certificate:

```bash
curl -s "http://localhost:8080/v1/certificates/identity-anchor/certificates/<anchor_request_id>" > identity_anchor_certificate.json
```

## Step 4: Continuity request + payment

```bash
iap-agent continuity request --registry-base "$REGISTRY_BASE" --amcs-db ./amcs.db --json
```

From the JSON output, copy:

- `request_id`
- `payment.lnbits_payment_hash` (legacy field name; backend may be OpenNode)
- `payment.lightning_invoice`

Pay invoice in your Lightning wallet.

Wait for certification:

```bash
iap-agent continuity wait --registry-base "$REGISTRY_BASE" --request-id <continuity_request_id> --timeout-seconds 600 --poll-seconds 5 --json
```

Fetch certificate bundle:

```bash
iap-agent continuity cert --registry-base "$REGISTRY_BASE" --request-id <continuity_request_id> --output-file ./continuity_record.json --json
```

Verify:

```bash
REGISTRY_PUBLIC_KEY_B64="$(curl -s "$REGISTRY_BASE/registry/public-key" | jq -r .public_key_b64)"
iap-agent verify ./continuity_record.json --profile strict --registry-public-key-b64 "$REGISTRY_PUBLIC_KEY_B64" --json
```

Expected: `{"ok": true, "reason": "ok"}`.

## Stripe local-dev notes

- For Stripe local webhook testing, run Stripe CLI in Terminal C and forward to `http://localhost:8080/v1/webhooks/stripe`.
- For OpenNode local webhook testing, use a reachable callback URL configured in registry settings (`OPENNODE_WEBHOOK_URL`) and OpenNode dashboard webhook configuration.
- Use `--payment-provider stripe` with:
  - `iap-agent anchor issue ...`
  - `iap-agent continuity pay ...`
- If Stripe is unavailable, fallback is:
  - `--payment-provider auto` (tries Stripe, then Lightning/OpenNode)
- `--payment-provider lnbits` is still accepted as a legacy alias for `lightning-btc`.
