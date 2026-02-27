# End-to-End Walkthrough (Developer Local, No Ambiguity)

This version is explicit about:

- which app runs in which terminal
- which virtual environment to activate
- where files are stored
- how to complete payment in Stripe or Lightning/OpenNode mode

Important:
- Do not type placeholders like `<anchor_request_id>` literally.
- This guide captures key values into shell variables to avoid manual copy mistakes.

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
```

Set local registry target:

```bash
export REGISTRY_BASE="http://localhost:8080"
```

## Step 1: Create agent key pair

```bash
INIT_JSON="$(iap-agent init --show-public --json)"
echo "$INIT_JSON"
AGENT_ID="$(echo "$INIT_JSON" | jq -r .agent_id)"
echo "AGENT_ID=$AGENT_ID"
```

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
iap-agent amcs append --amcs-db ./amcs.db --agent-id "$AGENT_ID" --file ./AGENT.md --file ./SOUL.md --json
```

If `./amcs.db` does not exist yet, AMCS creates it automatically.

Confirm root + sequence:

```bash
iap-agent amcs root --amcs-db ./amcs.db --agent-id "$AGENT_ID" --json
```

## Step 3: Identity Anchor request + payment

Capture output and extract values:

```bash
ANCHOR_JSON="$(iap-agent anchor issue --registry-base "$REGISTRY_BASE" --agent-name "Atlas" --payment-provider lightning-btc --json)"
echo "$ANCHOR_JSON"
ANCHOR_REQUEST_ID="$(echo "$ANCHOR_JSON" | jq -r .request_id)"
echo "ANCHOR_REQUEST_ID=$ANCHOR_REQUEST_ID"
```

Pay invoice in your Lightning wallet if a payable invoice is returned.

Check anchor status:

```bash
curl -s "http://localhost:8080/v1/certificates/identity-anchor/requests/$ANCHOR_REQUEST_ID"
```

When status is `CERTIFIED`, fetch anchor certificate:

```bash
iap-agent anchor cert --registry-base "$REGISTRY_BASE" --request-id "$ANCHOR_REQUEST_ID" --output-file ./identity_anchor_certificate.json --json
```

## Step 4: Continuity request + payment

```bash
CONT_JSON="$(iap-agent continuity request --registry-base "$REGISTRY_BASE" --amcs-db ./amcs.db --json)"
echo "$CONT_JSON"
CONT_REQUEST_ID="$(echo "$CONT_JSON" | jq -r .request_id)"
CONT_STATUS="$(echo "$CONT_JSON" | jq -r .status)"
echo "CONT_REQUEST_ID=$CONT_REQUEST_ID"
echo "CONT_STATUS=$CONT_STATUS"
```

Pay invoice in your Lightning wallet if continuity is not yet `CERTIFIED`.

Wait for certification:

```bash
iap-agent continuity wait --registry-base "$REGISTRY_BASE" --request-id "$CONT_REQUEST_ID" --timeout-seconds 600 --poll-seconds 5 --json
```

Fetch certificate bundle:

```bash
iap-agent continuity cert --registry-base "$REGISTRY_BASE" --request-id "$CONT_REQUEST_ID" --output-file ./continuity_record.json --json
```

Verify:

```bash
REGISTRY_PUBLIC_KEY_B64="$(curl -s "$REGISTRY_BASE/registry/public-key" | jq -r .public_key_b64)"
iap-agent verify ./continuity_record.json --profile strict --registry-public-key-b64 "$REGISTRY_PUBLIC_KEY_B64" --identity-anchor ./identity_anchor_certificate.json --json
```

The pinned `REGISTRY_PUBLIC_KEY_B64` is your local trust anchor for offline signature checks.

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
