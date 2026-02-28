# End-to-End Walkthrough (User-Friendly)

This walkthrough runs a real user flow from zero to a verified continuity record.

What you do:

1. Create your local agent identity (key pair).
2. Store e.g. `AGENT.md` and `SOUL.md` into local `amcs.db`.
3. Read `memory_root` and `sequence` from AMCS (Agent Memory Canonicalization Standard).
4. Request and pay for Identity Anchor.
5. Request and pay for Continuity.
6. Download and verify the continuity record offline.

Important:
- Do not type placeholders like `<agent_id>` or `<request_id>` literally.
- In this guide, values are captured into shell variables so you can copy/paste safely.

## 0) Fresh setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install iap-agent
```

Set registry URL:

```bash
export REGISTRY_BASE="https://registry.ia-protocol.com"
```

Optional: set your default agent display name once in config (used when `--agent-name` is omitted):

```bash
mkdir -p ~/.iap_agent
cat > ~/.iap_agent/config.toml <<'EOF'
[cli]
agent_name = "Atlas"
EOF
```

## 1) Create your local agent identity

Recommended for a fresh agent project: create a project-local identity so this folder gets its own
keypair and does not silently reuse `~/.iap_agent/identity/ed25519.json`.

```bash
INIT_JSON="$(iap-agent init --project-local --show-public --json)"
echo "$INIT_JSON"
AGENT_ID="$(echo "$INIT_JSON" | jq -r .agent_id)"
echo "AGENT_ID=$AGENT_ID"
```

If you omit `--project-local`, `iap-agent` uses the global default identity file under
`~/.iap_agent/identity/ed25519.json`. That is useful when you intentionally want to continue the
same agent across multiple folders, but it is the wrong default for “create a brand-new test agent”.

## 2) Create agent files and store them in AMCS

Create or use exiting files for your agent (these are two examples):

```bash
cat > AGENT.md <<'EOF'
# Atlas
Role: Personal AI assistant
EOF

cat > SOUL.md <<'EOF'
# Purpose
Help user reliably, safely, and with continuity.
EOF
```

Append both files into local AMCS database:

```bash
iap-agent amcs append --amcs-db ./amcs.db --agent-id "$AGENT_ID" --file ./AGENT.md --file ./SOUL.md --json
```

The command prints the latest memory root.
If `./amcs.db` does not exist yet, AMCS creates it automatically.

## 3) Confirm AMCS root and sequence

```bash
iap-agent amcs root --amcs-db ./amcs.db --agent-id "$AGENT_ID" --json
```

## 4) Request Identity Anchor and pay for issuance

Payment provider options:

- `--payment-provider auto`: try Stripe first, then Lightning fallback.
- `--payment-provider stripe`: force Stripe checkout.
- `--payment-provider lightning-btc`: force Lightning invoice flow.


Example with auto handoff (Stripe first, Lightning fallback):

```bash
ANCHOR_JSON="$(iap-agent anchor issue --registry-base "$REGISTRY_BASE" --agent-name "Atlas" --payment-provider auto --open-browser --json)"
echo "$ANCHOR_JSON"
ANCHOR_REQUEST_ID="$(echo "$ANCHOR_JSON" | jq -r .request_id)"
ANCHOR_STATUS="$(echo "$ANCHOR_JSON" | jq -r .status)"
echo "ANCHOR_REQUEST_ID=$ANCHOR_REQUEST_ID"
echo "ANCHOR_STATUS=$ANCHOR_STATUS"
```

If Stripe checkout is returned, a browser payment page opens.
If Lightning fallback is returned, pay the `payment.lightning_invoice`.

Fetch and save identity-anchor certificate bundle (recommended):

```bash
iap-agent anchor cert --registry-base "$REGISTRY_BASE" --request-id "$ANCHOR_REQUEST_ID" --output-file ./identity_anchor_record.json --json
```

Optional: wait directly from the same command:

```bash
iap-agent anchor issue --registry-base "$REGISTRY_BASE" --agent-name "Atlas" --payment-provider auto --open-browser --wait --timeout-seconds 600 --poll-seconds 5 --json
```

## 5) Request Continuity and pay for issuance

Create request:

```bash
CONT_JSON="$(iap-agent continuity request --registry-base "$REGISTRY_BASE" --amcs-db ./amcs.db --json)"
echo "$CONT_JSON"
CONT_REQUEST_ID="$(echo "$CONT_JSON" | jq -r .request_id)"
CONT_STATUS="$(echo "$CONT_JSON" | jq -r .status)"
echo "CONT_REQUEST_ID=$CONT_REQUEST_ID"
echo "CONT_STATUS=$CONT_STATUS"
```

If this command fails with a message like:

- `ledger_sequence must strictly increase; latest registry sequence is X`

it means this `agent_id` already has newer registry history than your local AMCS state.

Inspect current registry state:

```bash
iap-agent registry status --registry-base "$REGISTRY_BASE" --agent-id "$AGENT_ID" --json
```

Practical interpretation:

- If you meant to continue the same agent, update your local state process and use a higher
  continuity sequence.
- If you meant to create a brand-new agent, start over in a clean folder with
  `iap-agent init --project-local ...` so you get a new keypair and new `agent_id`.

If `CONT_STATUS` is already `CERTIFIED`, skip directly to step 6.
Otherwise request payment handoff:

```bash
iap-agent continuity pay --registry-base "$REGISTRY_BASE" --request-id "$CONT_REQUEST_ID" --payment-provider auto --open-browser --json
```

If Stripe is used, complete checkout in browser.
If Lightning is used, pay `lightning_invoice`.

### Advanced: manual continuity input (without AMCS read)

You can submit continuity requests with explicit values:

```bash
iap-agent continuity request --registry-base "$REGISTRY_BASE" --memory-root <64-lowercase-hex> --sequence <integer>=1+ --json
```

Manual mode implications:

- You must provide a valid 64-char lowercase hex `memory_root`.
- You must provide a strictly increasing `sequence` for that `agent_id`.
- The registry enforces monotonic sequence and signature validity, but it cannot verify your local
  process correctness for how root/sequence were produced.
- If your manual values are wrong (stale root, wrong sequence), the request may fail or produce
  continuity that does not match your real local state.

Why AMCS-backed mode is better:

- AMCS computes root from your append-only local event history.
- AMCS tracks sequence naturally from the same local history.
- It reduces human error and creates a reproducible continuity trail tied to local state changes.
- It is safer for sensitive workflows because you avoid hand-editing cryptographic continuity
  inputs.

## 6) Wait for certification, fetch continuity record, verify

```bash
iap-agent continuity wait --registry-base "$REGISTRY_BASE" --request-id "$CONT_REQUEST_ID" --timeout-seconds 600 --poll-seconds 5 --json
iap-agent continuity cert --registry-base "$REGISTRY_BASE" --request-id "$CONT_REQUEST_ID" --output-file ./continuity_record.json --json
REGISTRY_PUBLIC_KEY_B64="$(curl -s "$REGISTRY_BASE/registry/public-key" | jq -r .public_key_b64)"
iap-agent verify ./continuity_record.json --profile strict --registry-public-key-b64 "$REGISTRY_PUBLIC_KEY_B64" --identity-anchor ./identity_anchor_record.json --json
```

Why this registry public key step matters:
- It pins the registry trust anchor locally.
- With the pinned key, signature checks are done offline against certificate data.
- You can validate authenticity independently, even if the registry is unavailable later.

Expected verify output shape:

```json
{"ok": true, "reason": "ok"}
```
