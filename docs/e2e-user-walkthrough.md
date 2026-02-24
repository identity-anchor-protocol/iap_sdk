# End-to-End Walkthrough (User-Friendly)

This walkthrough runs a real user flow from zero to a verified continuity certificate.

What you do:

1. Create your local agent identity (key pair).
2. Store `AGENT.md` and `SOUL.md` into local `amcs.db`.
3. Read `memory_root` and `sequence` from AMCS.
4. Request and pay for Identity Anchor.
5. Request and pay for Continuity.
6. Download and verify the certificate offline.

## 0) Fresh setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install iap-agent
python -m pip install -e /path/to/AMCS-0.1
```

Set registry URL:

```bash
export REGISTRY_BASE="https://registry.ia-protocol.com"
```

## 1) Create your local agent identity

```bash
iap-agent init --show-public --json
```

Keep the returned `agent_id` for next steps.

## 2) Create agent files and store them in AMCS

Create files:

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

Append both files into local AMCS:

```bash
python scripts/append_agent_files_to_amcs.py \
  --amcs-db ./amcs.db \
  --agent-id <agent_id> \
  --agent-file ./AGENT.md \
  --soul-file ./SOUL.md
```

The command prints the latest memory root.

## 3) Confirm AMCS root and sequence

```bash
iap-agent amcs root --amcs-db ./amcs.db --agent-id <agent_id> --json
```

## 4) Request Identity Anchor and pay

Payment provider options:

- `--payment-provider auto`: try Stripe first, then Lightning fallback.
- `--payment-provider stripe`: force Stripe checkout.
- `--payment-provider lightning-btc`: force Lightning invoice flow.
- `--payment-provider lnbits`: legacy alias for `lightning-btc` (kept for compatibility).

Use automatic handoff (Stripe first, Lightning fallback):

```bash
iap-agent anchor issue --registry-base "$REGISTRY_BASE" --agent-name "Atlas" --payment-provider auto --open-browser --json
```

Save `request_id` from output.

If Stripe checkout is returned, a browser payment page opens.
If Lightning fallback is returned, pay the `payment.lightning_invoice`.

Optional: wait directly from the same command:

```bash
iap-agent anchor issue --registry-base "$REGISTRY_BASE" --agent-name "Atlas" --payment-provider auto --open-browser --wait --timeout-seconds 600 --poll-seconds 5 --json
```

## 5) Request Continuity and pay

Create request:

```bash
iap-agent continuity request --registry-base "$REGISTRY_BASE" --amcs-db ./amcs.db --json
```

Copy the `request_id`, then request payment handoff:

```bash
iap-agent continuity pay --registry-base "$REGISTRY_BASE" --request-id <request_id> --payment-provider auto --open-browser --json
```

If Stripe is used, complete checkout in browser.
If Lightning is used, pay `lightning_invoice`.

### Advanced: manual continuity input (without AMCS read)

You can submit continuity with explicit values:

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

## 6) Wait for certification, fetch certificate, verify

```bash
iap-agent continuity wait --registry-base "$REGISTRY_BASE" --request-id <request_id> --timeout-seconds 600 --poll-seconds 5 --json
iap-agent continuity cert --registry-base "$REGISTRY_BASE" --request-id <request_id> --output-file ./certificate.json --json
iap-agent verify ./certificate.json --registry-base "$REGISTRY_BASE" --json
```

Expected verify output shape:

```json
{"ok": true, "reason": "ok"}
```
