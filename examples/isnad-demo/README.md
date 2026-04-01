# Offline Isnād Demo (Under 5 Minutes)

This demo shows the current local action provenance flow without depending on a live registry.

It walks through:

1. creating a project-local agent identity
2. recording `file`, `shell`, and `http` actions
3. minting signed action receipts with an in-process demo registry
4. verifying the local action + receipt history
5. tampering with `receipts.log`
6. detecting the failure during verification

## Prerequisites

- Python 3.11+
- `iap-sdk` installed in editable mode or available on `PYTHONPATH`

## Run

```bash
python examples/isnad-demo/demo.py
```

Optional custom output directory:

```bash
python examples/isnad-demo/demo.py --workdir ./tmp/isnad-demo
```

## Expected output

You should see:

- `verify_before_ok=True`
- `verify_after_receipts_ok=True`
- `verify_after_tamper_ok=False`

That demonstrates the two current Isnād guarantees:

- local action history is verifiable
- local registry-style receipts become tamper-evident once stored
