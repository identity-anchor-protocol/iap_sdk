# State Drift Demo (Under 5 Minutes)

This demo shows the exact transition scenario:

1. Agent defined
2. Memory appended
3. Anchor created
4. Memory silently modified
5. Verification fails

## Prerequisites

- Python 3.11+
- `iap-sdk` installed (editable or package)
- `amcs` package available in the same environment

## Run

```bash
python examples/state-drift-demo/demo.py
```

Optional custom output directory:

```bash
python examples/state-drift-demo/demo.py --workdir ./tmp/iap-drift-demo
```

## Expected output

You should see:

- `verify_before_ok=True`
- `verify_after_ok=False`
- `verify_after_error=event hash mismatch`

That demonstrates tamper-evident state continuity: once historical AMCS events are changed, verification no longer passes.
