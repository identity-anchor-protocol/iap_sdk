# State Drift Demo (Under 5 Minutes)

This is the minimal hardened v0.1 demo artifact for third-party validation.

This demo shows the exact transition scenario:

1. Agent defined
2. Memory appended
3. Anchor created
4. Memory silently modified
5. Verification fails

It demonstrates:

- normal flow up to an anchorable state root
- tamper detection after a historical AMCS mutation

Fork / divergence is not modeled in this demo because v0.1 hardening only requires
"detect + fail" for direct historical mutation.

## Prerequisites

- Python 3.11+
- `iap-sdk` installed (editable or package)
- `iap-amcs` package available in the same environment

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
