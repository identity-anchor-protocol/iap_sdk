# Isnād Local Demo

This is the quickest way to see the current Isnād implementation working end to end without
depending on the live registry.

## What it demonstrates

- project-local identity setup
- append-only local action logging
- `file`, `shell`, and `http` action recording
- local receipt creation via an offline demo registry
- local verification before and after a deliberate receipt tamper

## Run

```bash
python examples/isnad-demo/demo.py
```

Optional custom output directory:

```bash
python examples/isnad-demo/demo.py --workdir ./tmp/isnad-demo
```

## Expected result

The demo should print:

- `verify_before_ok=True`
- `verify_after_receipts_ok=True`
- `verify_after_tamper_ok=False`

That maps directly to the current product state:

- local actions are chained and verifiable
- local receipts can be verified against those actions
- modifying receipt history after the fact is detectable

## Related CLI commands

After running the demo, the equivalent inspection commands are:

```bash
iap actions status --actions-dir ./isnad-demo-output/.iap/actions --json
iap actions verify --actions-dir ./isnad-demo-output/.iap/actions --json
```

If you have a pinned registry key, you can also verify receipt signatures explicitly:

```bash
iap actions verify \
  --actions-dir ./isnad-demo-output/.iap/actions \
  --registry-public-key-b64 <registry-public-key> \
  --json
```
