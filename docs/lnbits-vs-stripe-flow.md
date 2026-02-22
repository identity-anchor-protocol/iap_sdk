# LNBits vs Stripe Payment Flow

`iap-agent` supports both payment paths through the same continuity workflow.

## Stripe path (preferred when available)

1. CLI requests Stripe checkout session from registry.
2. Registry returns `checkout_url`.
3. User opens checkout URL and completes payment.
4. Registry marks request as `CERTIFIED` after webhook confirmation.

Command:

```bash
iap-agent continuity pay --request-id <request-id> --open-browser
```

## LNBits path (fallback)

1. If Stripe session endpoint is unavailable, CLI fetches continuity status.
2. Status includes LN invoice details (`lightning_invoice`, `lnbits_payment_hash`).
3. User pays invoice in LNBits-compatible wallet.
4. Registry updates request to `CERTIFIED`.

Same command:

```bash
iap-agent continuity pay --request-id <request-id>
```

## Common post-payment steps

```bash
iap-agent continuity wait --request-id <request-id>
iap-agent continuity cert --request-id <request-id>
```
