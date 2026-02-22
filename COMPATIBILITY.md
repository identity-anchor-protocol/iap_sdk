# iap-sdk Compatibility Matrix

This file pins the expected compatibility assumptions for `iap-sdk` releases.

## Matrix

| SDK version | Protocol version | Registry API assumptions |
| --- | --- | --- |
| `0.1.x` | `IAP-0.1` | `/registry/public-key`, `/v1/certificates/identity-anchor`, `/v1/continuity/requests`, `/v1/continuity/requests/{request_id}`, `/v1/continuity/certificates/{request_id}`, `/v1/payments/stripe/checkout-session` |

## Notes

- `iap-agent` supports Python `3.9` to `3.12`.
- `flow run` prefers Stripe checkout session when available and falls back to LNBits status/invoice fields from continuity request status.
- Offline verification assumes Ed25519 signatures and canonical JSON semantics implemented in this package.
