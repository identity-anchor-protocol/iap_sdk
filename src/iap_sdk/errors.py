"""SDK error types."""

from __future__ import annotations


class IAPSDKError(RuntimeError):
    """Base SDK error."""


class RegistryUnavailableError(IAPSDKError):
    """Registry could not be reached."""


class InvalidSignatureError(IAPSDKError):
    """Signature validation failed."""


class AgentIdentityMismatchError(IAPSDKError):
    """agent_id does not match public key derivation."""


class AnchorMissingError(IAPSDKError):
    """Identity anchor missing for operation requiring it."""


class SequenceViolationError(IAPSDKError):
    """Monotonic sequence requirement violated."""


class ReplayNonceError(IAPSDKError):
    """Nonce was already used."""


class ProtocolVersionMismatchError(IAPSDKError):
    """Unsupported protocol version."""


class SchemaValidationError(IAPSDKError):
    """Schema validation failed."""


class SDKTimeoutError(IAPSDKError):
    """Timed out waiting for registry state."""
