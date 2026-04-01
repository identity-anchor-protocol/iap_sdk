"""SDK error types."""

from __future__ import annotations


class IAPSDKError(RuntimeError):
    """Base SDK error."""


class RegistryUnavailableError(IAPSDKError):
    """Registry could not be reached."""


class RegistryRequestError(RegistryUnavailableError):
    """Registry returned a structured HTTP error response."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        detail: object | None = None,
        error_code: str | None = None,
        body: object | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.detail = detail
        self.error_code = error_code
        self.body = body


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


class ActionLogIntegrityError(IAPSDKError):
    """Local action log is missing entries or was tampered with."""


class ActionContextError(IAPSDKError):
    """Action provenance context_root could not be resolved safely."""


class ActionIdentityError(IAPSDKError):
    """Action logger identity material is missing or inconsistent."""


class ActionReceiptError(IAPSDKError):
    """Action receipt history is invalid or does not match the registry."""
