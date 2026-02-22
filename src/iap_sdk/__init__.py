"""IAP SDK public surface."""

from iap_sdk.amcs_adapter import AMCSAdapterProtocol, build_continuity_request_from_amcs
from iap_sdk.client import RegistryClient, wait_for_certification
from iap_sdk.crypto.agent_identity import derive_agent_id, validate_agent_id
from iap_sdk.errors import (
    AgentIdentityMismatchError,
    AnchorMissingError,
    IAPSDKError,
    InvalidSignatureError,
    ProtocolVersionMismatchError,
    RegistryUnavailableError,
    ReplayNonceError,
    SchemaValidationError,
    SDKTimeoutError,
    SequenceViolationError,
)
from iap_sdk.liveness import (
    build_liveness_response,
    request_liveness_challenge,
    respond_liveness_challenge,
    verify_liveness_attestation,
)
from iap_sdk.manifest import build_identity_manifest, compute_manifest_hash
from iap_sdk.offline_verify import verify_certificate_dict
from iap_sdk.requests import (
    build_continuity_request,
    build_continuity_request_legacy,
    build_key_rotation_request,
    build_lineage_request,
    check_sequence_integrity,
    sign_continuity_request,
    sign_key_rotation_request,
    sign_lineage_request,
)
from iap_sdk.transparency import get_inclusion_proof, verify_inclusion_proof
from iap_sdk.types import ALLOWED_CUSTODY_CLASSES, CustodyClass, normalize_custody_class
from iap_sdk.verify import (
    verify_certificate,
    verify_certificate_file,
    verify_key_rotation_certificate,
)

__all__ = [
    "IAPSDKError",
    "AMCSAdapterProtocol",
    "build_continuity_request_from_amcs",
    "RegistryClient",
    "wait_for_certification",
    "RegistryUnavailableError",
    "InvalidSignatureError",
    "AgentIdentityMismatchError",
    "AnchorMissingError",
    "SequenceViolationError",
    "ReplayNonceError",
    "ProtocolVersionMismatchError",
    "SchemaValidationError",
    "SDKTimeoutError",
    "derive_agent_id",
    "validate_agent_id",
    "build_identity_manifest",
    "compute_manifest_hash",
    "build_continuity_request",
    "build_continuity_request_legacy",
    "sign_continuity_request",
    "build_lineage_request",
    "sign_lineage_request",
    "build_key_rotation_request",
    "sign_key_rotation_request",
    "check_sequence_integrity",
    "verify_certificate",
    "verify_certificate_file",
    "verify_key_rotation_certificate",
    "get_inclusion_proof",
    "verify_inclusion_proof",
    "CustodyClass",
    "ALLOWED_CUSTODY_CLASSES",
    "normalize_custody_class",
    "request_liveness_challenge",
    "build_liveness_response",
    "respond_liveness_challenge",
    "verify_liveness_attestation",
    "verify_certificate_dict",
]
