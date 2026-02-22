"""Protocol certificate schemas (IAP v0.1)."""

from __future__ import annotations

from typing import Dict, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

PROTOCOL_VERSION = "IAP-0.1"
IDENTITY_TYPE = "IAP-Identity-0.1"
CONTINUITY_TYPE = "IAP-Continuity-0.2"
LINEAGE_TYPE = "IAP-Lineage-0.1"
KEY_ROTATION_TYPE = "IAP-KeyRotation-0.1"


class BaseCertificate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    certificate_version: Literal["IAP-0.1"] = PROTOCOL_VERSION
    certificate_type: str
    agent_id: str
    issued_at: str
    registry_id: str
    registry_signature_b64: str
    metadata: Optional[Dict[str, str]] = None


class IdentityAnchorCertificate(BaseCertificate):
    certificate_type: Literal["IAP-Identity-0.1"] = IDENTITY_TYPE
    agent_public_key_b64: str


class ContinuityCertificate(BaseCertificate):
    certificate_type: Literal["IAP-Continuity-0.2"] = CONTINUITY_TYPE
    memory_root: str
    ledger_sequence: int = Field(..., ge=0)
    payment_reference: Optional[str] = None


class LineageCertificate(BaseCertificate):
    certificate_type: Literal["IAP-Lineage-0.1"] = LINEAGE_TYPE
    parent_agent_id: Optional[str] = None
    fork_event_hash: Optional[str] = None


class KeyRotationCertificate(BaseCertificate):
    certificate_type: Literal["IAP-KeyRotation-0.1"] = KEY_ROTATION_TYPE
    old_agent_id: str
    new_agent_id: str
    old_agent_public_key_b64: str
    new_agent_public_key_b64: str
