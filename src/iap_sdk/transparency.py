"""SDK helpers for transparency log inclusion proofs."""

from __future__ import annotations

from iap_sdk.errors import RegistryUnavailableError
from iap_sdk.transparency_core import verify_merkle_proof


def get_inclusion_proof(*, base_url: str, certificate_digest: str, timeout: float = 10.0) -> dict:
    try:
        import requests

        response = requests.get(
            f"{base_url.rstrip('/')}/v1/transparency/proof/{certificate_digest}",
            timeout=timeout,
        )
    except Exception as exc:  # pragma: no cover
        raise RegistryUnavailableError(str(exc)) from exc

    if response.status_code >= 400:
        raise RegistryUnavailableError(
            f"inclusion proof request failed: {response.status_code} {response.text}"
        )
    return response.json()


def verify_inclusion_proof(proof_payload: dict) -> bool:
    digest = proof_payload.get("certificate_digest")
    leaf_index = proof_payload.get("leaf_index")
    proof = proof_payload.get("proof")
    root = proof_payload.get("root")
    if not isinstance(digest, str) or not isinstance(leaf_index, int):
        return False
    if not isinstance(proof, list) or not all(isinstance(item, str) for item in proof):
        return False
    if not isinstance(root, str):
        return False
    return verify_merkle_proof(leaf=digest, leaf_index=leaf_index, proof=proof, root=root)
