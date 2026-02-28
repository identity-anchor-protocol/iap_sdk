"""Typed SDK client for registry endpoints."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

from iap_sdk.errors import RegistryRequestError, RegistryUnavailableError, SDKTimeoutError

REGISTRY_API_KEY_ENV_VAR = "IAP_REGISTRY_API_KEY"


@dataclass
class RegistryClient:
    base_url: str
    api_key: str | None = None
    timeout: float = 10.0
    retries: int = 2

    def __post_init__(self) -> None:
        try:
            import requests
            from requests.adapters import HTTPAdapter
            from urllib3.util.retry import Retry
        except Exception as exc:  # pragma: no cover
            raise RegistryUnavailableError(f"requests stack unavailable: {exc}") from exc

        self._requests = requests
        self._session = requests.Session()
        retry = Retry(
            total=max(0, int(self.retries)),
            connect=max(0, int(self.retries)),
            read=max(0, int(self.retries)),
            status=max(0, int(self.retries)),
            status_forcelist=(429, 500, 502, 503, 504),
            backoff_factor=0.2,
            allowed_methods=("GET", "POST"),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)
        if self.api_key is None:
            env_api_key = os.getenv(REGISTRY_API_KEY_ENV_VAR)
            self.api_key = env_api_key.strip() or None if env_api_key else None

    def _url(self, path: str) -> str:
        return f"{self.base_url.rstrip('/')}/{path.lstrip('/')}"

    def _request(self, method: str, path: str, *, json_payload: dict | None = None) -> dict:
        headers = {"x-iap-api-key": self.api_key} if self.api_key else None
        try:
            response = self._session.request(
                method,
                self._url(path),
                json=json_payload,
                headers=headers,
                timeout=self.timeout,
            )
        except Exception as exc:  # pragma: no cover
            raise RegistryUnavailableError(str(exc)) from exc

        if response.status_code >= 400:
            body: object | None = None
            detail: object | None = None
            error_code: str | None = None
            try:
                body = response.json()
            except Exception:
                body = None
            if isinstance(body, dict):
                detail = body.get("detail")
                raw_error_code = body.get("error_code")
                error_code = str(raw_error_code) if isinstance(raw_error_code, str) else None
            if isinstance(detail, str):
                message = f"registry request failed: {response.status_code} {detail}"
            else:
                message = f"registry request failed: {response.status_code} {response.text}"
            raise RegistryRequestError(
                message,
                status_code=response.status_code,
                detail=detail,
                error_code=error_code,
                body=body,
            )
        return response.json()

    def submit_identity_anchor(self, payload: dict) -> dict:
        return self._request(
            "POST",
            "/v1/certificates/identity-anchor/requests",
            json_payload=payload,
        )

    def get_identity_anchor_status(self, request_id: str) -> dict:
        return self._request("GET", f"/v1/certificates/identity-anchor/requests/{request_id}")

    def get_identity_anchor_certificate(self, request_id: str) -> dict:
        return self._request("GET", f"/v1/certificates/identity-anchor/certificates/{request_id}")

    def submit_continuity_request(self, payload: dict) -> dict:
        return self._request("POST", "/v1/continuity/requests", json_payload=payload)

    def submit_lineage_request(self, payload: dict) -> dict:
        return self._request("POST", "/v1/certificates/lineage/requests", json_payload=payload)

    def get_lineage_status(self, request_id: str) -> dict:
        return self._request("GET", f"/v1/certificates/lineage/requests/{request_id}")

    def get_lineage_certificate(self, request_id: str) -> dict:
        return self._request("GET", f"/v1/certificates/lineage/certificates/{request_id}")

    def submit_key_rotation_request(self, payload: dict) -> dict:
        return self._request("POST", "/v1/certificates/key-rotation", json_payload=payload)

    def get_continuity_status(self, request_id: str) -> dict:
        return self._request("GET", f"/v1/continuity/requests/{request_id}")

    def get_continuity_certificate(self, request_id: str) -> dict:
        return self._request("GET", f"/v1/continuity/certificates/{request_id}")

    def create_stripe_checkout_session(
        self,
        *,
        request_id: str,
        success_url: str | None = None,
        cancel_url: str | None = None,
    ) -> dict:
        payload = {"request_id": request_id}
        if success_url:
            payload["success_url"] = success_url
        if cancel_url:
            payload["cancel_url"] = cancel_url
        return self._request("POST", "/v1/payments/stripe/checkout-session", json_payload=payload)

    def get_public_registry_key(self) -> dict:
        return self._request("GET", "/registry/public-key")

    def get_registry_info(self) -> dict:
        return self._request("GET", "/v1/registry/info")

    def get_agent_registry_status(self, agent_id: str) -> dict:
        return self._request("GET", f"/v1/registry/agents/{agent_id}/status")

    def wait_for_certification(
        self,
        *,
        request_id: str,
        timeout: float,
        interval: float = 2.0,
    ) -> dict:
        deadline = time.time() + timeout
        while time.time() < deadline:
            status = self.get_continuity_status(request_id)
            if status.get("status") == "CERTIFIED":
                return status
            time.sleep(max(0.1, interval))
        raise SDKTimeoutError(f"timed out waiting for certification: request_id={request_id}")

    def wait_for_identity_anchor(
        self,
        *,
        request_id: str,
        timeout: float,
        interval: float = 2.0,
    ) -> dict:
        deadline = time.time() + timeout
        while time.time() < deadline:
            status = self.get_identity_anchor_status(request_id)
            if status.get("status") == "CERTIFIED":
                return status
            time.sleep(max(0.1, interval))
        raise SDKTimeoutError(f"timed out waiting for identity-anchor: request_id={request_id}")

    def wait_for_lineage(
        self,
        *,
        request_id: str,
        timeout: float,
        interval: float = 2.0,
    ) -> dict:
        deadline = time.time() + timeout
        while time.time() < deadline:
            status = self.get_lineage_status(request_id)
            if status.get("status") == "CERTIFIED":
                return status
            time.sleep(max(0.1, interval))
        raise SDKTimeoutError(f"timed out waiting for lineage: request_id={request_id}")


__all__ = ["RegistryClient"]


def wait_for_certification(
    *,
    base_url: str,
    request_id: str,
    timeout: float,
    interval: float = 2.0,
) -> dict:
    client = RegistryClient(base_url=base_url)
    return client.wait_for_certification(request_id=request_id, timeout=timeout, interval=interval)


__all__.append("wait_for_certification")
