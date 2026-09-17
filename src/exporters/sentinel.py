"""
Microsoft Sentinel Exporter — sends enrichment events using the modern
Logs Ingestion API (Data Collection Endpoint + Data Collection Rule),
authenticated via a Microsoft Entra ID (Azure AD) app registration.

The legacy HTTP Data Collector API is intentionally NOT used here: it is
deprecated by Microsoft. See:
https://learn.microsoft.com/azure/azure-monitor/logs/logs-ingestion-api-overview
https://learn.microsoft.com/azure/azure-monitor/logs/data-collector-api

Required configuration (read only from Config/keys.env, never hardcoded):
  SENTINEL_TENANT_ID, SENTINEL_CLIENT_ID, SENTINEL_CLIENT_SECRET,
  SENTINEL_DCE_ENDPOINT, SENTINEL_DCR_IMMUTABLE_ID, SENTINEL_STREAM_NAME
"""

from __future__ import annotations

import time
from urllib.parse import urlsplit

from src.exporters.base import BaseExporter, ExportResult

_LOGIN_HOST = "login.microsoftonline.com"
_SCOPE = "https://monitor.azure.com/.default"
_API_VERSION = "2023-01-01"


class SentinelExporter(BaseExporter):
    name = "sentinel"

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        dce_endpoint: str,
        dcr_immutable_id: str,
        stream_name: str,
        verify_tls: bool = True,
        **kwargs,
    ):
        dce_host = urlsplit(dce_endpoint.rstrip("/")).hostname
        allowed = {_LOGIN_HOST}
        if dce_host:
            allowed.add(dce_host)
        super().__init__(allowed_hosts=allowed, verify_tls=verify_tls, **kwargs)

        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.dce_endpoint = dce_endpoint.rstrip("/")
        self.dcr_immutable_id = dcr_immutable_id
        self.stream_name = stream_name

        self._token: str | None = None
        self._token_expires_at: float = 0.0

    def _secrets(self) -> tuple[str, ...]:
        secrets = [self.client_secret]
        if self._token:
            secrets.append(self._token)
        return tuple(secrets)

    def _get_token(self) -> str | None:
        if self._token and time.time() < self._token_expires_at - 60:
            return self._token

        token_url = f"https://{_LOGIN_HOST}/{self.tenant_id}/oauth2/v2.0/token"
        body = (
            f"grant_type=client_credentials"
            f"&client_id={self.client_id}"
            f"&client_secret={self.client_secret}"
            f"&scope={_SCOPE}"
        )
        response = self._post(
            token_url,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if response is None:
            return None
        try:
            payload = response.json()
        except ValueError:
            self.logger.error("[%s] token endpoint returned an invalid response", self.name)
            return None

        token = payload.get("access_token")
        expires_in = payload.get("expires_in", 3600)
        if not token:
            self.logger.error("[%s] no access token in Entra ID response", self.name)
            return None

        self._token = token
        self._token_expires_at = time.time() + float(expires_in)
        return token

    def send_batch(self, events: list[dict]) -> ExportResult:
        token = self._get_token()
        if not token:
            return ExportResult(
                exporter=self.name, success=False, failed=len(events),
                error="Failed to authenticate with Microsoft Entra ID",
            )

        endpoint = (
            f"{self.dce_endpoint}/dataCollectionRules/{self.dcr_immutable_id}"
            f"/streams/{self.stream_name}?api-version={_API_VERSION}"
        )
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        sent = 0
        failed = 0
        for batch in self.chunk(events, self.batch_size):
            response = self._post(endpoint, json_body=batch, headers=headers)
            if response is not None:
                sent += len(batch)
            else:
                failed += len(batch)

        return ExportResult(
            exporter=self.name,
            success=failed == 0,
            sent=sent,
            failed=failed,
            error=None if failed == 0 else f"{failed} event(s) failed to reach Sentinel",
        )
