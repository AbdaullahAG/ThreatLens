"""
Config Manager — loads API keys from environment file or system env vars.
"""

import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from dotenv import dotenv_values


@dataclass
class Config:
    config_path: str = "config/keys.env"
    timeout: int = 10
    delay: float = 0.5
    max_file_bytes: int = 10 * 1024 * 1024
    max_iocs: int = 1_000
    max_requests: int = 250
    kev_cache_ttl: int = 24 * 60 * 60
    max_asset_file_bytes: int = 10 * 1024 * 1024
    max_asset_rows: int = 50_000
    max_log_lines: int = 500_000

    # API Keys (populated after __post_init__)
    abuseipdb_key: Optional[str] = field(default=None, init=False)
    virustotal_key: Optional[str] = field(default=None, init=False)
    otx_key: Optional[str] = field(default=None, init=False)
    shodan_key: Optional[str] = field(default=None, init=False)
    urlscan_key: Optional[str] = field(default=None, init=False)
    # NVD (National Vulnerability Database) is free with no key required
    # but an optional key increases rate limits
    nvd_key: Optional[str] = field(default=None, init=False)

    # SIEM export destinations (all optional; only exporters with complete
    # configuration are made available)
    splunk_hec_url: Optional[str] = field(default=None, init=False)
    splunk_hec_token: Optional[str] = field(default=None, init=False)
    splunk_index: Optional[str] = field(default=None, init=False)
    elastic_url: Optional[str] = field(default=None, init=False)
    elastic_api_key: Optional[str] = field(default=None, init=False)
    elastic_index: Optional[str] = field(default=None, init=False)
    sentinel_tenant_id: Optional[str] = field(default=None, init=False)
    sentinel_client_id: Optional[str] = field(default=None, init=False)
    sentinel_client_secret: Optional[str] = field(default=None, init=False)
    sentinel_dce_endpoint: Optional[str] = field(default=None, init=False)
    sentinel_dcr_immutable_id: Optional[str] = field(default=None, init=False)
    sentinel_stream_name: Optional[str] = field(default=None, init=False)

    def __post_init__(self):
        if not 1 <= self.timeout <= 60:
            raise ValueError("timeout must be between 1 and 60 seconds")
        if not 0 <= self.delay <= 5:
            raise ValueError("delay must be between 0 and 5 seconds")
        if not 1 <= self.max_iocs <= 10_000:
            raise ValueError("max_iocs must be between 1 and 10000")
        if not 1 <= self.max_file_bytes <= 100 * 1024 * 1024:
            raise ValueError("max_file_bytes must be between 1 byte and 100 MiB")
        if not 1 <= self.max_requests <= 10_000:
            raise ValueError("max_requests must be between 1 and 10000")
        if not 60 <= self.kev_cache_ttl <= 7 * 24 * 60 * 60:
            raise ValueError("kev_cache_ttl must be between 60 seconds and 7 days")
        if not 1 <= self.max_asset_file_bytes <= 100 * 1024 * 1024:
            raise ValueError("max_asset_file_bytes must be between 1 byte and 100 MiB")
        if not 1 <= self.max_asset_rows <= 1_000_000:
            raise ValueError("max_asset_rows must be between 1 and 1000000")
        if not 1 <= self.max_log_lines <= 10_000_000:
            raise ValueError("max_log_lines must be between 1 and 10000000")
        self._load_keys()

    def _load_keys(self):
        """Load keys: env file first, then system environment variables as fallback."""
        file_values = {}
        config_file = Path(self.config_path)
        if config_file.exists():
            file_values = dotenv_values(config_file)

        def get(key: str) -> Optional[str]:
            return file_values.get(key) or os.environ.get(key)

        self.abuseipdb_key = get("ABUSEIPDB_API_KEY")
        self.virustotal_key = get("VIRUSTOTAL_API_KEY")
        self.otx_key = get("OTX_API_KEY")
        self.shodan_key = get("SHODAN_API_KEY")
        self.urlscan_key = get("URLSCAN_API_KEY")
        self.nvd_key = get("NVD_API_KEY")

        self.splunk_hec_url = get("SPLUNK_HEC_URL")
        self.splunk_hec_token = get("SPLUNK_HEC_TOKEN")
        self.splunk_index = get("SPLUNK_INDEX")
        self.elastic_url = get("ELASTIC_URL")
        self.elastic_api_key = get("ELASTIC_API_KEY")
        self.elastic_index = get("ELASTIC_INDEX") or "threatlens-iocs"
        self.sentinel_tenant_id = get("SENTINEL_TENANT_ID")
        self.sentinel_client_id = get("SENTINEL_CLIENT_ID")
        self.sentinel_client_secret = get("SENTINEL_CLIENT_SECRET")
        self.sentinel_dce_endpoint = get("SENTINEL_DCE_ENDPOINT")
        self.sentinel_dcr_immutable_id = get("SENTINEL_DCR_IMMUTABLE_ID")
        self.sentinel_stream_name = get("SENTINEL_STREAM_NAME")

    def configured_exporters(self) -> dict[str, bool]:
        """Which SIEM exporters have complete configuration and can be used."""
        return {
            "splunk": bool(self.splunk_hec_url and self.splunk_hec_token),
            "elastic": bool(self.elastic_url and self.elastic_api_key),
            "sentinel": bool(
                self.sentinel_tenant_id
                and self.sentinel_client_id
                and self.sentinel_client_secret
                and self.sentinel_dce_endpoint
                and self.sentinel_dcr_immutable_id
                and self.sentinel_stream_name
            ),
        }

    def available_apis(self) -> dict[str, bool]:
        """Return which APIs have keys configured."""
        return {
            "abuseipdb": bool(self.abuseipdb_key),
            "virustotal": bool(self.virustotal_key),
            "otx": bool(self.otx_key),
            "shodan": bool(self.shodan_key),
            "urlscan": bool(self.urlscan_key),
            "nvd": True,  # Free, no key required
            "cisa_kev": True,  # Free, no key required
            "epss": True,  # Free, no key required
        }

    def get_key(self, api_name: str) -> Optional[str]:
        key_map = {
            "abuseipdb": self.abuseipdb_key,
            "virustotal": self.virustotal_key,
            "otx": self.otx_key,
            "shodan": self.shodan_key,
            "urlscan": self.urlscan_key,
            "nvd": self.nvd_key,
        }
        return key_map.get(api_name)
