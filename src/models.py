"""
IOC Models — typed dataclasses for all Indicator of Compromise types.
"""

from dataclasses import dataclass, field
from typing import Optional, Any
from enum import Enum


class IOCType(str, Enum):
    IP = "IP"
    DOMAIN = "Domain"
    URL = "URL"
    HASH = "Hash"
    CVE = "CVE"


@dataclass
class IOC:
    """Represents a single Indicator of Compromise."""
    value: str
    ioc_type: IOCType

    def __str__(self):
        return f"[{self.ioc_type.value}] {self.value}"


@dataclass
class EnrichmentResult:
    """
    Holds aggregated enrichment data for a single IOC
    from one or more threat intelligence APIs.
    """
    ioc: IOC

    # Common fields
    verdict: str = "Unknown"           # Clean / Suspicious / Malicious / Unknown
    confidence_score: int = 0          # 0–100
    country: Optional[str] = None
    isp: Optional[str] = None
    domain: Optional[str] = None

    # IP-specific
    total_reports: int = 0
    last_reported: Optional[str] = None
    abuse_score: int = 0
    usage_type: Optional[str] = None
    hostnames: list[str] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    shodan_tags: list[str] = field(default_factory=list)
    shodan_vulns: list[str] = field(default_factory=list)
    organization: Optional[str] = None
    asn: Optional[str] = None

    # Domain/URL-specific
    malicious_votes: int = 0
    harmless_votes: int = 0
    suspicious_votes: int = 0
    categories: list[str] = field(default_factory=list)
    urlscan_screenshot: Optional[str] = None
    urlscan_verdict: Optional[str] = None

    # Hash-specific
    file_name: Optional[str] = None
    file_type: Optional[str] = None
    file_size: Optional[int] = None
    positives: int = 0
    total_scanners: int = 0
    tags: list[str] = field(default_factory=list)

    # CVE-specific
    cve_description: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_version: Optional[str] = None
    severity: Optional[str] = None
    published_date: Optional[str] = None
    affected_products: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    # Per-source raw results (for verbose/JSON output)
    sources: dict[str, Any] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)

    def set_verdict(self):
        """Derive overall verdict from available scores."""
        if self.ioc.ioc_type == IOCType.IP:
            score = self.abuse_score
            if score >= 75:
                self.verdict = "Malicious"
            elif score >= 25:
                self.verdict = "Suspicious"
            elif score == 0 and self.confidence_score == 0:
                self.verdict = "Clean"
            else:
                self.verdict = "Clean"
        elif self.ioc.ioc_type in (IOCType.DOMAIN, IOCType.URL):
            if self.malicious_votes > 0:
                self.verdict = "Malicious"
            elif self.suspicious_votes > 0:
                self.verdict = "Suspicious"
            else:
                self.verdict = "Clean"
        elif self.ioc.ioc_type == IOCType.HASH:
            ratio = self.positives / self.total_scanners if self.total_scanners else 0
            if ratio >= 0.5:
                self.verdict = "Malicious"
            elif ratio > 0:
                self.verdict = "Suspicious"
            else:
                self.verdict = "Clean"
        elif self.ioc.ioc_type == IOCType.CVE:
            if self.cvss_score is not None:
                if self.cvss_score >= 9.0:
                    self.verdict = "Critical"
                elif self.cvss_score >= 7.0:
                    self.verdict = "High"
                elif self.cvss_score >= 4.0:
                    self.verdict = "Medium"
                else:
                    self.verdict = "Low"
            else:
                self.verdict = "Unknown"
