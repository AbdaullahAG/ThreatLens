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
class AssetRecord:
    """A single row of imported asset inventory data."""
    criticality: str
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    internet_facing: bool = False
    owner: Optional[str] = None
    product: Optional[str] = None


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

    # Vulnerability intelligence (CISA KEV / EPSS)
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    cisa_kev: bool = False
    cisa_kev_due_date: Optional[str] = None
    cisa_kev_ransomware_use: bool = False

    # Per-source raw results (for verbose/JSON output)
    sources: dict[str, Any] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)
    explanation: list[str] = field(default_factory=list)
    cached: bool = False

    def set_verdict(self):
        """Derive a verdict only when at least one compatible provider succeeded."""
        self.explanation = []
        if not self.sources:
            self.verdict = "Unknown"
            self.confidence_score = 0
            self.explanation.append("No enrichment source returned usable evidence.")
            return

        if self.ioc.ioc_type == IOCType.IP:
            score = self.abuse_score
            # IP reputation is not limited to AbuseIPDB. VirusTotal and OTX
            # both populate the vote fields for IPs, so do not classify an IP
            # as clean merely because its AbuseIPDB score is low.
            if self.malicious_votes > 0:
                self.verdict = "Malicious"
                self.explanation.append(f"{self.malicious_votes} malicious source signal(s) were returned.")
            elif self.suspicious_votes > 0:
                self.verdict = "Suspicious"
                self.explanation.append(f"{self.suspicious_votes} suspicious source signal(s) were returned.")
            elif score >= 75:
                self.verdict = "Malicious"
                self.explanation.append(f"AbuseIPDB confidence score is {score}%.")
            elif score >= 25:
                self.verdict = "Suspicious"
                self.explanation.append(f"AbuseIPDB confidence score is {score}%.")
            else:
                self.verdict = "Clean"
                self.explanation.append("Successful sources returned no elevated IP reputation signal.")
        elif self.ioc.ioc_type in (IOCType.DOMAIN, IOCType.URL):
            if self.malicious_votes > 0:
                self.verdict = "Malicious"
                self.explanation.append(f"{self.malicious_votes} malicious source signal(s) were returned.")
            elif self.suspicious_votes > 0:
                self.verdict = "Suspicious"
                self.explanation.append(f"{self.suspicious_votes} suspicious source signal(s) were returned.")
            else:
                self.verdict = "Clean"
                self.explanation.append("Successful sources returned no malicious or suspicious signal.")
        elif self.ioc.ioc_type == IOCType.HASH:
            ratio = self.positives / self.total_scanners if self.total_scanners else 0
            if ratio >= 0.5:
                self.verdict = "Malicious"
                self.explanation.append(f"{self.positives}/{self.total_scanners} scanners detected the file.")
            elif ratio > 0:
                self.verdict = "Suspicious"
                self.explanation.append(f"{self.positives}/{self.total_scanners} scanners detected the file.")
            else:
                self.verdict = "Clean"
                self.explanation.append("Successful sources returned no file detections.")
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
                self.explanation.append("The source returned no CVSS score.")

        source_factor = min(45, len(self.sources) * 20)
        signal_factor = 0
        if self.verdict in {"Malicious", "Critical"}:
            signal_factor = 45
        elif self.verdict in {"Suspicious", "High"}:
            signal_factor = 30
        elif self.verdict in {"Clean", "Medium", "Low"}:
            signal_factor = 20
        self.confidence_score = min(100, source_factor + signal_factor)
        self.explanation.append(
            f"Confidence {self.confidence_score}/100 based on {len(self.sources)} successful source(s)."
        )

    def is_decisive(self) -> bool:
        """Whether further paid/limited lookups add little value in normal mode."""
        if self.ioc.ioc_type == IOCType.IP:
            return self.abuse_score >= 90
        if self.ioc.ioc_type in (IOCType.DOMAIN, IOCType.URL):
            return self.malicious_votes >= 5
        if self.ioc.ioc_type == IOCType.HASH:
            return self.total_scanners >= 10 and self.positives / self.total_scanners >= 0.5
        return False

    def to_dict(self) -> dict[str, Any]:
        data = dict(self.__dict__)
        data["ioc"] = {"value": self.ioc.value, "type": self.ioc.ioc_type.value}
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EnrichmentResult":
        ioc_data = data["ioc"]
        known = {field_name for field_name in cls.__dataclass_fields__ if field_name != "ioc"}
        values = {key: value for key, value in data.items() if key in known}
        return cls(ioc=IOC(ioc_data["value"], IOCType(ioc_data["type"])), **values)
