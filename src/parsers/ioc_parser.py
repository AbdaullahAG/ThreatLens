"""
IOC Parser — extracts IPs, domains, URLs, hashes, and CVEs
from raw text / log files using regular expressions.
"""

import re
import ipaddress
from pathlib import Path
from typing import NamedTuple

from src.models import IOC, IOCType
from src.utils.security import IOCValidationError, validate_ioc


# ---------------------------------------------------------------------------
# Regex Patterns
# ---------------------------------------------------------------------------

_RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Domain: must have a dot, TLD of 2–6 chars, no leading/trailing hyphens
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|co|gov|edu|mil|int|info|biz|me|tv|app|dev|cloud|"
    r"xyz|online|site|tech|store|blog|ai|security|cyber|arpa|[a-z]{2})\b",
    re.IGNORECASE,
)

_RE_URL = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)

# MD5, SHA1, SHA256
_RE_HASH = re.compile(r"\b([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\b")

_RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# Common false-positive domain suffixes to reject
_DOMAIN_BLACKLIST = {
    "localhost", "example.com", "test.com", "invalid",
}

# Private / reserved IP ranges
def _is_public_ip(ip_str: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip_str)
        return not (
            obj.is_private
            or obj.is_loopback
            or obj.is_multicast
            or obj.is_reserved
            or obj.is_link_local
            or obj.is_unspecified
        )
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Parser class
# ---------------------------------------------------------------------------

class ParseResult(NamedTuple):
    iocs: list[IOC]
    ignored_ips: list[str]
    stats: dict[str, int]
    truncated: bool = False


class IOCParser:
    """
    Parses a string (log content) and extracts all IOC types.
    Can also read directly from a file path.
    """

    def __init__(self, max_file_bytes: int = 10 * 1024 * 1024, max_iocs: int = 1_000):
        self.max_file_bytes = max_file_bytes
        self.max_iocs = max_iocs

    def parse_file(self, path: str) -> ParseResult:
        """Read a file and parse its contents."""
        file_path = Path(path)
        if not file_path.is_file():
            raise FileNotFoundError(f"Log file not found: {path}")
        if file_path.stat().st_size > self.max_file_bytes:
            raise ValueError(
                f"Log file exceeds the configured {self.max_file_bytes // (1024 * 1024)} MiB limit"
            )
        text = file_path.read_text(encoding="utf-8", errors="replace")
        return self.parse_text(text)

    def parse_text(self, text: str) -> ParseResult:
        """Extract all IOCs from a raw text string."""
        iocs: list[IOC] = []
        ignored_ips: list[str] = []
        seen: set[str] = set()
        truncated = False

        def add(value: str, ioc_type: IOCType):
            nonlocal truncated
            if len(iocs) >= self.max_iocs:
                truncated = True
                return
            key = f"{ioc_type}:{value.lower()}"
            if key not in seen:
                try:
                    value = validate_ioc(value, ioc_type)
                except IOCValidationError:
                    return
                seen.add(key)
                iocs.append(IOC(value=value, ioc_type=ioc_type))

        # --- Extract URLs first (before domains consume them) ---
        for url in _RE_URL.findall(text):
            add(url.rstrip(".,;)\"'"), IOCType.URL)

        # --- Extract IPs ---
        for raw_ip in _RE_IPV4.findall(text):
            if _is_public_ip(raw_ip):
                add(raw_ip, IOCType.IP)
            else:
                if raw_ip not in ignored_ips:
                    ignored_ips.append(raw_ip)

        # --- Extract Domains (skip those inside already-found URLs) ---
        # Strip URLs from text so we don't double-count
        clean_text = _RE_URL.sub("", text)
        for domain in _RE_DOMAIN.findall(clean_text):
            domain_lower = domain.lower()
            if domain_lower not in _DOMAIN_BLACKLIST:
                # Skip if it's actually an IP
                if not _RE_IPV4.fullmatch(domain):
                    add(domain, IOCType.DOMAIN)

        # --- Extract Hashes ---
        for h in _RE_HASH.findall(text):
            add(h.lower(), IOCType.HASH)

        # --- Extract CVEs ---
        for cve in _RE_CVE.findall(text):
            add(cve.upper(), IOCType.CVE)

        stats = {
            "ip": sum(1 for x in iocs if x.ioc_type == IOCType.IP),
            "domain": sum(1 for x in iocs if x.ioc_type == IOCType.DOMAIN),
            "url": sum(1 for x in iocs if x.ioc_type == IOCType.URL),
            "hash": sum(1 for x in iocs if x.ioc_type == IOCType.HASH),
            "cve": sum(1 for x in iocs if x.ioc_type == IOCType.CVE),
            "ignored_private_ips": len(ignored_ips),
        }

        return ParseResult(iocs=iocs, ignored_ips=ignored_ips, stats=stats, truncated=truncated)

    @staticmethod
    def from_args(
        ips=None, domains=None, hashes=None, cves=None, allow_private: bool = False
    ) -> list[IOC]:
        """Build IOC list from explicit CLI arguments."""
        result: list[IOC] = []
        for ip in (ips or []):
            result.append(IOC(value=validate_ioc(ip, IOCType.IP, allow_private=allow_private), ioc_type=IOCType.IP))
        for d in (domains or []):
            t = IOCType.URL if d.strip().lower().startswith(("http://", "https://")) else IOCType.DOMAIN
            result.append(IOC(value=validate_ioc(d, t, allow_private=allow_private), ioc_type=t))
        for h in (hashes or []):
            result.append(IOC(value=validate_ioc(h, IOCType.HASH), ioc_type=IOCType.HASH))
        for cve in (cves or []):
            result.append(IOC(value=validate_ioc(cve, IOCType.CVE), ioc_type=IOCType.CVE))
        return result
