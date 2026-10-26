"""
IOC Parser — extracts IPs, domains, URLs, hashes, and CVEs
from raw text / log files using regular expressions.
"""

import re
import ipaddress
from pathlib import Path
import os
import stat
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
        if not isinstance(path, str) or not path or len(path) > 4096 or any(ord(ch) < 32 or ord(ch) == 127 for ch in path):
            raise ValueError("Log file path is invalid")
        file_path = Path(path)
        try:
            with file_path.open("rb") as handle:
                file_stat = os.fstat(handle.fileno())
                if not stat.S_ISREG(file_stat.st_mode):
                    raise ValueError("Log input must be a regular file")
                if file_stat.st_size > self.max_file_bytes:
                    raise ValueError("Log file exceeds the configured size limit")
                text = handle.read(self.max_file_bytes + 1).decode("utf-8", errors="replace")
        except FileNotFoundError:
            raise FileNotFoundError("Log file not found") from None
        if len(text.encode("utf-8", errors="replace")) > self.max_file_bytes:
            raise ValueError("Log file exceeds the configured size limit")
        return self.parse_text(text)

    def parse_text(self, text: str) -> ParseResult:
        """Extract all IOCs from a raw text string."""
        if not isinstance(text, str) or len(text) > self.max_file_bytes:
            raise ValueError("Log text exceeds the configured size limit")
        iocs: list[IOC] = []
        ignored_ips: list[str] = []
        ignored_ip_set: set[str] = set()
        ignored_ip_count = 0
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
                ignored_ip_count += 1
                if raw_ip not in ignored_ip_set and len(ignored_ips) < self.max_iocs:
                    ignored_ips.append(raw_ip)
                    ignored_ip_set.add(raw_ip)

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
            "ignored_private_ips": ignored_ip_count,
        }

        return ParseResult(iocs=iocs, ignored_ips=ignored_ips, stats=stats, truncated=truncated)

    @staticmethod
    def from_args(
        ips: list[str] | None = None,
        domains: list[str] | None = None,
        hashes: list[str] | None = None,
        cves: list[str] | None = None,
        allow_private: bool = False,
        max_iocs: int = 10_000,
    ) -> list[IOC]:
        """Build IOC list from explicit CLI arguments."""
        if isinstance(max_iocs, bool) or not isinstance(max_iocs, int) or max_iocs < 1:
            raise ValueError("max_iocs must be a positive integer")
        result: list[IOC] = []
        seen: set[str] = set()

        def add_values(values: list[str] | None, ioc_type: IOCType, *, url_aware: bool = False) -> bool:
            for value in values or []:
                if len(result) >= max_iocs:
                    return False
                if not isinstance(value, str):
                    raise IOCValidationError("IOC must be a text value")
                actual_type = ioc_type
                if url_aware and value.strip().lower().startswith(("http://", "https://")):
                    actual_type = IOCType.URL
                canonical = validate_ioc(value, actual_type, allow_private=allow_private)
                key = f"{actual_type.value}:{canonical.lower()}"
                if key in seen:
                    continue
                seen.add(key)
                result.append(IOC(value=canonical, ioc_type=actual_type))
            return True

        if not add_values(ips, IOCType.IP):
            return result
        if not add_values(domains, IOCType.DOMAIN, url_aware=True):
            return result
        if not add_values(hashes, IOCType.HASH):
            return result
        add_values(cves, IOCType.CVE)
        return result
