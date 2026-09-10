"""Validation, output-neutralisation, and secret-redaction helpers."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

from src.models import IOCType


class IOCValidationError(ValueError):
    """Raised when an observable does not meet the accepted format."""


_HASH_LENGTHS = {32, 40, 64}
_CVE_RE = re.compile(r"^CVE-(?:1999|2\d{3})-\d{4,7}$", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$",
    re.IGNORECASE,
)
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n")


def _contains_controls(value: str) -> bool:
    return any(ord(char) < 32 or ord(char) == 127 for char in value)


def _validate_ip(value: str, allow_private: bool) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise IOCValidationError("IP address is invalid") from exc
    if not allow_private and not address.is_global:
        raise IOCValidationError("non-public IP addresses require --allow-private-iocs")
    return str(address)


def _validate_domain(value: str) -> str:
    try:
        domain = value.strip().rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise IOCValidationError("domain cannot be IDNA-normalised") from exc
    if not _DOMAIN_RE.fullmatch(domain) or ".." in domain:
        raise IOCValidationError("domain is invalid")
    return domain


def _validate_url(value: str, allow_private: bool) -> str:
    if _contains_controls(value):
        raise IOCValidationError("URL contains control characters")
    parsed = urlsplit(value.strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise IOCValidationError("URL must use http or https and include a host")
    if parsed.username or parsed.password:
        raise IOCValidationError("URLs with credentials are not accepted")
    host = parsed.hostname
    try:
        _validate_ip(host, allow_private)
        normalized_host = host
    except IOCValidationError:
        # A non-IP hostname is validated as a domain. An invalid IP-like host fails here.
        if re.fullmatch(r"[0-9a-fA-F:.]+", host):
            raise
        normalized_host = _validate_domain(host)
    try:
        port = parsed.port
    except ValueError as exc:
        raise IOCValidationError("URL port is invalid") from exc
    netloc = normalized_host if port is None else f"{normalized_host}:{port}"
    # Fragments are never sent to HTTP services and can carry sensitive client-side data.
    return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, ""))


def validate_ioc(value: str, ioc_type: IOCType, *, allow_private: bool = False) -> str:
    """Return a canonical IOC value or reject it using allow-list validation."""
    if not isinstance(value, str) or not value.strip() or len(value) > 2048:
        raise IOCValidationError("IOC must be a non-empty value no longer than 2048 characters")
    if _contains_controls(value):
        raise IOCValidationError("IOC contains control characters")

    value = value.strip()
    if ioc_type == IOCType.IP:
        return _validate_ip(value, allow_private)
    if ioc_type == IOCType.DOMAIN:
        return _validate_domain(value)
    if ioc_type == IOCType.URL:
        return _validate_url(value, allow_private)
    if ioc_type == IOCType.HASH:
        if len(value) not in _HASH_LENGTHS or not re.fullmatch(r"[0-9a-fA-F]+", value):
            raise IOCValidationError("hash must be a MD5, SHA1, or SHA256 hex value")
        return value.lower()
    if ioc_type == IOCType.CVE:
        if not _CVE_RE.fullmatch(value):
            raise IOCValidationError("CVE must match CVE-YYYY-NNNN")
        return value.upper()
    raise IOCValidationError("unsupported IOC type")


def spreadsheet_value(value: object) -> object:
    """Neutralise CSV/Excel formulas while retaining native numeric values."""
    if not isinstance(value, str):
        return value
    cleaned = value.replace("\x00", "")
    return f"'{cleaned}" if cleaned.startswith(_FORMULA_PREFIXES) else cleaned


def redact_secrets(value: object, *secrets: str | None) -> str:
    """Create a one-line safe diagnostic without exposing known secret values."""
    text = str(value).replace("\r", " ").replace("\n", " ")
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[REDACTED]")
    return re.sub(r"(?i)(api[_-]?key|key|token|secret)=([^&\s]+)", r"\1=[REDACTED]", text)
