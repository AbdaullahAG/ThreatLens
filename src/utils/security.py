"""Validation, output-neutralisation, and secret-redaction helpers."""

from __future__ import annotations

import ipaddress
import json
import math
import re
import unicodedata
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from src.models import IOC, IOCType


class IOCValidationError(ValueError):
    """Raised when an observable does not meet the accepted format."""


_HASH_LENGTHS = {32, 40, 64}
_CVE_RE = re.compile(r"^CVE-(?:1999|2\d{3})-\d{4,7}$", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$",
    re.IGNORECASE,
)
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n")
_SENSITIVE_QUERY_MARKERS = (
    "token", "secret", "password", "passwd", "authorization", "auth",
    "credential", "session", "signature", "apikey", "accesskey", "jwt", "code",
)
_JSON_KEY_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_CVE_FIELD_RE = re.compile(r"^CVE-(?:1999|2\d{3})-\d{4,7}$", re.IGNORECASE)
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)([\"']?(?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|secret|password|passwd|authorization)[\"']?\s*[:=]\s*[\"']?)([^&\s,\"']+)"
)
_BEARER_RE = re.compile(r"(?i)(\bBearer\s+)[A-Za-z0-9._~+/=-]{8,}")
_SENSITIVE_FIELD_RE = re.compile(
    r"(?i)(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|secret|password|passwd|authorization|auth[_-]?token|hec[_-]?token)"
)
MAX_API_RESPONSE_BYTES = 10 * 1024 * 1024


def _contains_controls(value: str) -> bool:
    return any(unicodedata.category(char) == "Cc" for char in value)


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
    try:
        parsed = urlsplit(value.strip())
    except ValueError as exc:
        raise IOCValidationError("URL authority is invalid") from exc
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


def sanitize_ioc_for_external(ioc: IOC) -> IOC:
    """Return an IOC copy with sensitive URL query parameters removed.

    The caller keeps the original IOC for local output and storage. Only the
    copy passed to external providers is sanitized.
    """
    if ioc.ioc_type != IOCType.URL:
        return IOC(value=ioc.value, ioc_type=ioc.ioc_type)

    parsed = urlsplit(ioc.value)
    safe_query = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        normalized_key = re.sub(r"[^a-z0-9]", "", key.lower())
        if any(marker in normalized_key for marker in _SENSITIVE_QUERY_MARKERS):
            continue
        safe_query.append((key, value))

    safe_value = urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urlencode(safe_query, doseq=True), "")
    )
    return IOC(value=safe_value, ioc_type=ioc.ioc_type)


def validate_https_endpoint(
    url: str,
    allowed_hosts: set[str],
    *,
    allowed_query_keys: set[str] | None = None,
    allowed_authorities: set[tuple[str, int | None]] | None = None,
) -> bool:
    """Check a configured/request URL against an exact HTTPS host allow-list."""
    if not isinstance(url, str) or not 1 <= len(url) <= 4096:
        return False
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").rstrip(".").lower()
        port = parsed.port
    except (TypeError, ValueError):
        return False
    query_keys = {key for key, _value in parse_qsl(parsed.query, keep_blank_values=True)}
    return bool(
        parsed.scheme.lower() == "https"
        and host
        and host in {item.rstrip(".").lower() for item in allowed_hosts}
        and parsed.username is None
        and parsed.password is None
        and (port is None or 1 <= port <= 65535)
        and (
            (host, port) in {
                (authority_host.rstrip(".").lower(), authority_port)
                for authority_host, authority_port in allowed_authorities
            }
            if allowed_authorities is not None
            else port in (None, 443)
        )
        and query_keys.issubset(allowed_query_keys or set())
        and not parsed.fragment
    )


def bounded_response_bytes(response: Any, max_bytes: int) -> bytes | None:
    """Read an HTTP body in bounded chunks, closing the response in all cases."""
    try:
        try:
            content_length = response.headers.get("Content-Length")
            if content_length is not None and int(content_length) > max_bytes:
                return None
        except (TypeError, ValueError):
            return None
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_content(chunk_size=64 * 1024):
            if not chunk:
                continue
            total += len(chunk)
            if total > max_bytes:
                return None
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        close = getattr(response, "close", None)
        if callable(close):
            close()


def bounded_json_response(response: Any, max_bytes: int = MAX_API_RESPONSE_BYTES) -> dict | None:
    """Read and validate a bounded JSON object from an HTTP response."""
    try:
        body = bounded_response_bytes(response, max_bytes)
        if body is None:
            return None
        payload = json.loads(body)
    except (ValueError, TypeError, json.JSONDecodeError):
        return None

    if not isinstance(payload, dict):
        return None
    return _validate_json_tree(payload)


def _validate_json_tree(value: Any, *, depth: int = 0, budget: list[int] | None = None) -> Any:
    """Allow bounded JSON primitives and safe key syntax from provider payloads."""
    if budget is None:
        budget = [50_000]
    budget[0] -= 1
    if budget[0] < 0 or depth > 24:
        raise ValueError("provider response exceeds structural limits")
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("provider response contains a non-finite number")
        return value
    if isinstance(value, str):
        if len(value) > 65_536:
            raise ValueError("provider response string exceeds field limit")
        return "".join(ch for ch in value if ch in "\t\n\r" or ord(ch) >= 32)
    if isinstance(value, list):
        if len(value) > 10_000:
            raise ValueError("provider response list exceeds field limit")
        return [_validate_json_tree(item, depth=depth + 1, budget=budget) for item in value]
    if isinstance(value, dict):
        if len(value) > 10_000:
            raise ValueError("provider response object exceeds field limit")
        safe: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not _JSON_KEY_RE.fullmatch(key):
                continue
            safe[key] = _validate_json_tree(item, depth=depth + 1, budget=budget)
        return safe
    raise ValueError("provider response contains an unsupported value")


def allowlisted_object(value: Any, allowed_keys: set[str]) -> dict[str, Any]:
    """Return only named fields from an API object, or an empty mapping."""
    if not isinstance(value, dict):
        return {}
    return {key: value[key] for key in allowed_keys if key in value}


def api_text(value: Any, *, max_length: int = 2_048) -> str | None:
    """Accept a bounded printable text field from a provider response."""
    if not isinstance(value, str) or len(value) > max_length or _contains_controls(value):
        return None
    return value


def api_country(value: Any) -> str | None:
    """Accept only two-letter uppercase country/region codes."""
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z]{2}", value):
        return None
    return value.upper()


def api_hostname(value: Any) -> str | None:
    """Accept a bounded DNS hostname including single-label inventory names."""
    if not isinstance(value, str) or not 1 <= len(value) <= 253 or _contains_controls(value):
        return None
    try:
        normalized = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    labels = normalized.split(".")
    if not labels or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
        return None
    return normalized


def api_public_ip(value: Any) -> str | None:
    """Accept only public IPv4/IPv6 address fields returned by a provider."""
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    return str(address) if address.is_global else None


def api_integer(value: Any, *, minimum: int = 0, maximum: int = 10_000_000) -> int | None:
    """Accept only bounded integer fields; booleans and numeric strings fail."""
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        return None
    return value


def api_float(value: Any, *, minimum: float = 0.0, maximum: float = 1.0) -> float | None:
    """Accept a finite, bounded floating-point field from a provider."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) and minimum <= number <= maximum else None


def api_probability(value: Any) -> float | None:
    """Accept EPSS decimal strings or numbers in the inclusive [0, 1] range."""
    if isinstance(value, str):
        if len(value) > 16 or not re.fullmatch(r"(?:0(?:\.\d{1,12})?|1(?:\.0{1,12})?)", value):
            return None
        value = float(value)
    return api_float(value)


def api_cve(value: Any) -> str | None:
    """Return a canonical CVE ID only when it matches the accepted syntax."""
    if isinstance(value, str) and _CVE_FIELD_RE.fullmatch(value):
        return value.upper()
    return None


def api_cve_list(value: Any, *, max_items: int = 100) -> list[str]:
    """Keep only syntactically valid CVE identifiers from an API response."""
    if not isinstance(value, list):
        return []
    return [
        item.upper()
        for item in value[:max_items]
        if isinstance(item, str) and _CVE_FIELD_RE.fullmatch(item)
    ]


def api_string_list(value: Any, *, max_items: int = 100, max_length: int = 512) -> list[str]:
    """Keep only bounded printable strings from an API list."""
    if not isinstance(value, list):
        return []
    return [
        item for item in (api_text(entry, max_length=max_length) for entry in value[:max_items])
        if item is not None
    ]


def api_hostname_list(value: Any, *, max_items: int = 100) -> list[str]:
    """Keep only syntactically valid DNS hostnames from a provider list."""
    if not isinstance(value, list):
        return []
    return [
        hostname for hostname in (api_hostname(item) for item in value[:max_items])
        if hostname is not None
    ]


def api_mapping_values(value: Any, *, max_items: int = 100, max_length: int = 512) -> list[str]:
    """Keep bounded string values from an API mapping with dynamic keys."""
    if not isinstance(value, dict):
        return []
    values = list(value.values())[:max_items]
    return api_string_list(values, max_items=max_items, max_length=max_length)


def sanitize_sensitive_data(value: Any, secrets: Iterable[str] = ()) -> Any:
    """Recursively redact configured secrets and credential-like URL parameters."""
    secret_values = tuple(secrets)
    if isinstance(value, str):
        sanitized = redact_secrets(value, *secret_values)
        try:
            parsed = urlsplit(sanitized)
            if parsed.scheme in {"http", "https"} and parsed.hostname:
                return sanitize_ioc_for_external(IOC(sanitized, IOCType.URL)).value
        except (ValueError, TypeError):
            pass
        return sanitized
    if isinstance(value, list):
        return [sanitize_sensitive_data(item, secret_values) for item in value]
    if isinstance(value, tuple):
        return [sanitize_sensitive_data(item, secret_values) for item in value]
    if isinstance(value, dict):
        safe: dict[Any, Any] = {}
        for key, item in value.items():
            if isinstance(key, str) and _SENSITIVE_FIELD_RE.search(key):
                safe_key = sanitize_sensitive_data(key, secret_values)
                safe[safe_key] = "[REDACTED]"
            else:
                safe_key = sanitize_sensitive_data(key, secret_values) if isinstance(key, str) else key
                safe[safe_key] = sanitize_sensitive_data(item, secret_values)
        return safe
    return value


def sanitize_result_for_output(result: Any, secrets: Iterable[str] = ()) -> Any:
    """Clone an enrichment result after redacting secrets and sensitive URLs."""
    from src.models import EnrichmentResult

    if not isinstance(result, EnrichmentResult):
        raise TypeError("result must be an EnrichmentResult")
    clean = sanitize_sensitive_data(result.to_dict(), secrets)
    return EnrichmentResult.from_dict(clean)


def has_control_characters(value: str) -> bool:
    """Public wrapper so other modules (CSV/log importers) can reuse this check."""
    return _contains_controls(value)


def spreadsheet_value(value: object) -> object:
    """Neutralise formulas after leading whitespace while retaining numbers."""
    if not isinstance(value, str):
        return value
    cleaned = value.replace("\x00", "")
    # Spreadsheet programs may ignore leading whitespace/control characters
    # when deciding whether a cell begins with a formula. Prefix the original
    # value so the displayed content is preserved while the formula is inert.
    return f"'{cleaned}" if cleaned.lstrip().startswith(_FORMULA_PREFIXES) else cleaned


def redact_secrets(value: object, *secrets: str | None) -> str:
    """Create a one-line safe diagnostic without exposing known secret values."""
    text = str(value).replace("\r", " ").replace("\n", " ")
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[REDACTED]")
    text = _SECRET_ASSIGNMENT_RE.sub(r"\1[REDACTED]", text)
    return _BEARER_RE.sub(r"\1[REDACTED]", text)
