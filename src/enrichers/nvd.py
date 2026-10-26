"""
NVD Enricher — NIST National Vulnerability Database.
Supports: CVE
Free tier: 50 requests per 30s (no key), 2000/30s (with key)
https://nvd.nist.gov/developers/vulnerabilities
"""

from src.models import IOC, IOCType, EnrichmentResult
from src.enrichers.base import BaseEnricher
from src.utils.security import allowlisted_object, api_cve, api_float, api_text, validate_ioc, IOCValidationError


class NVDEnricher(BaseEnricher):
    name = "nvd"
    supports = [IOCType.CVE]

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    allowed_hosts = {"services.nvd.nist.gov"}

    def is_available(self) -> bool:
        return True  # Free without key

    def _headers(self) -> dict:
        h = {}
        if self.api_key:
            h["apiKey"] = self.api_key
        return h

    def enrich(self, ioc: IOC, result: EnrichmentResult) -> EnrichmentResult:
        if ioc.ioc_type != IOCType.CVE:
            return result

        data = self.get(
            self.BASE_URL,
            params={"cveId": ioc.value},
            headers=self._headers(),
        )

        if not data:
            result.errors[self.name] = "No data"
            return result

        vulns = data.get("vulnerabilities")
        if not isinstance(vulns, list) or not vulns:
            result.errors[self.name] = "CVE not found"
            return result

        envelope = allowlisted_object(vulns[0], {"cve"})
        cve_item = allowlisted_object(
            envelope.get("cve"),
            {"id", "descriptions", "published", "metrics", "configurations", "references"},
        )
        if api_cve(cve_item.get("id")) != ioc.value.upper():
            result.errors[self.name] = "Provider response did not match the requested CVE"
            return result

        # Description (English preferred)
        descriptions = cve_item.get("descriptions")
        for raw_desc in descriptions[:50] if isinstance(descriptions, list) else []:
            desc = allowlisted_object(raw_desc, {"lang", "value"})
            if desc.get("lang") == "en":
                result.cve_description = api_text(desc.get("value"), max_length=16_384)
                break

        # Published date
        published = api_text(cve_item.get("published"), max_length=64)
        result.published_date = published[:10] if published and len(published) >= 10 else None

        # CVSS Score — try v3.1, then v3.0, then v2.0
        metrics = allowlisted_object(cve_item.get("metrics"), {"cvssMetricV31", "cvssMetricV30", "cvssMetricV2"})
        cvss_data = None
        for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(version_key)
            if isinstance(metric_list, list) and metric_list:
                metric = allowlisted_object(metric_list[0], {"cvssData"})
                cvss_data = allowlisted_object(metric.get("cvssData"), {"baseScore", "baseSeverity"})
                result.cvss_version = version_key.replace("cvssMetric", "CVSS ")
                break

        if cvss_data:
            result.cvss_score = api_float(cvss_data.get("baseScore"), maximum=10.0)
            severity = api_text(cvss_data.get("baseSeverity"), max_length=16)
            result.severity = severity.upper() if severity and severity.upper() in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} else _score_to_severity(result.cvss_score)

        # Affected products (CPE)
        configurations = cve_item.get("configurations", [])
        products = set()
        for raw_config in configurations[:100] if isinstance(configurations, list) else []:
            config = allowlisted_object(raw_config, {"nodes"})
            for raw_node in config.get("nodes", [])[:100] if isinstance(config.get("nodes"), list) else []:
                node = allowlisted_object(raw_node, {"cpeMatch"})
                matches = node.get("cpeMatch")
                for raw_match in matches[:200] if isinstance(matches, list) else []:
                    cpe_match = allowlisted_object(raw_match, {"criteria"})
                    cpe = api_text(cpe_match.get("criteria"), max_length=512) or ""
                    if not cpe.startswith("cpe:2.3:"):
                        continue
                    parts = cpe.split(":")
                    if len(parts) >= 5:
                        vendor = parts[3].replace("_", " ").title()
                        product = parts[4].replace("_", " ").title()
                        if vendor and product:
                            products.add(f"{vendor} {product}")
        result.affected_products = sorted(products)[:20]  # Cap at 20

        # References
        refs = cve_item.get("references", [])
        result.references = []
        for raw_reference in refs[:10] if isinstance(refs, list) else []:
            reference = allowlisted_object(raw_reference, {"url"})
            url = api_text(reference.get("url"), max_length=2048)
            if url:
                try:
                    result.references.append(validate_ioc(url, IOCType.URL))
                except IOCValidationError:
                    continue

        result.sources[self.name] = {
            "cvss_score": result.cvss_score,
            "severity": result.severity,
            "published": result.published_date,
            "affected_count": len(result.affected_products),
        }

        return result


def _score_to_severity(score: float | None) -> str:
    if score is None:
        return "Unknown"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"
