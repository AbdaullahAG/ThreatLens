"""
NVD Enricher — NIST National Vulnerability Database.
Supports: CVE
Free tier: 50 requests per 30s (no key), 2000/30s (with key)
https://nvd.nist.gov/developers/vulnerabilities
"""

from src.models import IOC, IOCType, EnrichmentResult
from src.enrichers.base import BaseEnricher


class NVDEnricher(BaseEnricher):
    name = "nvd"
    supports = [IOCType.CVE]

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

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

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            result.errors[self.name] = "CVE not found"
            return result

        cve_item = vulns[0].get("cve", {})

        # Description (English preferred)
        descriptions = cve_item.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                result.cve_description = desc.get("value")
                break

        # Published date
        result.published_date = cve_item.get("published", "")[:10]

        # CVSS Score — try v3.1, then v3.0, then v2.0
        metrics = cve_item.get("metrics", {})
        cvss_data = None
        for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(version_key)
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                result.cvss_version = version_key.replace("cvssMetric", "CVSS ")
                break

        if cvss_data:
            result.cvss_score = cvss_data.get("baseScore")
            result.severity = cvss_data.get("baseSeverity") or _score_to_severity(result.cvss_score)

        # Affected products (CPE)
        configurations = cve_item.get("configurations", [])
        products = set()
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    cpe = cpe_match.get("criteria", "")
                    parts = cpe.split(":")
                    if len(parts) >= 5:
                        vendor = parts[3].replace("_", " ").title()
                        product = parts[4].replace("_", " ").title()
                        if vendor and product:
                            products.add(f"{vendor} {product}")
        result.affected_products = sorted(products)[:20]  # Cap at 20

        # References
        refs = cve_item.get("references", [])
        result.references = [r.get("url", "") for r in refs[:10]]

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
