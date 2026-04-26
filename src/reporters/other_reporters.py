"""
JSON & CSV Reporters — machine-readable output formats.
"""

from __future__ import annotations

import json
import csv
import datetime
from pathlib import Path
from typing import List
from dataclasses import asdict

from src.models import EnrichmentResult


class JSONReporter:

    def generate(
        self,
        results: List[EnrichmentResult],
        output_dir: str = "output",
    ) -> str:
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = str(Path(output_dir) / f"ThreatLens_Report_{ts}.json")

        data = {
            "meta": {
                "tool": "ThreatLens",
                "version": "2.0.0",
                "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
                "total_iocs": len(results),
            },
            "results": [self._serialize(r) for r in results],
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

        return filepath

    @staticmethod
    def _serialize(r: EnrichmentResult) -> dict:
        return {
            "ioc": {"value": r.ioc.value, "type": r.ioc.ioc_type.value},
            "verdict": r.verdict,
            "country": r.country,
            "isp": r.isp,
            "organization": r.organization,
            "asn": r.asn,
            # IP
            "abuse_score": r.abuse_score,
            "total_reports": r.total_reports,
            "last_reported": r.last_reported,
            "open_ports": r.open_ports,
            "shodan_vulns": r.shodan_vulns,
            "hostnames": r.hostnames,
            # Domain/URL
            "malicious_votes": r.malicious_votes,
            "suspicious_votes": r.suspicious_votes,
            "harmless_votes": r.harmless_votes,
            "categories": r.categories,
            "urlscan_verdict": r.urlscan_verdict,
            # Hash
            "file_name": r.file_name,
            "file_type": r.file_type,
            "file_size": r.file_size,
            "positives": r.positives,
            "total_scanners": r.total_scanners,
            # CVE
            "cvss_score": r.cvss_score,
            "severity": r.severity,
            "cve_description": r.cve_description,
            "published_date": r.published_date,
            "affected_products": r.affected_products,
            # Meta
            "sources": r.sources,
            "errors": r.errors,
        }


class CSVReporter:

    FIELDS = [
        "ioc_value", "ioc_type", "verdict", "country", "isp", "organization", "asn",
        "abuse_score", "total_reports", "last_reported", "open_ports", "shodan_vulns",
        "malicious_votes", "suspicious_votes", "harmless_votes", "categories",
        "urlscan_verdict", "file_name", "file_type", "file_size", "positives",
        "total_scanners", "cvss_score", "severity", "cve_description", "published_date",
        "errors",
    ]

    def generate(
        self,
        results: List[EnrichmentResult],
        output_dir: str = "output",
    ) -> str:
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = str(Path(output_dir) / f"ThreatLens_Report_{ts}.csv")

        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=self.FIELDS)
            writer.writeheader()
            for r in results:
                writer.writerow({
                    "ioc_value": r.ioc.value,
                    "ioc_type": r.ioc.ioc_type.value,
                    "verdict": r.verdict,
                    "country": r.country or "",
                    "isp": r.isp or "",
                    "organization": r.organization or "",
                    "asn": r.asn or "",
                    "abuse_score": r.abuse_score,
                    "total_reports": r.total_reports,
                    "last_reported": r.last_reported or "",
                    "open_ports": "|".join(str(p) for p in r.open_ports),
                    "shodan_vulns": "|".join(r.shodan_vulns),
                    "malicious_votes": r.malicious_votes,
                    "suspicious_votes": r.suspicious_votes,
                    "harmless_votes": r.harmless_votes,
                    "categories": "|".join(r.categories),
                    "urlscan_verdict": r.urlscan_verdict or "",
                    "file_name": r.file_name or "",
                    "file_type": r.file_type or "",
                    "file_size": r.file_size or "",
                    "positives": r.positives,
                    "total_scanners": r.total_scanners,
                    "cvss_score": r.cvss_score or "",
                    "severity": r.severity or "",
                    "cve_description": (r.cve_description or "")[:200],
                    "published_date": r.published_date or "",
                    "errors": "; ".join(f"{k}:{v}" for k, v in r.errors.items()),
                })

        return filepath
