"""
CVE Decision Card — deterministic, explainable triage recommendation.

Given a CVE's enrichment data (NVD CVSS, CISA KEV status, EPSS score) and,
optionally, correlated asset context (internet-facing exposure, business
criticality, whether any inventory asset actually runs the affected
product), produce one of four recommendations:

    Patch          — remediate on the normal patch cycle / urgently
    Isolate        — reduce exposure now (network-isolate / take offline)
                      while remediation is arranged
    Monitor        — no immediate action; watch for new signals
    Not affected   — no known matching asset in the current inventory

This is intentionally a deterministic rule table, not a model or score —
every decision returns a human-readable ``reasons`` list explaining exactly
which inputs drove it, so an analyst can audit and challenge it.

Design notes / limitations
---------------------------
* "Not affected" is only ever returned when asset correlation explicitly
  confirms no inventory asset matches the CVE's affected products *and*
  that correlation was based on actual product/vendor data (not merely the
  absence of an asset inventory). If no asset inventory was supplied, or
  NVD returned no affected-product data to match against, correlation is
  treated as "unknown" and asset context is simply not used to escalate or
  downgrade the decision — see ``AssetContext.has_product_data``.
* CISA KEV listing is treated as a hard floor: a KEV-listed CVE is never
  downgraded to "Monitor" by this function, matching the requirement that
  known-exploited vulnerabilities always receive at least a "Patch"
  recommendation.
* Asset matching itself (see ``src/decision/asset_correlation.py``) is a
  heuristic (hostname/IP/product string matching) and can both miss real
  matches and produce false positives; "Not affected" should be read as
  "no match found by the current heuristic", not an absolute guarantee.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from src.models import EnrichmentResult, IOCType


class Decision(str, Enum):
    PATCH = "Patch"
    ISOLATE = "Isolate"
    MONITOR = "Monitor"
    NOT_AFFECTED = "Not affected"


@dataclass
class AssetContext:
    """
    Asset-correlation context for a single CVE, produced by
    ``src.decision.asset_correlation``.
    """
    # Whether NVD returned affected-product data *and* an asset inventory
    # was available to match against. When False, "matched" below is
    # meaningless and must not be used to infer "Not affected".
    has_product_data: bool = False
    matched: bool = False
    matched_assets: list[dict] = field(default_factory=list)
    any_internet_facing: bool = False
    highest_criticality: Optional[str] = None  # "critical" | "high" | "medium" | "low"


_CRITICAL_CRITICALITY = {"critical", "high"}


@dataclass
class CVEDecisionCard:
    cve_id: str
    decision: Decision
    reasons: list[str]

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "decision": self.decision.value,
            "reasons": list(self.reasons),
        }


def decide(result: EnrichmentResult, asset_context: Optional[AssetContext] = None) -> CVEDecisionCard:
    """Produce a deterministic Patch/Isolate/Monitor/Not affected decision."""
    if result.ioc.ioc_type != IOCType.CVE:
        raise ValueError("CVE decision cards can only be produced for CVE enrichment results")

    ctx = asset_context or AssetContext()
    reasons: list[str] = []

    # ------------------------------------------------------------------
    # 1. "Not affected" — only when correlation is actually informative.
    # ------------------------------------------------------------------
    if ctx.has_product_data and not ctx.matched:
        reasons.append(
            "No asset in the current inventory matches this CVE's affected products/vendor."
        )
        reasons.append(
            "Note: this reflects the asset-matching heuristic and inventory completeness, "
            "not a guarantee the organization is unaffected."
        )
        return CVEDecisionCard(cve_id=result.ioc.value, decision=Decision.NOT_AFFECTED, reasons=reasons)

    # ------------------------------------------------------------------
    # 2. CISA KEV is a hard floor: never "Monitor" once listed.
    # ------------------------------------------------------------------
    if result.cisa_kev:
        reasons.append("Listed in the CISA Known Exploited Vulnerabilities (KEV) catalog.")
        if result.cisa_kev_due_date:
            reasons.append(f"CISA remediation due date: {result.cisa_kev_due_date}.")
        if result.cisa_kev_ransomware_use:
            reasons.append("CISA records known ransomware campaign use of this vulnerability.")

        escalate = ctx.any_internet_facing or (ctx.highest_criticality in _CRITICAL_CRITICALITY)
        if escalate:
            if ctx.any_internet_facing:
                reasons.append("A matched asset is internet-facing.")
            if ctx.highest_criticality in _CRITICAL_CRITICALITY:
                reasons.append(f"Matched asset criticality is '{ctx.highest_criticality}'.")
            reasons.append("Exploitation is confirmed and exposure is significant — isolate pending remediation.")
            return CVEDecisionCard(cve_id=result.ioc.value, decision=Decision.ISOLATE, reasons=reasons)

        reasons.append("Patch per CISA's required action; KEV listing alone always warrants remediation.")
        return CVEDecisionCard(cve_id=result.ioc.value, decision=Decision.PATCH, reasons=reasons)

    # ------------------------------------------------------------------
    # 3. Not KEV-listed — weigh CVSS severity and EPSS exploit probability.
    # ------------------------------------------------------------------
    cvss = result.cvss_score
    epss = result.epss_score

    high_severity = cvss is not None and cvss >= 9.0
    likely_severe = cvss is not None and cvss >= 7.0 and epss is not None and epss >= 0.5
    moderate_severity = cvss is not None and cvss >= 7.0
    elevated_epss = epss is not None and epss >= 0.1

    if cvss is not None:
        reasons.append(f"NVD CVSS base score is {cvss} ({result.severity or 'unrated'}).")
    else:
        reasons.append("NVD returned no CVSS score for this CVE.")
    if epss is not None:
        reasons.append(f"EPSS exploit probability is {epss:.2f} (percentile {result.epss_percentile}).")

    if high_severity or likely_severe:
        exposed = ctx.any_internet_facing and (ctx.highest_criticality in _CRITICAL_CRITICALITY)
        if exposed:
            reasons.append("A matched asset is internet-facing and business-critical.")
            reasons.append("Critical severity plus significant exposure — isolate pending remediation.")
            return CVEDecisionCard(cve_id=result.ioc.value, decision=Decision.ISOLATE, reasons=reasons)
        reasons.append("Severity and/or predicted exploitation likelihood is high — patch promptly.")
        return CVEDecisionCard(cve_id=result.ioc.value, decision=Decision.PATCH, reasons=reasons)

    if moderate_severity or elevated_epss:
        if ctx.any_internet_facing and ctx.highest_criticality in _CRITICAL_CRITICALITY:
            reasons.append("Elevated severity/exploitation signal on an internet-facing, critical asset — patch.")
            return CVEDecisionCard(cve_id=result.ioc.value, decision=Decision.PATCH, reasons=reasons)
        reasons.append("Severity/exploitation signal is elevated but exposure is limited — monitor for change.")
        return CVEDecisionCard(cve_id=result.ioc.value, decision=Decision.MONITOR, reasons=reasons)

    reasons.append("No CISA KEV listing, low/unknown severity, and low predicted exploitation — monitor.")
    return CVEDecisionCard(cve_id=result.ioc.value, decision=Decision.MONITOR, reasons=reasons)
