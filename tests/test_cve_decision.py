"""Unit tests for the deterministic CVE Decision Card logic."""

from __future__ import annotations

import pytest

from src.decision.cve_decision import AssetContext, Decision, decide
from src.models import IOC, IOCType, EnrichmentResult


def _cve_result(cve="CVE-2021-44228", **overrides) -> EnrichmentResult:
    result = EnrichmentResult(ioc=IOC(cve, IOCType.CVE))
    for key, value in overrides.items():
        setattr(result, key, value)
    return result


class TestNotAffected:
    def test_no_matching_asset_when_product_data_present(self):
        result = _cve_result(cvss_score=9.8, severity="CRITICAL")
        ctx = AssetContext(has_product_data=True, matched=False)
        card = decide(result, ctx)
        assert card.decision == Decision.NOT_AFFECTED

    def test_kev_but_no_matching_asset_still_not_affected(self):
        """Matching takes priority over KEV since 'no product data' precedes it."""
        result = _cve_result(cisa_kev=True, cvss_score=10.0)
        ctx = AssetContext(has_product_data=True, matched=False)
        card = decide(result, ctx)
        assert card.decision == Decision.NOT_AFFECTED

    def test_no_inventory_data_does_not_trigger_not_affected(self):
        result = _cve_result(cvss_score=2.0)
        ctx = AssetContext(has_product_data=False, matched=False)
        card = decide(result, ctx)
        assert card.decision != Decision.NOT_AFFECTED

    def test_no_context_at_all_does_not_trigger_not_affected(self):
        result = _cve_result(cvss_score=2.0)
        card = decide(result, None)
        assert card.decision != Decision.NOT_AFFECTED


class TestKEVFloor:
    def test_kev_never_monitor_low_exposure(self):
        result = _cve_result(cisa_kev=True, cvss_score=3.0)
        card = decide(result, AssetContext())
        assert card.decision in {Decision.PATCH, Decision.ISOLATE}
        assert card.decision != Decision.MONITOR

    def test_kev_plus_internet_facing_critical_isolates(self):
        result = _cve_result(cisa_kev=True, cvss_score=9.8, cisa_kev_ransomware_use=True)
        ctx = AssetContext(has_product_data=True, matched=True, any_internet_facing=True, highest_criticality="critical")
        card = decide(result, ctx)
        assert card.decision == Decision.ISOLATE
        assert any("ransomware" in r.lower() for r in card.reasons)

    def test_kev_without_exposure_is_patch(self):
        result = _cve_result(cisa_kev=True, cvss_score=7.5)
        ctx = AssetContext(has_product_data=True, matched=True, any_internet_facing=False, highest_criticality="low")
        card = decide(result, ctx)
        assert card.decision == Decision.PATCH


class TestSeverityDriven:
    def test_high_cvss_high_epss_isolated_when_exposed(self):
        result = _cve_result(cvss_score=9.1, epss_score=0.8)
        ctx = AssetContext(has_product_data=True, matched=True, any_internet_facing=True, highest_criticality="critical")
        card = decide(result, ctx)
        assert card.decision == Decision.ISOLATE

    def test_high_cvss_without_exposure_is_patch(self):
        result = _cve_result(cvss_score=9.5)
        card = decide(result, AssetContext())
        assert card.decision == Decision.PATCH

    def test_moderate_severity_internet_critical_is_patch(self):
        result = _cve_result(cvss_score=7.2)
        ctx = AssetContext(has_product_data=True, matched=True, any_internet_facing=True, highest_criticality="critical")
        card = decide(result, ctx)
        assert card.decision == Decision.PATCH

    def test_moderate_severity_no_exposure_is_monitor(self):
        result = _cve_result(cvss_score=5.0)
        card = decide(result, AssetContext())
        assert card.decision == Decision.MONITOR

    def test_low_severity_is_monitor(self):
        result = _cve_result(cvss_score=2.1)
        card = decide(result, AssetContext())
        assert card.decision == Decision.MONITOR

    def test_no_cvss_data_defaults_to_monitor(self):
        result = _cve_result()
        card = decide(result, AssetContext())
        assert card.decision == Decision.MONITOR
        assert any("no cvss" in r.lower() for r in card.reasons)

    def test_elevated_epss_alone_without_exposure_monitors(self):
        result = _cve_result(cvss_score=3.0, epss_score=0.3)
        card = decide(result, AssetContext())
        assert card.decision == Decision.MONITOR


class TestValidation:
    def test_non_cve_raises(self):
        result = EnrichmentResult(ioc=IOC("8.8.8.8", IOCType.IP))
        with pytest.raises(ValueError):
            decide(result)

    def test_decision_card_to_dict(self):
        result = _cve_result(cvss_score=9.8)
        card = decide(result, AssetContext())
        d = card.to_dict()
        assert d["cve_id"] == "CVE-2021-44228"
        assert d["decision"] == "Patch"
        assert isinstance(d["reasons"], list) and d["reasons"]
