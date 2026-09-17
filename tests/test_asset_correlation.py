"""Unit tests for CVE-to-asset correlation heuristics."""

from __future__ import annotations

from src.decision.asset_correlation import correlate
from src.models import IOC, IOCType, EnrichmentResult


def _result(products):
    r = EnrichmentResult(ioc=IOC("CVE-2021-44228", IOCType.CVE))
    r.affected_products = products
    return r


class TestCorrelation:
    def test_no_affected_products_reports_no_product_data(self):
        ctx = correlate(_result([]), [{"product": "Apache Log4j2", "criticality": "high"}])
        assert ctx.has_product_data is False

    def test_no_assets_reports_no_product_data(self):
        ctx = correlate(_result(["Apache Log4j2"]), [])
        assert ctx.has_product_data is False

    def test_matching_product_found(self):
        assets = [{"product": "Apache Log4j", "criticality": "critical", "internet_facing": 1}]
        ctx = correlate(_result(["Apache Log4j2"]), assets)
        assert ctx.matched is True
        assert ctx.any_internet_facing is True
        assert ctx.highest_criticality == "critical"

    def test_no_matching_product(self):
        assets = [{"product": "nginx", "criticality": "high", "internet_facing": 0}]
        ctx = correlate(_result(["Apache Log4j2"]), assets)
        assert ctx.matched is False
        assert ctx.has_product_data is True

    def test_asset_without_product_field_is_ignored(self):
        assets = [{"product": "", "criticality": "high"}]
        ctx = correlate(_result(["Apache Log4j2"]), assets)
        assert ctx.matched is False

    def test_highest_criticality_picked_across_matches(self):
        assets = [
            {"product": "Log4j", "criticality": "low", "internet_facing": 0},
            {"product": "Apache Log4j Core", "criticality": "critical", "internet_facing": 0},
        ]
        ctx = correlate(_result(["Apache Log4j2"]), assets)
        assert ctx.highest_criticality == "critical"

    def test_short_generic_tokens_do_not_false_positive(self):
        # "io" / "js" style short tokens are below the 3-char threshold.
        assets = [{"product": "io", "criticality": "low"}]
        ctx = correlate(_result(["Some Big Product"]), assets)
        assert ctx.matched is False
