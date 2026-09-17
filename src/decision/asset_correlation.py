"""
Vulnerability–Asset Correlation — links a CVE's NVD-reported affected
products to the local asset inventory (hostname / IP / product-name
matching), producing the ``AssetContext`` consumed by
``src.decision.cve_decision``.

Matching heuristics and their limits
-------------------------------------
This is deliberately a *best-effort* heuristic, not a definitive asset
mapping, and callers/readers should treat "matched" and "not matched" with
that caveat:

* Product matching is a case-insensitive substring/token match between
  NVD's "Vendor Product" strings and the free-text ``product`` field an
  analyst typed into the asset CSV. It will miss real matches when naming
  differs (e.g. "nginx" vs "NGINX Open Source") and can produce false
  positives on generic/short product names.
* Hostname/IP matching only tells us an asset *exists*; it says nothing
  about which software that asset runs unless the CSV's ``product`` field
  was also populated for it.
* If NVD returned no affected-product data at all for the CVE, or no
  asset inventory has been imported, correlation is reported as
  "no product data" (``has_product_data=False``) rather than "not
  matched", so the decision layer does not mistake missing data for a
  confirmed absence of exposure.
"""

from __future__ import annotations

import re
from typing import Iterable

from src.decision.cve_decision import AssetContext
from src.models import EnrichmentResult

_CRITICALITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}


def _tokenize(text: str) -> set[str]:
    return {tok for tok in re.split(r"[^a-z0-9]+", text.lower()) if len(tok) >= 3}


def _product_matches(nvd_product: str, asset_product: str) -> bool:
    nvd_tokens = _tokenize(nvd_product)
    asset_tokens = _tokenize(asset_product)
    if not nvd_tokens or not asset_tokens:
        return False
    return bool(nvd_tokens & asset_tokens)


def correlate(result: EnrichmentResult, assets: Iterable[dict]) -> AssetContext:
    """
    Correlate a CVE enrichment result against a list of asset dicts as
    returned by ``InvestigationStore.list_assets()``.
    """
    asset_list = list(assets)
    affected_products = result.affected_products or []

    if not affected_products or not asset_list:
        return AssetContext(has_product_data=False)

    matched_assets: list[dict] = []
    for asset in asset_list:
        asset_product = (asset.get("product") or "").strip()
        if not asset_product:
            continue
        for nvd_product in affected_products:
            if _product_matches(nvd_product, asset_product):
                matched_assets.append(asset)
                break

    if not matched_assets:
        return AssetContext(has_product_data=True, matched=False)

    any_internet_facing = any(bool(a.get("internet_facing")) for a in matched_assets)
    highest = max(
        (str(a.get("criticality") or "low").lower() for a in matched_assets),
        key=lambda c: _CRITICALITY_RANK.get(c, -1),
        default=None,
    )

    return AssetContext(
        has_product_data=True,
        matched=True,
        matched_assets=matched_assets,
        any_internet_facing=any_internet_facing,
        highest_criticality=highest,
    )
