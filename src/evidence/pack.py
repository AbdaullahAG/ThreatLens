"""
Evidence Pack Builder — packages an investigation's results, related CVE
Decision Cards, and correlated asset data into a single ZIP with a
``manifest.json`` recording a SHA-256 hash of every file inside, for basic
chain-of-custody / tamper-evidence.

Uses only the standard library ``zipfile`` module. Every value written
into the pack is passed through a redaction pass (the same secret-pattern
redaction used for logs) before being serialized, and no API keys or other
secrets are ever included by design — enrichment results don't carry
credentials, but this is defense-in-depth in case a future field does.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional
from zipfile import ZIP_DEFLATED, ZipFile

from src.models import EnrichmentResult
from src.utils.security import sanitize_sensitive_data

TOOL_VERSION = "2.2.0"
_INVESTIGATION_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _sanitize(value: Any, secrets: Iterable[str] = ()) -> Any:
    """Recursively redact anything that looks like a credential before export."""
    if isinstance(value, str):
        return sanitize_sensitive_data(value, secrets)
    if isinstance(value, dict):
        return {key: _sanitize(val, secrets) for key, val in value.items()}
    if isinstance(value, list):
        return [_sanitize(item, secrets) for item in value]
    return value


class EvidencePackBuilder:
    def __init__(self, output_dir: str = "output"):
        self.output_dir = Path(output_dir)

    def build(
        self,
        investigation_id: str,
        results: Iterable[EnrichmentResult],
        decision_cards: Optional[Iterable[Any]] = None,
        matched_assets: Optional[Any] = None,
        secrets: Iterable[str] = (),
    ) -> str:
        if not isinstance(investigation_id, str) or not _INVESTIGATION_ID_RE.fullmatch(investigation_id):
            raise ValueError("Investigation identifier is invalid")
        secret_values = tuple(secrets)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        zip_path = self.output_dir / f"EvidencePack_{investigation_id}_{timestamp}.zip"

        files: dict[str, bytes] = {}

        investigation_payload = _sanitize(
            {
                "investigation_id": investigation_id,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "results": [r.to_dict() for r in results],
            }, secret_values
        )
        files["investigation.json"] = json.dumps(investigation_payload, indent=2, default=str).encode("utf-8")

        if decision_cards:
            serialized_cards = [
                card.to_dict() if hasattr(card, "to_dict") else card for card in decision_cards
            ]
            files["decision_cards.json"] = json.dumps(
                _sanitize(serialized_cards, secret_values), indent=2, default=str
            ).encode("utf-8")

        if matched_assets:
            files["assets.json"] = json.dumps(_sanitize(matched_assets, secret_values), indent=2, default=str).encode("utf-8")

        manifest = {
            "tool": "ThreatLens",
            "version": TOOL_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "investigation_id": investigation_id,
            "files": {
                name: {"sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content)}
                for name, content in files.items()
            },
        }
        files["manifest.json"] = json.dumps(manifest, indent=2).encode("utf-8")

        with ZipFile(zip_path, "w", compression=ZIP_DEFLATED) as archive:
            for name, content in files.items():
                archive.writestr(name, content)

        return str(zip_path)
