"""Consent migration into the authoritative Trust API contract."""
from __future__ import annotations

from typing import Any


TRUST_CONTRACT = "unison.trust.v1"
REQUIRED_DIMENSIONS = {"principal_id", "assistant_id", "capability_id", "actions", "purposes", "audiences", "data_classes", "space_ids"}


def migrate_legacy_grant(grant_id: str, legacy: dict[str, Any]) -> dict[str, Any]:
    """Convert only explicitly bounded legacy records; all others stay disabled."""
    normalized = {
        "contract_version": TRUST_CONTRACT,
        "grant_id": grant_id,
        "principal_id": legacy.get("principal_id") or legacy.get("subject"),
        "assistant_id": legacy.get("assistant_id"),
        "capability_id": legacy.get("capability_id"),
        "actions": legacy.get("actions"),
        "purposes": legacy.get("purposes") or ([legacy["purpose"]] if legacy.get("purpose") else None),
        "audiences": legacy.get("audiences"),
        "data_classes": legacy.get("data_classes"),
        "space_ids": legacy.get("space_ids"),
        "recipient_ids": legacy.get("recipient_ids", []),
        "migration_source": "legacy-consent",
    }
    missing = sorted(key for key in REQUIRED_DIMENSIONS if not normalized.get(key))
    if missing:
        return {"grant_id": grant_id, "status": "disabled", "reason": "unknown legacy authority: " + ", ".join(missing), "rollback": "retain original record read-only"}
    return {**normalized, "status": "ready-for-trust-import", "rollback": "revoke imported grant and restore read-only legacy record"}
