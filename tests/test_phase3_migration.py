from migration import migrate_legacy_grant


def test_unknown_legacy_grant_is_disabled():
    result = migrate_legacy_grant("old-1", {"subject": "p1", "purpose": "assist", "scopes": ["mail"]})
    assert result["status"] == "disabled"
    assert "unknown legacy authority" in result["reason"]


def test_explicit_legacy_grant_can_be_imported_and_rolled_back():
    result = migrate_legacy_grant("old-2", {"subject": "p1", "assistant_id": "a1", "capability_id": "mail", "actions": ["draft"], "purpose": "assist", "audiences": ["self"], "data_classes": ["personal"], "space_ids": ["private:p1"]})
    assert result["contract_version"] == "unison.trust.v1"
    assert result["status"] == "ready-for-trust-import"
    assert "rollback" in result
