from scanners.metadata_rules import apply_metadata_rules, apply_suppressions, load_suppressions


CANDIDATE = {
    "ecosystem": "npm",
    "package_name": "expresss-auth",
    "version": "1.0.0-beta!",
    "description": "free nitro discord stealer",
    "homepage": "https://198.51.100.10/tool",
    "source_repo": "https://github.com/example/expresss-auth",
    "maintainer": "unknown",
    "release_age_hours": 2,
    "release_count": 1,
    "package_size": 9000000,
    "has_install_hooks": True,
    "likely_popular_target": "express",
    "similarity_score": 0.9,
    "typosquat_rule": "brand_affix",
}


def test_metadata_rules_trigger_expected_signals() -> None:
    findings = apply_metadata_rules(CANDIDATE)
    rule_ids = {item["rule_id"] for item in findings}
    assert "meta.typosquat" in rule_ids
    assert "meta.suspicious_description" in rule_ids
    assert "meta.install_hooks" in rule_ids
    assert "meta.large_package" in rule_ids
    assert "meta.weird_version" in rule_ids


def test_suppression_filters_rule() -> None:
    suppressions = load_suppressions()
    filtered = apply_suppressions({"ecosystem": "npm", "package_name": "react"}, [{"rule_id": "meta.typosquat"}], suppressions)
    assert filtered == []
