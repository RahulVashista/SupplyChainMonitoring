from scanners.guarddog_runner import should_shortlist
from scanners.metadata_rules import is_suppressed, load_suppressions


def test_shortlist_logic() -> None:
    candidate = {
        "likely_popular_target": "requests",
        "has_install_hooks": False,
        "suspicious_description_keywords": [],
        "release_count": 5,
        "package_size": 1000,
        "score": 0,
    }
    assert should_shortlist(candidate) is True


def test_rule_level_suppression() -> None:
    suppressions = load_suppressions()
    assert is_suppressed({"ecosystem": "pypi", "package_name": "whatever"}, "static.extract_failed", suppressions) is True
