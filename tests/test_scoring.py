from scoring.score import final_severity, process_findings


def test_scoring_combines_and_ranks() -> None:
    payload = {
        "findings": [
            {
                "ecosystem": "npm",
                "package_name": "expresss-auth",
                "version": "1.0.0",
                "score": 0,
                "matched_rules": [
                    {"rule_id": "meta.typosquat", "title": "typo", "description": "", "weight": 25, "severity_hint": "high", "evidence": {}},
                    {"rule_id": "meta.install_hooks", "title": "hooks", "description": "", "weight": 20, "severity_hint": "high", "evidence": {}},
                    {"rule_id": "shared.webhook", "title": "webhook", "description": "", "weight": 15, "severity_hint": "high", "evidence": {}},
                ],
                "triage_status": "new",
                "severity": "ignore",
                "why_flagged": "",
                "package_url": "u",
                "source_repo": "r",
                "maintainer": "m",
                "published_at": "2026-03-18T00:00:00+00:00"
            }
        ]
    }
    processed = process_findings(payload)
    assert processed["summary"]["total_suspicious"] == 1
    assert processed["findings"][0]["score"] == 60
    assert processed["findings"][0]["severity"] == "High"
    assert final_severity(75) == "Critical"
