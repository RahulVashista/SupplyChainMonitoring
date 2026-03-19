from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

from scanners import guarddog_runner


CANDIDATE = {"ecosystem": "pypi", "package_name": "demo", "version": "1.0.0"}


def test_extract_guarddog_findings_ignores_integer_issues() -> None:
    findings = guarddog_runner.extract_guarddog_findings({"issues": 3, "findings": "nope", "results": None})
    assert findings == []


def test_extract_guarddog_findings_accepts_findings_list() -> None:
    findings = guarddog_runner.extract_guarddog_findings({
        "findings": [
            {"rule_id": "network", "title": "Network IOC", "description": "desc", "severity": "HIGH", "message": "abc", "location": "setup.py"},
            7,
        ]
    })
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "guarddog.network"
    assert findings[0]["severity_hint"] == "high"


def test_run_guarddog_on_candidate_handles_timeout(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(guarddog_runner.shutil, "which", lambda _: "/usr/bin/guarddog")
    archive = tmp_path / "package.tar.gz"
    archive.write_bytes(b"dummy")
    monkeypatch.setattr(guarddog_runner, "fetch_package_archive", lambda candidate, workspace: archive)
    monkeypatch.setattr(guarddog_runner, "safe_extract", lambda archive_path, destination: [])

    def raise_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=180)

    monkeypatch.setattr(guarddog_runner.subprocess, "run", raise_timeout)
    result = guarddog_runner.run_guarddog_on_candidate(CANDIDATE)
    assert result["status"] == "timeout"
    assert result["findings"] == []


def test_run_guarddog_on_candidate_handles_malformed_json(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(guarddog_runner.shutil, "which", lambda _: "/usr/bin/guarddog")
    archive = tmp_path / "package.tar.gz"
    archive.write_bytes(b"dummy")
    monkeypatch.setattr(guarddog_runner, "fetch_package_archive", lambda candidate, workspace: archive)
    monkeypatch.setattr(guarddog_runner, "safe_extract", lambda archive_path, destination: [])
    monkeypatch.setattr(
        guarddog_runner.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="{not-json", stderr=""),
    )
    result = guarddog_runner.run_guarddog_on_candidate(CANDIDATE)
    assert result["status"] == "parse_error"
    assert result["findings"] == []
