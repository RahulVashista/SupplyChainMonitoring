from __future__ import annotations

import sys
from pathlib import Path as SysPath

ROOT_DIR = SysPath(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import argparse
import json
import logging
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

from collectors.common import configure_logging, dump_json, load_json, safe_domain
from scanners.ast_checks import scan_python_paths
from scanners.guarddog_runner import fetch_package_archive, safe_extract, should_shortlist
from scanners.regex_checks import scan_paths

try:
    import yara  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    yara = None

LOGGER = logging.getLogger(__name__)
ROOT = Path(__file__).resolve().parents[1]
SUPPRESSIONS_PATH = ROOT / "scoring" / "suppressions.yml"
SEMGREP_RULES = ROOT / "scanners" / "semgrep_rules"
YARA_RULES = ROOT / "scanners" / "yara_rules"
METADATA_THRESHOLD = 15
LARGE_PACKAGE_BYTES = {"npm": 5_000_000, "pypi": 3_000_000}
SUSPICIOUS_URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "rb.gy", "cutt.ly"}
SUSPICIOUS_DESCRIPTION_TERMS = {"wallet", "seed phrase", "recovery", "free nitro", "telegram", "discord", "token grabber", "crypto drainer", "bypass", "stealer", "loader", "cracked", "generator", "unlock", "exploit"}
ENTERPRISE_TERMS = {"enterprise", "security", "cloud", "identity", "production"}
LOOKALIKE_RE = re.compile(r"[0-9$@]")
ENCODED_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{180,}={0,2}")
VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9A-Za-z-]+){0,4}$")


def load_suppressions(path: Path = SUPPRESSIONS_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"packages": [], "rules": []}


def is_suppressed(candidate: dict[str, Any], rule_id: str, suppressions: dict[str, Any]) -> bool:
    for package_rule in suppressions.get("packages", []):
        if package_rule.get("ecosystem") == candidate.get("ecosystem") and package_rule.get("package_name") == candidate.get("package_name"):
            rules = package_rule.get("rule_ids") or []
            if not rules or rule_id in rules:
                return True
    return any(rule.get("rule_id") == rule_id for rule in suppressions.get("rules", []))


def rule(rule_id: str, title: str, description: str, weight: int, severity_hint: str, evidence: dict[str, Any]) -> dict[str, Any]:
    return {"rule_id": rule_id, "title": title, "description": description, "weight": weight, "severity_hint": severity_hint, "evidence": evidence}


def apply_metadata_rules(candidate: dict[str, Any]) -> list[dict[str, Any]]:
    findings = []
    description = (candidate.get("description") or "").lower()
    homepage = candidate.get("homepage") or ""
    source_repo = candidate.get("source_repo") or ""
    maintainer = candidate.get("maintainer") or "unknown"
    published_age = candidate.get("release_age_hours") or 9999
    similarity_score = candidate.get("similarity_score") or 0
    if candidate.get("likely_popular_target") and candidate.get("typosquat_rule"):
        findings.append(rule("meta.typosquat", "Likely typosquat of popular package", "Package name resembles a popular baseline package.", 25, "high", {"target": candidate["likely_popular_target"], "similarity": similarity_score, "pattern": candidate["typosquat_rule"]}))
        if published_age <= 24 and similarity_score >= 0.86:
            findings.append(rule("meta.new_brand_similarity", "New package with strong brand similarity", "Recently published package closely resembles a popular package.", 10, "medium", {"target": candidate["likely_popular_target"], "release_age_hours": published_age}))
    terms = sorted(term for term in SUSPICIOUS_DESCRIPTION_TERMS if term in description)
    if terms:
        findings.append(rule("meta.suspicious_description", "Suspicious description keywords", "Package description contains terms commonly associated with fraud or malware.", 15, "medium", {"terms": terms[:5]}))
    if not source_repo and ENTERPRISE_TERMS.intersection(description.split()):
        findings.append(rule("meta.missing_repo", "Missing source repository URL", "Package claims enterprise-oriented functionality but does not provide a repository URL.", 10, "medium", {"homepage": homepage or None}))
    if source_repo and homepage and safe_domain(source_repo) and safe_domain(homepage) and safe_domain(source_repo) != safe_domain(homepage):
        findings.append(rule("meta.repo_mismatch", "Homepage and repository domain mismatch", "Source repository and homepage domains differ.", 10, "medium", {"source_repo": safe_domain(source_repo), "homepage": safe_domain(homepage)}))
    if candidate.get("release_count", 0) <= 1 and maintainer.lower() in {"unknown", "", "none"}:
        findings.append(rule("meta.new_publisher", "First release from unknown publisher", "Package appears to be an initial release with minimal publisher history.", 10, "medium", {"maintainer": maintainer}))
    if candidate.get("package_size", 0) >= LARGE_PACKAGE_BYTES.get(candidate.get("ecosystem"), 4_000_000):
        findings.append(rule("meta.large_package", "Unusually large package for ecosystem", "Package size is large for a small library package.", 10, "medium", {"package_size": candidate.get("package_size")}))
    if candidate.get("has_install_hooks"):
        findings.append(rule("meta.install_hooks", "Install or build hooks present", "Package manifest declares install-time hooks.", 20, "high", {"has_install_hooks": True}))
    if candidate.get("version") and not VERSION_RE.match(candidate["version"]):
        findings.append(rule("meta.weird_version", "Weird versioning pattern", "Version string deviates from common semantic version layouts.", 5, "low", {"version": candidate["version"]}))
    for url_field, url in (("homepage", homepage), ("source_repo", source_repo)):
        domain = safe_domain(url)
        if domain in SUSPICIOUS_URL_SHORTENERS or re.search(r"https?://\d+\.\d+\.\d+\.\d+", url):
            findings.append(rule("meta.suspicious_url", "Suspicious homepage or source URL", "Metadata references a URL shortener or raw IP address.", 10, "medium", {"field": url_field, "url": url}))
    combined_meta = " ".join(filter(None, [candidate.get("description"), homepage, source_repo, candidate.get("package_name")]))
    if ENCODED_BLOB_RE.search(combined_meta):
        findings.append(rule("meta.encoded_blob", "Encoded blob indicator in metadata", "Long encoded-looking string appears in package metadata.", 15, "medium", {"field": "metadata"}))
    if any(keyword in combined_meta.lower() for keyword in ("postinstall", "preinstall", "setup.py", "install_requires", "curl ", "wget ")):
        findings.append(rule("meta.install_exec_indicator", "Install-time execution indicator", "Metadata contains strings suggestive of execution during build or install.", 15, "high", {"snippet": combined_meta[:120]}))
    if LOOKALIKE_RE.search(candidate.get("package_name", "")):
        findings.append(rule("meta.lookalike_name", "Lookalike naming pattern", "Package name uses number or symbol substitutions common in impersonation attempts.", 10, "medium", {"package_name": candidate.get("package_name")}))
    return findings


def semgrep_findings(path: Path) -> list[dict[str, Any]]:
    if shutil.which("semgrep") is None:
        return []
    try:
        completed = subprocess.run(["semgrep", "scan", "--config", str(SEMGREP_RULES), "--json", str(path)], capture_output=True, text=True, timeout=180, check=False)
        if completed.returncode not in (0, 1):
            return []
        payload = json.loads(completed.stdout or "{}")
    except Exception:  # noqa: BLE001
        return []
    findings = []
    for result in payload.get("results", []):
        extra = result.get("extra", {})
        findings.append(rule(f"semgrep.{result.get('check_id', 'match')}", extra.get("message", "Semgrep matched suspicious code"), extra.get("metadata", {}).get("description", "Semgrep rule matched source code."), int(extra.get("metadata", {}).get("weight", 15)), extra.get("severity", "medium").lower(), {"path": result.get("path"), "lines": result.get("start", {}).get("line")}))
    return findings


def yara_findings(paths: Iterable[Path]) -> list[dict[str, Any]]:
    if yara is None:
        return []
    compiled = yara.compile(filepaths={rule_file.stem: str(rule_file) for rule_file in YARA_RULES.glob("*.yar")})
    findings = []
    for path in paths:
        if not path.is_file() or path.stat().st_size > 2_000_000:
            continue
        try:
            matches = compiled.match(str(path))
        except Exception:  # noqa: BLE001
            continue
        for match in matches:
            findings.append(rule(f"yara.{match.rule}", f"YARA matched {match.rule}", "YARA rule matched suspicious static content.", 15, "medium", {"file": str(path), "rule": match.rule}))
    return findings


def validate_finding(item: dict[str, Any]) -> None:
    required = ["ecosystem", "package_name", "version", "score", "matched_rules", "triage_status", "severity", "why_flagged", "package_url", "maintainer", "published_at"]
    missing = [field for field in required if field not in item]
    if missing:
        raise ValueError(f"Finding missing required fields: {missing}")


def merge_findings(*finding_groups: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[str, dict[str, Any]] = {}
    for group in finding_groups:
        for item in group:
            deduped.setdefault(item["rule_id"], item)
    return list(deduped.values())


def download_and_scan(candidate: dict[str, Any]) -> list[dict[str, Any]]:
    if not should_shortlist(candidate, METADATA_THRESHOLD):
        return []
    with tempfile.TemporaryDirectory(prefix="package-scan-") as tmpdir:
        workspace = Path(tmpdir)
        archive = fetch_package_archive(candidate, workspace)
        if not archive:
            return []
        source_dir = workspace / "src"
        source_dir.mkdir(exist_ok=True)
        try:
            extracted = safe_extract(archive, source_dir)
        except (tarfile.TarError, zipfile.BadZipFile, ValueError, OSError) as exc:
            LOGGER.error("Safe extraction failed for %s: %s", candidate["package_name"], exc)
            return [rule("static.extract_failed", "Archive extraction failed", "Package archive could not be safely extracted for static scanning.", 5, "low", {"error": str(exc)[:120]})]
        files = [path for path in extracted if path.is_file()]
        return merge_findings(scan_paths(files), scan_python_paths(files), semgrep_findings(source_dir), yara_findings(files))


def apply_suppressions(candidate: dict[str, Any], findings: list[dict[str, Any]], suppressions: dict[str, Any]) -> list[dict[str, Any]]:
    return [item for item in findings if not is_suppressed(candidate, item["rule_id"], suppressions)]


def combine_guarddog_results(results_path: Path | None) -> dict[tuple[str, str], list[dict[str, Any]]]:
    if not results_path or not results_path.exists():
        return {}
    combined: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for result in load_json(results_path).get("results", []):
        combined[(result.get("package"), result.get("version"))].extend(result.get("findings", []))
    return combined


def severity_from_score(score: int) -> str:
    if score >= 70:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 30:
        return "medium"
    return "ignore"


def why_flagged(findings: list[dict[str, Any]]) -> str:
    return " + ".join(item["title"] for item in sorted(findings, key=lambda item: item["weight"], reverse=True)[:3])


def process_candidates(candidates_path: Path, output_path: Path, guarddog_path: Path | None = None) -> dict[str, Any]:
    payload = load_json(candidates_path)
    suppressions = load_suppressions()
    guarddog_results = combine_guarddog_results(guarddog_path)
    findings_output = []
    for candidate in payload.get("candidates", []):
        merged = merge_findings(apply_metadata_rules(candidate), download_and_scan(candidate), guarddog_results.get((candidate["package_name"], candidate["version"]), []))
        merged = apply_suppressions(candidate, merged, suppressions)
        score = sum(int(item.get("weight", 0)) for item in merged)
        record = {**candidate, "score": score, "matched_rules": merged, "severity": severity_from_score(score), "why_flagged": why_flagged(merged) if merged else ""}
        validate_finding(record)
        findings_output.append(record)
    final_payload = {"generated_at": payload.get("generated_at"), "total_scanned": len(findings_output), "findings": findings_output}
    dump_json(output_path, final_payload)
    return final_payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Apply metadata rules and static analysis to candidates.")
    parser.add_argument("--in", dest="input_path", required=True)
    parser.add_argument("--guarddog")
    parser.add_argument("--out", required=True)
    parser.add_argument("--verbose", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    configure_logging(args.verbose)
    payload = process_candidates(Path(args.input_path), Path(args.out), Path(args.guarddog) if args.guarddog else None)
    LOGGER.info("Metadata/static analysis completed for %s packages", payload["total_scanned"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
