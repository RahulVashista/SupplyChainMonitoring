from __future__ import annotations

import sys
from pathlib import Path as SysPath

ROOT_DIR = SysPath(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import argparse
import json
import logging
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from collectors.common import configure_logging, dump_json, load_json
from collectors.http_client import fetch_json

LOGGER = logging.getLogger(__name__)
TMP_SIZE_LIMIT = 20 * 1024 * 1024
DOWNLOAD_TIMEOUT = 30
SHORTLIST_SCORE_THRESHOLD = 20


def should_shortlist(candidate: dict[str, Any], threshold: int = SHORTLIST_SCORE_THRESHOLD) -> bool:
    return any([
        bool(candidate.get("likely_popular_target")),
        bool(candidate.get("has_install_hooks")),
        bool(candidate.get("suspicious_description_keywords")),
        candidate.get("release_count", 0) <= 1,
        candidate.get("package_size", 0) > 5_000_000,
        candidate.get("score", 0) >= threshold,
    ])


def fetch_package_archive(candidate: dict[str, Any], workspace: Path) -> Path | None:
    try:
        if candidate["ecosystem"] == "pypi":
            meta = fetch_json(f"https://pypi.org/pypi/{candidate['package_name']}/json", timeout=DOWNLOAD_TIMEOUT)
            urls = meta.get("urls") or []
            preferred = next((item for item in urls if item.get("packagetype") == "sdist"), urls[0] if urls else None)
            if not preferred:
                return None
            url = preferred["url"]
            filename = preferred["filename"]
        elif candidate["ecosystem"] == "npm":
            meta = fetch_json(f"https://registry.npmjs.org/{candidate['package_name']}", timeout=DOWNLOAD_TIMEOUT)
            version_meta = meta.get("versions", {}).get(candidate["version"], {})
            url = version_meta.get("dist", {}).get("tarball")
            filename = Path(urlparse(url).path).name if url else None
            if not url or not filename:
                return None
        else:
            return None
        request = Request(url, headers={"User-Agent": "supply-chain-monitor/1.0"})
        archive_path = workspace / filename
        total = 0
        with urlopen(request, timeout=DOWNLOAD_TIMEOUT) as response, archive_path.open("wb") as handle:
            while True:
                chunk = response.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > TMP_SIZE_LIMIT:
                    LOGGER.warning("Skipping %s because archive exceeded size limit", candidate["package_name"])
                    return None
                handle.write(chunk)
        return archive_path
    except Exception as exc:  # noqa: BLE001
        LOGGER.error("Archive fetch failed for %s: %s", candidate["package_name"], exc)
        return None


def safe_extract(archive_path: Path, destination: Path) -> list[Path]:
    extracted: list[Path] = []
    if archive_path.suffix == ".zip":
        with zipfile.ZipFile(archive_path) as archive:
            for member in archive.infolist():
                if member.file_size > TMP_SIZE_LIMIT:
                    continue
                target = (destination / member.filename).resolve()
                target.relative_to(destination.resolve())
                archive.extract(member, destination)
                extracted.append(target)
    else:
        with tarfile.open(archive_path, "r:*") as archive:
            for member in archive.getmembers():
                if member.size > TMP_SIZE_LIMIT:
                    continue
                target = (destination / member.name).resolve()
                target.relative_to(destination.resolve())
                archive.extract(member, destination)
                extracted.append(target)
    return extracted


def ecosystem_to_guarddog(ecosystem: str) -> str:
    return {"pypi": "pypi", "npm": "npm"}.get(ecosystem, ecosystem)


def run_guarddog_on_candidate(candidate: dict[str, Any]) -> dict[str, Any]:
    if shutil.which("guarddog") is None:
        return {"package": candidate["package_name"], "version": candidate["version"], "findings": [], "status": "guarddog_not_installed"}
    with tempfile.TemporaryDirectory(prefix="guarddog-") as tmpdir:
        workspace = Path(tmpdir)
        archive = fetch_package_archive(candidate, workspace)
        if not archive:
            return {"package": candidate["package_name"], "version": candidate["version"], "findings": [], "status": "download_failed"}
        unpack_dir = workspace / "src"
        unpack_dir.mkdir(exist_ok=True)
        try:
            safe_extract(archive, unpack_dir)
            completed = subprocess.run(["guarddog", ecosystem_to_guarddog(candidate["ecosystem"]), "scan", str(unpack_dir), "--output-format", "json"], capture_output=True, text=True, timeout=180, check=False)
        except Exception as exc:  # noqa: BLE001
            LOGGER.error("GuardDog execution failed for %s: %s", candidate["package_name"], exc)
            return {"package": candidate["package_name"], "version": candidate["version"], "findings": [], "status": "execution_failed"}
    if completed.returncode not in (0, 1):
        return {"package": candidate["package_name"], "version": candidate["version"], "findings": [], "status": f"error:{completed.returncode}", "stderr": completed.stderr[:400]}
    try:
        payload = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError:
        payload = {"raw": completed.stdout[:400]}
    findings = []
    for finding in payload.get("issues", payload.get("findings", [])):
        findings.append({
            "rule_id": f"guarddog.{finding.get('rule_id', finding.get('id', 'issue'))}",
            "title": finding.get("title", "GuardDog finding"),
            "description": finding.get("description", "GuardDog reported a suspicious pattern."),
            "weight": 20,
            "severity_hint": str(finding.get("severity", "high")).lower(),
            "evidence": {"location": finding.get("location"), "message": str(finding.get("message", ""))[:200]},
        })
    return {"package": candidate["package_name"], "version": candidate["version"], "findings": findings, "status": "ok"}


def run(candidates: Iterable[dict[str, Any]]) -> dict[str, Any]:
    return {"results": [run_guarddog_on_candidate(candidate) for candidate in candidates if should_shortlist(candidate)]}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run GuardDog against shortlisted package candidates.")
    parser.add_argument("--in", dest="input_path", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--verbose", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    configure_logging(args.verbose)
    results = run(load_json(Path(args.input_path)).get("candidates", []))
    dump_json(Path(args.out), results)
    LOGGER.info("GuardDog processed %s shortlisted packages", len(results["results"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
