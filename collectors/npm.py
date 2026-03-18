from __future__ import annotations

import sys
from pathlib import Path as SysPath

ROOT_DIR = SysPath(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import argparse
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from collectors.common import configure_logging, dump_json, hours_since
from collectors.http import fetch_json

LOGGER = logging.getLogger(__name__)
CHANGES_URL = "https://replicate.npmjs.com/_changes?include_docs=true&descending=true&limit={limit}"
MAX_CHANGES = 250


def extract_repository(doc: dict[str, Any]) -> str | None:
    repository = doc.get("repository")
    if isinstance(repository, dict):
        return repository.get("url")
    if isinstance(repository, str):
        return repository
    return None


def extract_maintainer(doc: dict[str, Any]) -> str:
    maintainers = doc.get("maintainers") or []
    if maintainers and isinstance(maintainers[0], dict):
        return maintainers[0].get("name") or "unknown"
    if isinstance(doc.get("author"), dict):
        return doc["author"].get("name") or "unknown"
    return "unknown"


def extract_candidate(doc: dict[str, Any]) -> dict[str, Any] | None:
    time_info = doc.get("time") or {}
    modified = time_info.get("modified")
    version = doc.get("dist-tags", {}).get("latest")
    if not modified or not version:
        return None
    versions = doc.get("versions") or {}
    latest_manifest = versions.get(version, {})
    published_at = time_info.get(version) or modified
    dist = latest_manifest.get("dist") or {}
    scripts = latest_manifest.get("scripts") or {}
    return {
        "ecosystem": "npm",
        "package_name": doc.get("name"),
        "version": version,
        "published_at": published_at,
        "package_url": f"https://www.npmjs.com/package/{doc.get('name')}/v/{version}",
        "source_repo": extract_repository(latest_manifest) or extract_repository(doc),
        "maintainer": extract_maintainer(doc),
        "release_age_hours": hours_since(published_at),
        "package_size": int(dist.get("unpackedSize") or 0),
        "release_count": len(versions),
        "description": latest_manifest.get("description") or doc.get("description") or "",
        "homepage": latest_manifest.get("homepage") or doc.get("homepage"),
        "collector_source": "npm_changes_feed",
        "raw_metadata_ref": f"npm:{doc.get('name')}:{version}",
        "has_install_hooks": any(name in scripts for name in ("preinstall", "install", "postinstall", "prepare")),
    }


def collect_recent_packages(hours: int, limit: int = MAX_CHANGES) -> list[dict[str, Any]]:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    payload = fetch_json(CHANGES_URL.format(limit=limit), timeout=20)
    results, seen = [], set()
    for item in payload.get("results", []):
        candidate = extract_candidate(item.get("doc") or {})
        if not candidate:
            continue
        modified = datetime.fromisoformat(candidate["published_at"].replace("Z", "+00:00")).astimezone(timezone.utc)
        if modified < cutoff:
            continue
        key = (candidate["package_name"], candidate["version"])
        if key in seen:
            continue
        seen.add(key)
        results.append(candidate)
    return results


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Collect recently updated npm package metadata.")
    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--out", required=True)
    parser.add_argument("--limit", type=int, default=MAX_CHANGES)
    parser.add_argument("--verbose", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    configure_logging(args.verbose)
    packages = collect_recent_packages(args.hours, args.limit)
    dump_json(Path(args.out), packages)
    LOGGER.info("Wrote %s npm candidates to %s", len(packages), args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
