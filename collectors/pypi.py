from __future__ import annotations

import sys
from pathlib import Path as SysPath

ROOT_DIR = SysPath(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import argparse
import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

from collectors.common import configure_logging, dump_json, hours_since
from collectors.http import fetch_json, fetch_text

LOGGER = logging.getLogger(__name__)
RECENT_UPDATES_RSS = "https://pypi.org/rss/updates.xml"
PACKAGE_JSON_URL = "https://pypi.org/pypi/{package}/json"
MAX_ITEMS = 200


def parse_rss_items(xml_text: str, cutoff: datetime) -> list[tuple[str, datetime]]:
    root = ET.fromstring(xml_text)
    items: list[tuple[str, datetime]] = []
    for item in root.findall("./channel/item"):
        title = item.findtext("title") or ""
        package_name = title.split()[0].strip()
        published = item.findtext("pubDate")
        if not package_name or not published:
            continue
        published_at = parsedate_to_datetime(published).astimezone(timezone.utc)
        if published_at >= cutoff:
            items.append((package_name, published_at))
    return items[:MAX_ITEMS]


def extract_candidate(package_name: str, metadata: dict[str, Any], published_hint: datetime) -> dict[str, Any]:
    info = metadata.get("info", {})
    releases = metadata.get("releases", {})
    version = info.get("version")
    release_files = releases.get(version, []) if version else []
    published_at = min((item.get("upload_time_iso_8601") for item in release_files if item.get("upload_time_iso_8601")), default=published_hint.isoformat())
    package_size = sum(int(item.get("size", 0) or 0) for item in release_files)
    project_urls = info.get("project_urls") or {}
    return {
        "ecosystem": "pypi",
        "package_name": package_name,
        "version": version,
        "published_at": published_at,
        "package_url": f"https://pypi.org/project/{package_name}/{version}/" if version else f"https://pypi.org/project/{package_name}/",
        "source_repo": project_urls.get("Source") or project_urls.get("Homepage") or info.get("project_url"),
        "maintainer": info.get("maintainer") or info.get("author") or "unknown",
        "release_age_hours": hours_since(published_at),
        "package_size": package_size,
        "release_count": len([key for key, value in releases.items() if value]),
        "description": info.get("summary") or (info.get("description") or "")[:400],
        "homepage": info.get("home_page") or project_urls.get("Homepage"),
        "collector_source": "pypi_rss_updates",
        "raw_metadata_ref": f"pypi:{package_name}:{version}",
        "has_install_hooks": False,
    }


def collect_recent_packages(hours: int) -> list[dict[str, Any]]:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    recent_items = parse_rss_items(fetch_text(RECENT_UPDATES_RSS, timeout=15), cutoff)
    results, seen = [], set()
    for package_name, published_hint in recent_items:
        if package_name in seen:
            continue
        seen.add(package_name)
        try:
            candidate = extract_candidate(package_name, fetch_json(PACKAGE_JSON_URL.format(package=package_name), timeout=15), published_hint)
            if candidate.get("release_age_hours") is not None and candidate["release_age_hours"] <= hours:
                results.append(candidate)
        except Exception as exc:  # noqa: BLE001
            LOGGER.error("Failed to fetch PyPI metadata for %s: %s", package_name, exc)
    return results


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Collect recently updated PyPI package metadata.")
    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--out", required=True)
    parser.add_argument("--verbose", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    configure_logging(args.verbose)
    packages = collect_recent_packages(args.hours)
    dump_json(Path(args.out), packages)
    LOGGER.info("Wrote %s PyPI candidates to %s", len(packages), args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
