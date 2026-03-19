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
from urllib.error import HTTPError
from urllib.parse import parse_qsl, quote, urlencode, urlparse

from collectors.common import configure_logging, dump_json, hours_since, load_json
from collectors.http_client import fetch_json

LOGGER = logging.getLogger(__name__)
ROOT_ENDPOINT = "https://replicate.npmjs.com/"
CHANGES_ENDPOINT = "https://replicate.npmjs.com/registry/_changes"
PACKUMENT_ENDPOINT = "https://registry.npmjs.org/{package_name}"
MAX_CHANGES = 250
MAX_PAGES = 5
DEFAULT_STATE_PATH = Path("data/raw/npm_state.json")
SUPPORTED_CHANGE_PARAMS = {"since", "limit"}
INVALID_SEQUENCES = {"", "now"}


def build_changes_url(since: str, limit: int) -> str:
    params = {"since": since, "limit": str(limit)}
    return f"{CHANGES_ENDPOINT}?{urlencode(params)}"


def validate_changes_url(url: str) -> None:
    params = {key for key, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)}
    unsupported = sorted(params - SUPPORTED_CHANGE_PARAMS)
    if unsupported:
        raise ValueError(f"Unsupported _changes query parameters present: {', '.join(unsupported)}")


def is_valid_sequence(value: Any) -> bool:
    if value is None:
        return False
    normalized = str(value).strip()
    if normalized.lower() in INVALID_SEQUENCES:
        return False
    return bool(normalized)


def load_state(state_path: Path) -> dict[str, Any] | None:
    if not state_path.exists():
        return None
    try:
        payload = load_json(state_path)
    except Exception as exc:  # noqa: BLE001
        LOGGER.warning("Failed to read npm state file %s: %s", state_path, exc)
        return None
    last_sequence = payload.get("last_sequence")
    if not is_valid_sequence(last_sequence):
        LOGGER.warning("Ignoring invalid npm last_sequence in %s: %r", state_path, last_sequence)
        return None
    return {"last_sequence": str(last_sequence).strip()}


def save_state(state_path: Path, last_sequence: str) -> None:
    dump_json(state_path, {"last_sequence": str(last_sequence), "saved_at": datetime.now(timezone.utc).isoformat()})


def fetch_update_sequence() -> str:
    payload = fetch_json(ROOT_ENDPOINT, timeout=20)
    update_seq = payload.get("update_seq")
    if not is_valid_sequence(update_seq):
        raise RuntimeError("npm replication root did not return a valid update_seq")
    return str(update_seq).strip()


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


def extract_candidate(doc: dict[str, Any], cutoff: datetime) -> dict[str, Any] | None:
    time_info = doc.get("time") or {}
    modified = time_info.get("modified")
    version = doc.get("dist-tags", {}).get("latest")
    if not doc.get("name") or not modified or not version:
        return None
    versions = doc.get("versions") or {}
    latest_manifest = versions.get(version, {})
    published_at = time_info.get(version) or modified
    try:
        modified_at = datetime.fromisoformat(modified.replace("Z", "+00:00")).astimezone(timezone.utc)
        published_dt = datetime.fromisoformat(published_at.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None
    if max(modified_at, published_dt) < cutoff:
        return None
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
        "collector_source": "npm_registry_changes",
        "raw_metadata_ref": f"npm:{doc.get('name')}:{version}",
        "has_install_hooks": any(name in scripts for name in ("preinstall", "install", "postinstall", "prepare")),
    }


def fetch_changes_page(since: str, limit: int) -> dict[str, Any]:
    normalized_since = since.strip()
    if normalized_since.lower() == "now":
        raise RuntimeError("Refusing to send npm _changes request with since=now; state must be initialized from update_seq first.")
    url = build_changes_url(normalized_since, limit)
    validate_changes_url(url)
    try:
        return fetch_json(url, timeout=20)
    except HTTPError as exc:
        LOGGER.error("npm _changes request failed: %s", url)
        if exc.code == 400:
            raise RuntimeError(f"npm replication API rejected request {url}. Only supported parameters are: since, limit.") from exc
        raise


def fetch_packument(package_name: str) -> dict[str, Any]:
    encoded_name = quote(package_name, safe="@/")
    return fetch_json(PACKUMENT_ENDPOINT.format(package_name=encoded_name), timeout=20)


def initialize_state(state_path: Path) -> str:
    sequence = fetch_update_sequence()
    save_state(state_path, sequence)
    LOGGER.info("Initialized npm state from update_seq=%s; no backfill attempted", sequence)
    return sequence


def collect_recent_packages(hours: int, limit: int = MAX_CHANGES, state_path: Path = DEFAULT_STATE_PATH) -> list[dict[str, Any]]:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    state = load_state(state_path)
    if state is None:
        initialize_state(state_path)
        return []

    since = str(state["last_sequence"]).strip()
    if since.lower() == "now":
        LOGGER.warning("Ignoring invalid npm saved sequence 'now' in %s", state_path)
        initialize_state(state_path)
        return []

    LOGGER.info("Resuming npm replication from saved sequence %s", since)
    latest_sequence = since
    package_ids: list[str] = []
    seen_ids: set[str] = set()

    for _ in range(MAX_PAGES):
        page = fetch_changes_page(since, limit)
        latest_sequence = str(page.get("last_seq", since)).strip()
        results = page.get("results", [])
        for item in results:
            package_id = item.get("id")
            if not package_id or package_id in seen_ids:
                continue
            seen_ids.add(package_id)
            package_ids.append(package_id)
        if not results or latest_sequence == since:
            break
        since = latest_sequence
        if len(results) < limit:
            break

    candidates: list[dict[str, Any]] = []
    for package_id in package_ids:
        try:
            candidate = extract_candidate(fetch_packument(package_id), cutoff)
        except HTTPError as exc:
            LOGGER.warning("Failed to fetch npm packument for %s: HTTP %s", package_id, exc.code)
            continue
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("Failed to fetch npm packument for %s: %s", package_id, exc)
            continue
        if candidate:
            candidates.append(candidate)

    save_state(state_path, latest_sequence)
    return candidates


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Collect recently updated npm package metadata.")
    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--out", required=True)
    parser.add_argument("--state", default=str(DEFAULT_STATE_PATH), help="Path to the persisted npm sequence state file.")
    parser.add_argument("--limit", type=int, default=MAX_CHANGES)
    parser.add_argument("--verbose", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    configure_logging(args.verbose)
    state_path = Path(args.state)
    packages = collect_recent_packages(args.hours, args.limit, state_path=state_path)
    dump_json(Path(args.out), packages)
    LOGGER.info("Wrote %s npm candidates to %s", len(packages), args.out)
    LOGGER.info("Saved npm sequence state to %s", state_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
