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
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

LOGGER = logging.getLogger(__name__)
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MAX_RELEASE_AGE_HOURS = 24
SUSPICIOUS_KEYWORDS = {
    "wallet",
    "seed phrase",
    "recovery",
    "free nitro",
    "telegram",
    "discord",
    "token grabber",
    "crypto drainer",
    "bypass",
    "stealer",
    "loader",
    "cracked",
    "generator",
    "unlock",
    "exploit",
}
LOOKALIKE_TRANSLATION = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a"})


@dataclass(frozen=True)
class PopularityMatch:
    target: str | None
    score: float
    rule: str | None


class BaselineMatcher:
    def __init__(self, names: Iterable[str]) -> None:
        self.names = sorted({name.strip() for name in names if name.strip()})

    @staticmethod
    def _normalize(value: str) -> str:
        lowered = value.lower().translate(LOOKALIKE_TRANSLATION)
        lowered = re.sub(r"[-_.]+", "", lowered)
        lowered = re.sub(r"(.)\1{2,}", r"\1\1", lowered)
        return lowered

    @staticmethod
    def _levenshtein(left: str, right: str) -> int:
        if left == right:
            return 0
        if not left:
            return len(right)
        if not right:
            return len(left)
        previous = list(range(len(right) + 1))
        for i, left_char in enumerate(left, start=1):
            current = [i]
            for j, right_char in enumerate(right, start=1):
                current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (left_char != right_char)))
            previous = current
        return previous[-1]

    def match(self, package_name: str) -> PopularityMatch:
        normalized_name = self._normalize(package_name)
        base_token = self._normalize(re.split(r"[-_.]", package_name)[0]) if package_name else ""
        best_name = None
        best_score = 0.0
        best_rule = None
        for baseline_name in self.names:
            baseline_normalized = self._normalize(baseline_name)
            if normalized_name == baseline_normalized:
                continue
            distance = self._levenshtein(normalized_name, baseline_normalized)
            base_distance = self._levenshtein(base_token, baseline_normalized) if base_token else distance
            similarity = 1 - (min(distance, base_distance) / max(len(base_token or normalized_name), len(baseline_normalized), 1))
            rule = None
            if base_distance <= 2 and similarity >= 0.75:
                rule = "typosquat_distance"
            elif normalized_name.startswith(baseline_normalized) or normalized_name.endswith(baseline_normalized):
                rule = "brand_affix"
                similarity = max(similarity, 0.86)
            elif baseline_normalized in normalized_name and len(normalized_name) - len(baseline_normalized) <= 8:
                rule = "combosquat"
                similarity = max(similarity, 0.8)
            if rule and similarity > best_score:
                best_name = baseline_name
                best_score = round(similarity, 3)
                best_rule = rule
        return PopularityMatch(best_name, best_score, best_rule)


def configure_logging(verbose: bool = False) -> None:
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, format="%(asctime)s %(levelname)s %(name)s - %(message)s")


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def dump_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def hours_since(timestamp: str | None) -> float | None:
    parsed = parse_timestamp(timestamp)
    if parsed is None:
        return None
    return round((datetime.now(timezone.utc) - parsed).total_seconds() / 3600, 2)


def safe_domain(url: str | None) -> str | None:
    if not url:
        return None
    return urlparse(url).netloc.lower() or None


def find_suspicious_keywords(text: str | None) -> list[str]:
    lowered = (text or "").lower()
    return sorted(keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in lowered)


def validate_candidate(candidate: dict[str, Any]) -> None:
    required = ["ecosystem", "package_name", "version", "published_at", "package_url", "maintainer", "score", "matched_rules", "triage_status"]
    missing = [field for field in required if field not in candidate]
    if missing:
        raise ValueError(f"Candidate missing required fields: {missing}")


def normalize_candidate(raw: dict[str, Any], matcher: BaselineMatcher) -> dict[str, Any]:
    package_name = raw.get("package_name", "")
    match = matcher.match(package_name)
    candidate = {
        "ecosystem": raw.get("ecosystem"),
        "package_name": package_name,
        "version": str(raw.get("version", "")),
        "published_at": raw.get("published_at"),
        "package_url": raw.get("package_url"),
        "source_repo": raw.get("source_repo"),
        "maintainer": raw.get("maintainer") or "unknown",
        "release_age_hours": raw.get("release_age_hours") if raw.get("release_age_hours") is not None else hours_since(raw.get("published_at")),
        "package_size": int(raw.get("package_size") or 0),
        "release_count": int(raw.get("release_count") or 0),
        "description": raw.get("description") or "",
        "homepage": raw.get("homepage"),
        "score": 0,
        "matched_rules": [],
        "triage_status": "new",
        "package_basename": re.split(r"[-_.]", package_name)[0].lower() if package_name else "",
        "normalized_name": BaselineMatcher._normalize(package_name),
        "likely_popular_target": match.target,
        "similarity_score": match.score,
        "has_install_hooks": bool(raw.get("has_install_hooks", False)),
        "collector_source": raw.get("collector_source"),
        "raw_metadata_ref": raw.get("raw_metadata_ref"),
        "typosquat_rule": match.rule,
        "suspicious_description_keywords": find_suspicious_keywords(raw.get("description")),
        "repo_domain": safe_domain(raw.get("source_repo")),
        "homepage_domain": safe_domain(raw.get("homepage")),
    }
    return candidate


def deduplicate(candidates: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: dict[tuple[str, str, str], dict[str, Any]] = {}
    for candidate in candidates:
        key = (candidate.get("ecosystem", ""), candidate.get("package_name", ""), candidate.get("version", ""))
        seen.setdefault(key, candidate)
    return list(seen.values())


def is_low_value(candidate: dict[str, Any], max_age_hours: int = DEFAULT_MAX_RELEASE_AGE_HOURS) -> bool:
    age = candidate.get("release_age_hours")
    if age is not None and age > max_age_hours:
        return True
    if candidate.get("package_name", "").startswith("example-"):
        return True
    return not candidate.get("package_name") or not candidate.get("version")


def load_baseline(ecosystem: str) -> BaselineMatcher:
    baseline_file = ROOT / "baselines" / f"popular_{ecosystem}.txt"
    return BaselineMatcher(baseline_file.read_text(encoding="utf-8").splitlines() if baseline_file.exists() else [])


def normalize_inputs(input_paths: list[Path], output_path: Path) -> dict[str, Any]:
    all_candidates = []
    matchers = {"pypi": load_baseline("pypi"), "npm": load_baseline("npm")}
    for input_path in input_paths:
        for raw in load_json(input_path):
            candidate = normalize_candidate(raw, matchers.get(raw.get("ecosystem"), BaselineMatcher([])))
            if is_low_value(candidate):
                continue
            validate_candidate(candidate)
            all_candidates.append(candidate)
    deduped = deduplicate(all_candidates)
    payload = {"generated_at": datetime.now(timezone.utc).isoformat(), "total_candidates": len(deduped), "candidates": sorted(deduped, key=lambda item: (item["ecosystem"], item["package_name"]))}
    dump_json(output_path, payload)
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Normalize collector outputs into candidate schema.")
    parser.add_argument("--inputs", nargs="+", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--verbose", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    configure_logging(args.verbose)
    payload = normalize_inputs([Path(item) for item in args.inputs], Path(args.out))
    LOGGER.info("Normalized %s candidates", payload["total_candidates"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
