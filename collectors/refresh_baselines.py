from __future__ import annotations

import sys
from pathlib import Path as SysPath

ROOT_DIR = SysPath(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import argparse
import logging
from pathlib import Path

from collectors.common import configure_logging
from collectors.http_client import fetch_json

LOGGER = logging.getLogger(__name__)
ROOT = Path(__file__).resolve().parents[1]
PYPI_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
NPM_URL = "https://raw.githubusercontent.com/nice-registry/all-the-package-names/master/names.json"


def refresh_pypi(limit: int) -> list[str]:
    return [item["project"] for item in fetch_json(PYPI_URL, timeout=30).get("rows", [])[:limit]]


def refresh_npm(limit: int) -> list[str]:
    return sorted(fetch_json(NPM_URL, timeout=30)[: limit * 3])[:limit]


def write_lines(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Refresh popular package baseline lists.")
    parser.add_argument("--limit", type=int, default=1000)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    configure_logging(args.verbose)
    write_lines(ROOT / "baselines" / "popular_pypi.txt", refresh_pypi(args.limit))
    write_lines(ROOT / "baselines" / "popular_npm.txt", refresh_npm(args.limit))
    LOGGER.info("Refreshed baselines")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
