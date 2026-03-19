from __future__ import annotations

import sys
from pathlib import Path as SysPath

ROOT_DIR = SysPath(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import json
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

DEFAULT_TIMEOUT = 30
USER_AGENT = "supply-chain-monitor/1.0"


def fetch_text(url: str, timeout: int = DEFAULT_TIMEOUT, retries: int = 3) -> str:
    request = Request(url, headers={"User-Agent": USER_AGENT})
    last_error: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            with urlopen(request, timeout=timeout) as response:
                return response.read().decode("utf-8", errors="replace")
        except (HTTPError, URLError) as exc:
            last_error = exc
            if attempt == retries:
                raise
            time.sleep(attempt * 1.5)
    raise RuntimeError(str(last_error))


def fetch_json(url: str, timeout: int = DEFAULT_TIMEOUT, retries: int = 3) -> Any:
    return json.loads(fetch_text(url, timeout=timeout, retries=retries))
