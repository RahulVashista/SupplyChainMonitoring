from __future__ import annotations

import sys
from pathlib import Path as SysPath

ROOT_DIR = SysPath(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import re
from pathlib import Path
from typing import Iterable

REGEX_PATTERNS: dict[str, tuple[re.Pattern[str], dict[str, object]]] = {
    "npm.lifecycle_shell": (
        re.compile(r"\b(preinstall|postinstall|install|prepare)\b.{0,120}\b(curl|wget|powershell|bash\s+-c|cmd\.exe|Invoke-WebRequest)\b", re.IGNORECASE | re.DOTALL),
        {"title": "Lifecycle hook invokes shell/network tooling", "weight": 20, "severity_hint": "high"},
    ),
    "npm.child_process": (
        re.compile(r"child_process\.(exec|spawn|execSync|spawnSync)|require\(['\"]child_process['\"]\)", re.IGNORECASE),
        {"title": "Node child_process usage", "weight": 12, "severity_hint": "medium"},
    ),
    "shared.webhook": (
        re.compile(r"discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot|pastebin\.com/raw|hastebin\.com", re.IGNORECASE),
        {"title": "Webhook or exfil endpoint string", "weight": 15, "severity_hint": "high"},
    ),
    "shared.credential_paths": (
        re.compile(r"\.aws/credentials|id_rsa|browser/Login Data|/\.ssh/|/\.npmrc|/\.pypirc|/\.config/gcloud", re.IGNORECASE),
        {"title": "Credential file path access string", "weight": 25, "severity_hint": "critical"},
    ),
    "python.install_exec": (
        re.compile(r"(setup\(|cmdclass|setuptools\.setup).{0,200}(subprocess|os\.system|exec\(|eval\(|requests\.|socket\.)", re.IGNORECASE | re.DOTALL),
        {"title": "Python install-time execution indicators", "weight": 20, "severity_hint": "high"},
    ),
    "shared.encoded_blob": (
        re.compile(r"(?:[A-Za-z0-9+/]{200,}={0,2})|frombase64string|base64\.b64decode", re.IGNORECASE),
        {"title": "Encoded blob or decoding primitive", "weight": 15, "severity_hint": "medium"},
    ),
}


def scan_text(path: Path, text: str) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for rule_id, (pattern, meta) in REGEX_PATTERNS.items():
        match = pattern.search(text)
        if not match:
            continue
        findings.append({
            "rule_id": rule_id,
            "title": meta["title"],
            "description": f"Regex match in {path.name}",
            "weight": meta["weight"],
            "severity_hint": meta["severity_hint"],
            "evidence": {"file": str(path), "match": match.group(0)[:160]},
        })
    return findings


def scan_paths(paths: Iterable[Path]) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for path in paths:
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        findings.extend(scan_text(path, text))
    return findings
