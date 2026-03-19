from __future__ import annotations

import sys
from pathlib import Path as SysPath

ROOT_DIR = SysPath(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import argparse
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from collectors.common import configure_logging, dump_json, load_json

REPORT_THRESHOLD = 30


def final_severity(score: int) -> str:
    if score >= 70:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 30:
        return "Medium"
    return "Ignore"


def dedupe_rules(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[str, dict[str, Any]] = {}
    for rule in rules:
        existing = deduped.get(rule["rule_id"])
        if not existing or rule.get("weight", 0) > existing.get("weight", 0):
            deduped[rule["rule_id"]] = rule
    return list(deduped.values())


def summarize_why_flagged(rules: list[dict[str, Any]]) -> str:
    top_titles = [rule["title"] for rule in sorted(rules, key=lambda item: item.get("weight", 0), reverse=True)[:3]]
    return " + ".join(top_titles)


def process_findings(payload: dict[str, Any]) -> dict[str, Any]:
    findings = []
    for item in payload.get("findings", []):
        rules = dedupe_rules(item.get("matched_rules", []))
        score = sum(int(rule.get("weight", 0)) for rule in rules)
        findings.append({
            **item,
            "matched_rules": rules,
            "score": score,
            "severity": final_severity(score),
            "why_flagged": summarize_why_flagged(rules) if rules else item.get("why_flagged", ""),
        })
    findings.sort(key=lambda item: (-item["score"], item["ecosystem"], item["package_name"]))
    suspicious = [item for item in findings if item["score"] >= REPORT_THRESHOLD]
    ecosystems = sorted({item["ecosystem"] for item in findings})
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_scanned": len(findings),
        "total_suspicious": len(suspicious),
        "total_high_confidence": len([item for item in findings if item["score"] >= 50]),
        "ecosystems": ecosystems,
    }
    return {"summary": summary, "findings": findings}


def render_report(processed: dict[str, Any], report_date: str) -> str:
    summary = processed["summary"]
    findings = [item for item in processed["findings"] if item["score"] >= REPORT_THRESHOLD]
    lines = [
        f"# Daily Supply Chain Monitoring Report - {report_date}",
        "",
        "## Summary",
        f"- Packages scanned: {summary['total_scanned']}",
        f"- Suspicious: {summary['total_suspicious']}",
        f"- High confidence: {summary['total_high_confidence']}",
        f"- Ecosystems: {', '.join(summary['ecosystems']) if summary['ecosystems'] else 'none'}",
        "",
        "## Top Findings",
        "",
        "| Severity | Ecosystem | Package | Version | Score | Why flagged |",
        "|---|---|---|---|---:|---|",
    ]
    for item in findings:
        lines.append(
            f"| {item['severity']} | {item['ecosystem']} | {item['package_name']} | {item['version']} | {item['score']} | {item['why_flagged']} |"
        )
    if not findings:
        lines.append("| Ignore | - | - | - | 0 | No findings met the reporting threshold |")
    lines.extend([
        "",
        "## Notes",
        "- No dynamic execution performed in GitHub Actions",
        "- Findings are heuristic and require analyst validation",
        "",
    ])
    return "\n".join(lines)


def write_outputs(processed: dict[str, Any], findings_path: Path, report_path: Path) -> None:
    report_date = report_path.stem
    report_path.parent.mkdir(parents=True, exist_ok=True)
    findings_path.parent.mkdir(parents=True, exist_ok=True)
    dump_json(findings_path, processed)
    report_path.write_text(render_report(processed, report_date), encoding="utf-8")
    summary_path = findings_path.parent / "latest-summary.json"
    dump_json(summary_path, processed["summary"])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Finalize scores and build markdown reports.")
    parser.add_argument("--in", dest="input_path", required=True, help="Enriched findings JSON path.")
    parser.add_argument("--report", required=True, help="Report output path.")
    parser.add_argument("--out", default="data/latest-findings.json", help="Final findings JSON output path.")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging.")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    configure_logging(args.verbose)
    processed = process_findings(load_json(Path(args.input_path)))
    write_outputs(processed, Path(args.out), Path(args.report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
