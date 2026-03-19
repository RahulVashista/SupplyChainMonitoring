# Methodology

## Pipeline stages
1. **Discovery**: Pull only recently updated PyPI and npm packages using zero-cost registry feeds.
2. **Normalization**: Convert ecosystem-specific metadata into a shared candidate schema.
3. **Cheap metadata heuristics**: Score explainable signals such as typosquatting, suspicious descriptions, install hooks, size anomalies, and URL mismatches.
4. **Shortlisted static analysis**: Download only shortlisted package artifacts into temporary storage, extract them safely, scan with GuardDog when available, then run regex, AST, Semgrep, and YARA checks.
5. **Scoring and reporting**: Deduplicate findings, suppress known benign noise, assign weighted severity, and emit compact JSON plus a Markdown report.

## Why static-only
GitHub-hosted runners are not an appropriate place to detonate potentially malicious packages. This MVP therefore performs static analysis only, keeps execution deterministic, and avoids handling live malware infrastructure.

## Why no detonation in GitHub Actions
Dynamic execution risks credential exposure, lateral movement, and abuse of shared runner resources. The project is intentionally designed for public-repo operation, so it avoids runtime package execution and stores only compact outputs.

## Scoring thresholds
- **70+**: Critical
- **50-69**: High
- **30-49**: Medium
- **Below 30**: Ignore in the analyst report

## Storage guardrails
- Raw artifacts stay in temporary directories only.
- Only compact JSON and Markdown are committed.
- The repo keeps current outputs instead of accumulating bulky archives.
