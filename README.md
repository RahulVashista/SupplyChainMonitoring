# supply-chain-monitor

A production-minded, zero-cost MVP for automated daily monitoring of suspicious open-source packages across PyPI and npm using public GitHub Actions.

## Purpose
This repository discovers recently updated packages, applies explainable metadata heuristics, runs static analysis on a shortlist, scores suspicious behavior, and publishes compact analyst-friendly outputs.

## Zero-cost design principles
- Public GitHub repository only
- GitHub Actions as scheduler and orchestrator
- Python 3.11 runtime
- Static analysis only: **no dynamic malware detonation**
- No long-term raw package storage
- Compact JSON + Markdown outputs only
- Low dependency count and bounded runtime

## Current scope
### Enabled ecosystems
- PyPI
- npm

### Future-ready extension points
The architecture isolates ecosystem collectors so RubyGems, Go modules, GitHub Actions, and VS Code extensions can be added later without reworking scoring or reporting.

## Architecture overview
- `collectors/`: incremental collection and normalization
- `scanners/`: metadata heuristics, GuardDog integration, regex, AST, Semgrep, and YARA
- `scoring/`: suppression handling, weighted ranking, and report generation
- `schemas/`: JSON schema validation for candidates and findings
- `docs/`: methodology, rules, and operations guidance
- `.github/workflows/`: daily scan and weekly baseline refresh automation

## How the pipeline works
1. Collect recent PyPI updates via the public RSS updates feed and enrich with project JSON metadata.
2. Collect recent npm changes via the public replication changes feed and filter to the last 24 hours.
3. Normalize metadata to a common schema and annotate with baseline similarity.
4. Score cheap metadata heuristics first.
5. Shortlist candidates for deeper static analysis only when higher-signal conditions are present.
6. Download artifacts to temporary storage, extract safely, and scan statically.
7. Deduplicate rules, apply suppressions, rank by weighted score, and generate outputs.

## Scoring model
Representative weights:
- Typosquat of top package: +25
- Install hook present: +20
- Obfuscation or encoded blob: +15 to +20
- Webhook/network exfil string: +15
- Credential path access: +25
- New publisher: +10
- Repository mismatch: +10

Thresholds:
- 70+: Critical
- 50-69: High
- 30-49: Medium
- Below 30: ignored in the Markdown report

## Outputs
- `reports/YYYY-MM-DD.md`: daily analyst report
- `data/latest-findings.json`: compact current findings and summary
- `data/latest-summary.json`: GitHub Pages- and workflow-summary-friendly metrics
- Optional GitHub workflow job summary

## Local usage
```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
python collectors/pypi.py --hours 24 --out data/raw/pypi.json
python collectors/npm.py --hours 24 --out data/raw/npm.json
python collectors/common.py --inputs data/raw/pypi.json data/raw/npm.json --out data/normalized/candidates.json
python scanners/guarddog_runner.py --in data/normalized/candidates.json --out data/normalized/guarddog_results.json
python scanners/metadata_rules.py --in data/normalized/candidates.json --guarddog data/normalized/guarddog_results.json --out data/latest-findings.json
python scoring/score.py --in data/latest-findings.json --report reports/$(date -u +%F).md --out data/latest-findings.json
```

## GitHub Actions
- `daily-scan.yml` runs every day, builds the daily report, and commits updated outputs.
- `weekly-baseline-refresh.yml` refreshes popular package baselines once per week.

## Limitations and tradeoffs
- PyPI and npm both expose imperfect zero-cost “recent updates” views; this MVP uses practical public feeds rather than full registry mirrors.
- GuardDog and Semgrep are optional at runtime; the pipeline continues if those tools are unavailable.
- The baseline files in the repository are intentionally compact seed lists, while the weekly workflow refresh can expand them toward the top 1k package names.
- Heuristics are explainable but not definitive; analyst validation is always required.

## Safety notes
- No package execution is performed.
- Temporary extraction is size-bounded and cleaned up automatically.
- Large archives are skipped to reduce zip-bomb risk and runner cost.

## Extending later
To add RubyGems, Go modules, GitHub Actions, or VS Code extensions later:
1. Add a collector that emits the shared raw field set.
2. Reuse `collectors/common.py` normalization and baseline matching.
3. Add ecosystem-specific static scan hints only where needed.
4. Keep scoring weights and schemas stable so reports remain comparable.
