# Operations

## Daily workflow
- The scheduled workflow runs once per day and may also be launched manually.
- It collects PyPI and npm updates from the last 24 hours.
- It normalizes candidates, runs metadata scoring, shortlists deeper scans, and writes compact outputs.
- Reports are committed back into the repository.

## Weekly baseline refresh
- The weekly workflow refreshes popularity baselines.
- Only baseline files are committed, and only when there is a diff.

## False positive suppression
- Maintain `scoring/suppressions.yml` with package- or rule-level suppressions.
- Prefer narrowly scoped suppressions to keep explainability intact.

## Review process
- Start with `reports/YYYY-MM-DD.md` for a concise analyst view.
- Pivot into `data/latest-findings.json` for rule evidence and triage state.
- Validate suspicious packages outside GitHub Actions if deeper reverse engineering is required.
