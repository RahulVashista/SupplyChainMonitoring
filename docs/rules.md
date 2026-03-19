# Rules

## Metadata rules
- `meta.typosquat` (+25): Similar to a popular baseline package.
- `meta.new_brand_similarity` (+10): Newly published package strongly matches a baseline name.
- `meta.suspicious_description` (+15): Suspicious keywords in package summary.
- `meta.missing_repo` (+10): Missing repository for enterprise/security-style claims.
- `meta.repo_mismatch` (+10): Homepage and source repository domains do not align.
- `meta.new_publisher` (+10): First release from an unknown publisher.
- `meta.large_package` (+10): Size anomaly for the ecosystem.
- `meta.install_hooks` (+20): Install/build hooks present.
- `meta.weird_version` (+5): Version string deviates from common patterns.
- `meta.suspicious_url` (+10): URL shortener or raw IP in metadata.
- `meta.encoded_blob` (+15): Encoded blob indicator in metadata.
- `meta.install_exec_indicator` (+15): Install-time execution strings in metadata.
- `meta.lookalike_name` (+10): Name uses lookalike substitutions.

## Static analysis rules
- `guarddog.*`: GuardDog issues normalized into the common finding format.
- `semgrep.*`: Custom Semgrep rules for install hooks, network strings, and credential-path references.
- `yara.*`: YARA signatures for encoded blobs, webhooks, and credential access strings.
- `npm.lifecycle_shell`, `npm.child_process`, `python.install_exec`, `shared.webhook`, `shared.credential_paths`, `shared.encoded_blob`: Regex-based static source findings.
- `python.ast.install_exec_combo`: Python AST combo for suspicious imports and calls.
