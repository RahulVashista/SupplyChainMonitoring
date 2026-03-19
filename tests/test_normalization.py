from pathlib import Path

from collectors.common import normalize_inputs


def test_normalization_adds_similarity_and_defaults(tmp_path: Path) -> None:
    output_path = tmp_path / "candidates.json"
    payload = normalize_inputs([
        Path("tests/fixtures/raw_pypi.json"),
        Path("tests/fixtures/raw_npm.json"),
    ], output_path)
    assert payload["total_candidates"] == 2
    by_name = {item["package_name"]: item for item in payload["candidates"]}
    assert by_name["reqeusts-tools"]["likely_popular_target"] == "requests"
    assert by_name["expresss-auth"]["has_install_hooks"] is True
    assert by_name["expresss-auth"]["score"] == 0
