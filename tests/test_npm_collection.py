from __future__ import annotations

from pathlib import Path
from urllib.parse import parse_qs, urlparse

from collectors import npm


class FakeFetcher:
    def __init__(self) -> None:
        self.urls: list[str] = []

    def __call__(self, url: str, timeout: int = 20):  # type: ignore[override]
        self.urls.append(url)
        if url.startswith(npm.CHANGES_ENDPOINT):
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            assert set(params) <= {"since", "limit"}
            assert "include_docs" not in params
            if params["since"] == ["now"]:
                return {"results": [{"id": "left-pad"}], "last_seq": "100-g1AAA"}
            raise AssertionError(f"unexpected since value: {params['since']}")
        if url == npm.PACKUMENT_ENDPOINT.format(package_name="left-pad"):
            return {
                "name": "left-pad",
                "description": "pad strings",
                "dist-tags": {"latest": "1.3.0"},
                "time": {
                    "modified": "2026-03-19T00:00:00.000Z",
                    "1.3.0": "2026-03-18T23:00:00.000Z",
                },
                "versions": {
                    "1.3.0": {
                        "description": "pad strings",
                        "dist": {"unpackedSize": 1234},
                        "scripts": {"postinstall": "node install.js"},
                        "repository": {"url": "https://github.com/example/left-pad"},
                        "homepage": "https://example.com/left-pad",
                    }
                },
                "maintainers": [{"name": "alice"}],
            }
        raise AssertionError(f"unexpected url: {url}")


def test_collect_recent_packages_uses_supported_changes_api_and_persists_state(tmp_path: Path, monkeypatch) -> None:
    state_path = tmp_path / "npm_state.json"
    fetcher = FakeFetcher()
    monkeypatch.setattr(npm, "fetch_json", fetcher)

    results = npm.collect_recent_packages(hours=24, limit=50, state_path=state_path)

    assert len(results) == 1
    assert results[0]["package_name"] == "left-pad"
    assert results[0]["has_install_hooks"] is True
    assert npm.load_state(state_path)["last_sequence"] == "100-g1AAA"
    assert any(url.startswith("https://registry.npmjs.org/left-pad") for url in fetcher.urls)


def test_build_changes_url_only_uses_since_and_limit() -> None:
    url = npm.build_changes_url("42-g1AAA", 25)
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    assert parsed.scheme == "https"
    assert parsed.netloc == "replicate.npmjs.com"
    assert parsed.path == "/registry/_changes"
    assert params == {"since": ["42-g1AAA"], "limit": ["25"]}
