"""Tests for source manifest ingest and verification.

The producer publishes metadata.json describing the snapshot behind nvd.json.
These tests cover the gates that stand between that manifest and a build:
health (degraded / API fallback / completeness), regression against the last
accepted snapshot, and integrity of the downloaded object.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from data.download_cve_data import CVEDataDownloader
from tests.fakes import FakeDataReader, FakeDataWriter, FakeHttpClient


MANIFEST_URL = "https://nvd.handsonhacking.org/metadata.json"
BASELINE_URL = "https://cve.icu/data/source_manifest.json"


def make_manifest(**overrides):
    """A healthy manifest, shaped like the real one."""
    manifest = {
        "last_run_iso": "2026-08-18T01:07:27.380633+00:00",
        "cve_count": 378426,
        "degraded": False,
        "years_via_api": [],
        "expected_total": 378739,
        "completeness_ratio": 0.9992,
        "year_counts": {"1999": 1579, "2025": 45146, "2026": 45127},
    }
    manifest.update(overrides)
    return manifest


def make_downloader(tmp_path: Path, http_client: FakeHttpClient) -> CVEDataDownloader:
    return CVEDataDownloader(
        cache_dir=tmp_path,
        quiet=True,
        http_client=http_client,
        data_reader=FakeDataReader(),
        data_writer=FakeDataWriter(),
    )


class TestFetchSourceManifest:
    def test_returns_parsed_manifest(self, tmp_path):
        manifest = make_manifest()
        client = FakeHttpClient()
        client.add_response(MANIFEST_URL, json_data=manifest)

        assert make_downloader(tmp_path, client).fetch_source_manifest() == manifest

    def test_returns_none_when_unavailable(self, tmp_path):
        """An unreachable manifest must not break the build."""
        client = FakeHttpClient()  # unregistered URLs 404
        assert make_downloader(tmp_path, client).fetch_source_manifest() is None

    def test_returns_none_on_malformed_payload(self, tmp_path):
        client = FakeHttpClient()
        client.add_response(MANIFEST_URL, json_data={"unexpected": True})
        assert make_downloader(tmp_path, client).fetch_source_manifest() is None


class TestVerifyManifestHealthy:
    def test_accepts_healthy_manifest(self, tmp_path):
        d = make_downloader(tmp_path, FakeHttpClient())
        d.verify_manifest_healthy(make_manifest())  # must not raise

    def test_rejects_degraded_run(self, tmp_path):
        d = make_downloader(tmp_path, FakeHttpClient())
        with pytest.raises(ValueError, match="degraded"):
            d.verify_manifest_healthy(make_manifest(degraded=True))

    def test_rejects_api_fallback(self, tmp_path):
        """The REST API fallback drops records whose ID year != publication year."""
        d = make_downloader(tmp_path, FakeHttpClient())
        with pytest.raises(ValueError, match="REST API"):
            d.verify_manifest_healthy(make_manifest(years_via_api=["2023"]))

    def test_rejects_low_completeness(self, tmp_path):
        """The leading-edge failure mode shows up as a completeness dip."""
        d = make_downloader(tmp_path, FakeHttpClient())
        with pytest.raises(ValueError, match="completeness_ratio"):
            d.verify_manifest_healthy(make_manifest(completeness_ratio=0.97))

    def test_tolerates_absent_completeness_field(self, tmp_path):
        m = make_manifest()
        del m["completeness_ratio"]
        make_downloader(tmp_path, FakeHttpClient()).verify_manifest_healthy(m)


class TestVerifyManifestNotRegressed:
    def test_accepts_growth(self, tmp_path):
        d = make_downloader(tmp_path, FakeHttpClient())
        baseline = make_manifest(cve_count=378000, year_counts={"1999": 1579, "2026": 45000})
        d.verify_manifest_not_regressed(make_manifest(), baseline)

    def test_accepts_identical(self, tmp_path):
        """A producer run with no new CVEs is normal, not a regression."""
        d = make_downloader(tmp_path, FakeHttpClient())
        d.verify_manifest_not_regressed(make_manifest(), make_manifest())

    def test_rejects_total_regression(self, tmp_path):
        d = make_downloader(tmp_path, FakeHttpClient())
        baseline = make_manifest(cve_count=378426)
        with pytest.raises(ValueError, match="total"):
            d.verify_manifest_not_regressed(make_manifest(cve_count=377000), baseline)

    def test_rejects_single_year_regression(self, tmp_path):
        """The 2023-feed fallback showed up as one year moving, not the total."""
        d = make_downloader(tmp_path, FakeHttpClient())
        baseline = make_manifest()
        regressed = make_manifest(
            cve_count=999999,  # total grew, masking the per-year loss
            year_counts={"1999": 1579, "2025": 40000, "2026": 45127},
        )
        with pytest.raises(ValueError, match="year 2025"):
            d.verify_manifest_not_regressed(regressed, baseline)

    def test_rejects_disappeared_year(self, tmp_path):
        """Year 1999 vanishing entirely is the 2026-07-08 shape."""
        d = make_downloader(tmp_path, FakeHttpClient())
        with pytest.raises(ValueError, match="year 1999"):
            d.verify_manifest_not_regressed(
                make_manifest(year_counts={"2025": 45146, "2026": 45127}),
                make_manifest(),
            )

    def test_no_baseline_is_accepted(self, tmp_path):
        """First run has nothing to compare against."""
        d = make_downloader(tmp_path, FakeHttpClient())
        d.verify_manifest_not_regressed(make_manifest(), None)


class TestVerifyDownloadAgainstManifest:
    def test_accepts_matching_size(self, tmp_path):
        d = make_downloader(tmp_path, FakeHttpClient())
        d.verify_download_against_manifest(make_manifest(bytes=1000), 1000)

    def test_rejects_size_mismatch(self, tmp_path):
        d = make_downloader(tmp_path, FakeHttpClient())
        with pytest.raises(OSError, match="Size mismatch"):
            d.verify_download_against_manifest(make_manifest(bytes=1787783421), 1787000000)

    def test_tolerates_absent_integrity_fields(self, tmp_path):
        """bytes and sha256 only appear from the first post-merge producer run."""
        d = make_downloader(tmp_path, FakeHttpClient())
        d.verify_download_against_manifest(make_manifest(), 12345)

    def test_no_manifest_skips_verification(self, tmp_path):
        d = make_downloader(tmp_path, FakeHttpClient())
        d.verify_download_against_manifest(None, 12345)

    def test_rejects_sha256_mismatch(self, tmp_path):
        real_cache = tmp_path / "cache"
        real_cache.mkdir()
        d = CVEDataDownloader(cache_dir=real_cache, quiet=True, http_client=FakeHttpClient())
        d.cache_file.write_bytes(b"payload")
        with pytest.raises(OSError, match="SHA-256 mismatch"):
            d.verify_download_against_manifest(make_manifest(sha256="0" * 64), 7)

    def test_accepts_correct_sha256(self, tmp_path):
        import hashlib

        real_cache = tmp_path / "cache"
        real_cache.mkdir()
        d = CVEDataDownloader(cache_dir=real_cache, quiet=True, http_client=FakeHttpClient())
        payload = b"payload"
        d.cache_file.write_bytes(payload)
        d.verify_download_against_manifest(make_manifest(sha256=hashlib.sha256(payload).hexdigest()), len(payload))


class TestStreamingHash:
    def test_matches_hashlib(self, tmp_path):
        import hashlib

        target = tmp_path / "blob.bin"
        payload = b"x" * (3 * 1024 * 1024)
        target.write_bytes(payload)
        d = CVEDataDownloader(cache_dir=tmp_path, quiet=True, http_client=FakeHttpClient())
        assert d.calculate_file_hash_streaming(target, chunk_size=64 * 1024) == (hashlib.sha256(payload).hexdigest())


class TestBaselineManifest:
    def test_missing_baseline_returns_none(self, tmp_path):
        """404 on first run is expected, not an error."""
        client = FakeHttpClient()
        client.add_response(BASELINE_URL, status_code=404, content=b"Not Found")
        assert make_downloader(tmp_path, client).fetch_baseline_manifest() is None

    def test_returns_baseline(self, tmp_path):
        baseline = make_manifest(cve_count=1)
        client = FakeHttpClient()
        client.add_response(BASELINE_URL, json_data=baseline)
        assert make_downloader(tmp_path, client).fetch_baseline_manifest() == baseline


class TestPersistAcceptedManifest:
    def test_writes_manifest(self, tmp_path):
        writer = FakeDataWriter()
        d = CVEDataDownloader(cache_dir=tmp_path, quiet=True, http_client=FakeHttpClient(), data_writer=writer)
        manifest = make_manifest()
        d.persist_accepted_manifest(manifest)
        assert writer.get_json(d.manifest_file) == manifest
