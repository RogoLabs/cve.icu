"""The small feeds must not be able to poison the cache with a bad download.

EPSS and KEV both answer 200 with a body, so `raise_for_status()` cannot tell a
good response from a truncated or empty one. The EPSS endpoint in particular
redirects to a dated filename, so a client that does not follow redirects gets
200 and zero bytes.

Both downloads used to be written straight over the cache, which meant a bad
response destroyed the last good copy and showed up later as a quietly
shrinking coverage figure rather than an error. These tests hold the line.
"""

from __future__ import annotations

import gzip
import json
from unittest.mock import MagicMock, patch

import pytest
from download_cve_data import (
    MIN_EPSS_ROWS,
    CVEDataDownloader,
)


@pytest.fixture
def dl(tmp_path):
    return CVEDataDownloader(cache_dir=tmp_path, quiet=True)


def write_epss(path, rows: int) -> None:
    """A gzipped EPSS CSV with `rows` data rows.

    Scores and percentiles are varied because identical rows compress far better
    than the real feed does, which would put a legitimately sized file under the
    byte floor and test the wrong thing.
    """
    import random

    rng = random.Random(1234)
    with gzip.open(path, "wt", encoding="utf-8") as f:
        f.write("#model_version:v2025.03.14\n")
        f.write("cve,epss,percentile\n")
        for i in range(rows):
            f.write(f"CVE-2026-{i:05d},{rng.random():.5f},{rng.random():.5f}\n")


def write_kev(path, entries: int, declared: int | None = None) -> None:
    catalog = {
        "catalogVersion": "2026.09.18",
        "count": entries if declared is None else declared,
        "vulnerabilities": [{"cveID": f"CVE-2026-{i:05d}"} for i in range(entries)],
    }
    # pad so the size floor is not what rejects it
    catalog["_pad"] = "x" * 300_000
    path.write_text(json.dumps(catalog))


class TestEpssDownloadGuard:
    def test_empty_response_is_rejected(self, dl):
        """The real failure: a 200 with no body, from an unfollowed redirect."""
        tmp = dl.cache_dir / "probe.csv.gz"
        tmp.write_bytes(b"")
        problem = dl._epss_download_problem(tmp)
        assert problem and "bytes" in problem

    def test_truncated_response_is_rejected(self, dl):
        tmp = dl.cache_dir / "probe.csv.gz"
        write_epss(tmp, 50)
        assert dl._epss_download_problem(tmp), "a 50-row EPSS file should not pass"

    def test_non_gzip_body_is_rejected(self, dl):
        tmp = dl.cache_dir / "probe.csv.gz"
        tmp.write_bytes(b"<html>404 Not Found</html>" * 40_000)
        problem = dl._epss_download_problem(tmp)
        assert problem and "gzip" in problem.lower()

    def test_healthy_feed_is_accepted(self, dl):
        tmp = dl.cache_dir / "probe.csv.gz"
        write_epss(tmp, MIN_EPSS_ROWS + 5_000)
        assert dl._epss_download_problem(tmp) is None

    def test_collapse_against_previous_parse_is_rejected(self, dl):
        """Passes the absolute floor, but is a fraction of what we had."""
        dl.epss_parsed_file.write_text(json.dumps({f"CVE-{i}": {} for i in range(400_000)}))
        tmp = dl.cache_dir / "probe.csv.gz"
        write_epss(tmp, MIN_EPSS_ROWS + 1_000)
        problem = dl._epss_download_problem(tmp)
        assert problem and "previously" in problem

    def test_a_rejected_download_leaves_the_cache_alone(self, dl):
        """The point of the guard: keep the last good copy."""
        dl.epss_cache_file.write_bytes(b"known good payload")
        before = dl.epss_cache_file.read_bytes()
        tmp = dl.cache_dir / "probe.csv.gz"
        tmp.write_bytes(b"")
        assert dl._epss_download_problem(tmp)
        assert dl.epss_cache_file.read_bytes() == before


class TestKevDownloadGuard:
    def test_empty_response_is_rejected(self, dl):
        tmp = dl.cache_dir / "probe.json"
        tmp.write_text("")
        problem = dl._kev_download_problem(tmp)
        assert problem and "bytes" in problem

    def test_declared_count_must_match_the_array(self, dl):
        """A partial body can still be valid JSON; the catalog states its length."""
        tmp = dl.cache_dir / "probe.json"
        write_kev(tmp, entries=900, declared=1716)
        problem = dl._kev_download_problem(tmp)
        assert problem and "declares" in problem

    def test_healthy_catalog_is_accepted(self, dl):
        tmp = dl.cache_dir / "probe.json"
        write_kev(tmp, entries=1716)
        assert dl._kev_download_problem(tmp) is None

    def test_collapse_against_previous_parse_is_rejected(self, dl):
        dl.kev_parsed_file.write_text(json.dumps({f"CVE-{i}": True for i in range(1700)}))
        tmp = dl.cache_dir / "probe.json"
        write_kev(tmp, entries=600)
        problem = dl._kev_download_problem(tmp)
        assert problem and "previously" in problem


class TestParsedEntryCount:
    def test_missing_file_reports_zero_rather_than_raising(self, dl):
        assert dl._parsed_entry_count(dl.cache_dir / "absent.json") == 0

    def test_corrupt_file_reports_zero_rather_than_raising(self, dl):
        bad = dl.cache_dir / "bad.json"
        bad.write_text("{not json")
        assert dl._parsed_entry_count(bad) == 0


class TestDownloadPathEndToEnd:
    """The guard has to hold through download_epss_data(), not just the checker."""

    def test_empty_body_does_not_destroy_a_good_cache(self, dl):
        """Reproduces the real incident: 200 OK, zero bytes, from an unfollowed redirect."""
        write_epss(dl.epss_cache_file, MIN_EPSS_ROWS + 1_000)
        good = dl.epss_cache_file.read_bytes()

        response = MagicMock()
        response.raise_for_status.return_value = None
        response.iter_content.return_value = iter([])  # 200, empty body

        with patch("download_cve_data.requests.get", return_value=response):
            result = dl.download_epss_data(force=True)

        assert result == dl.epss_cache_file
        assert dl.epss_cache_file.read_bytes() == good, "a bad download overwrote the cache"
        assert not list(dl.cache_dir.glob("*.part")), "temp file left behind"

    def test_healthy_body_replaces_the_cache(self, dl):
        dl.epss_cache_file.write_bytes(b"stale")
        fresh = dl.cache_dir / "fresh.csv.gz"
        write_epss(fresh, MIN_EPSS_ROWS + 1_000)
        payload = fresh.read_bytes()

        response = MagicMock()
        response.raise_for_status.return_value = None
        response.iter_content.return_value = iter([payload])

        with patch("download_cve_data.requests.get", return_value=response):
            result = dl.download_epss_data(force=True)

        assert result == dl.epss_cache_file
        assert dl.epss_cache_file.read_bytes() == payload
        assert not list(dl.cache_dir.glob("*.part"))
