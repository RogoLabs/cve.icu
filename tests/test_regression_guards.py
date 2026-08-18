"""Tests for the build-side regression, freshness, and provenance guards.

These are independent of the source-manifest checks in the downloader. The
manifest catches a bad snapshot from the producer; these catch a regression in
our own analysis code, which the producer cannot see.

Keying note: everything here is publication-date bucketed, matching our own
outputs. Manifest year_counts are CVE-ID keyed and are never compared to these.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest

from build import CVESiteBuilder


def year_data(**counts: int) -> list[dict[str, int]]:
    """Build all_year_data-shaped input from year=count pairs."""
    return [{"year": int(y), "total_cves": c} for y, c in counts.items()]


def published(total: int, **counts: int) -> dict:
    return {
        "total_cves": total,
        "yearly_trend": [{"year": int(y), "count": c} for y, c in counts.items()],
    }


@pytest.fixture
def builder(tmp_path):
    """A builder in strict mode, i.e. how it behaves in CI.

    Strict is set explicitly rather than inherited from the environment so the
    suite behaves identically whether or not CI is set in the shell running it.
    """
    b = CVESiteBuilder(quiet=True)
    b.cache_dir = tmp_path
    b.current_year = 2026
    b.accept_baseline = False
    b.strict_data_guards = True
    return b


@pytest.fixture
def lenient_builder(builder):
    """A builder outside CI, where guards warn instead of aborting."""
    builder.strict_data_guards = False
    return builder


class TestVerifyNoRegression:
    def test_accepts_growth(self, builder):
        with patch.object(CVESiteBuilder, "fetch_published_totals",
                          return_value=published(1000, **{"2025": 600, "2026": 400})):
            builder.verify_no_regression(year_data(**{"2025": 600, "2026": 450}))

    def test_accepts_small_decrease_within_allowance(self, builder):
        """Genuine CVE withdrawals are a handful of records and must not fail."""
        with patch.object(CVESiteBuilder, "fetch_published_totals",
                          return_value=published(1000, **{"2025": 600, "2026": 400})):
            builder.verify_no_regression(year_data(**{"2025": 595, "2026": 400}))

    def test_rejects_total_regression_beyond_allowance(self, builder):
        with patch.object(CVESiteBuilder, "fetch_published_totals",
                          return_value=published(359880, **{"2025": 48154, "2026": 51675})):
            with pytest.raises(RuntimeError, match="total"):
                builder.verify_no_regression(year_data(**{"2025": 48154, "2026": 51375}))

    def test_rejects_closed_year_regression(self, builder):
        """The 2026-06-29 shape: year 2024 lost 5,254 CVEs and got them back."""
        with patch.object(CVESiteBuilder, "fetch_published_totals",
                          return_value=published(100000, **{"2024": 39959, "2026": 60041})):
            with pytest.raises(RuntimeError, match="year 2024"):
                builder.verify_no_regression(year_data(**{"2024": 34705, "2026": 70000}))

    def test_rejects_vanished_closed_year(self, builder):
        """The 2026-07-08 shape: year 1999 disappeared entirely."""
        with patch.object(CVESiteBuilder, "fetch_published_totals",
                          return_value=published(10000, **{"1999": 894, "2026": 9106})):
            with pytest.raises(RuntimeError, match="year 1999"):
                builder.verify_no_regression(year_data(**{"2026": 9106}))

    def test_current_year_decrease_is_not_a_closed_year_error(self, builder):
        """The current year is still accumulating; only the total covers it."""
        with patch.object(CVESiteBuilder, "fetch_published_totals",
                          return_value=published(1000, **{"2025": 600, "2026": 400})):
            # total stays healthy, current year dips slightly
            builder.verify_no_regression(year_data(**{"2025": 700, "2026": 395}))

    def test_no_baseline_is_accepted(self, builder):
        """First run has nothing published to compare against."""
        with patch.object(CVESiteBuilder, "fetch_published_totals", return_value=None):
            builder.verify_no_regression(year_data(**{"2026": 1}))

    def test_accept_baseline_skips_check(self, builder):
        builder.accept_baseline = True
        with patch.object(CVESiteBuilder, "fetch_published_totals",
                          side_effect=AssertionError("should not be fetched")):
            builder.verify_no_regression(year_data(**{"2026": 1}))

    def test_allowance_boundary(self, builder):
        """Exactly at the allowance passes; one beyond fails."""
        base = published(1000, **{"2026": 1000})
        with patch.object(CVESiteBuilder, "fetch_published_totals", return_value=base):
            builder.verify_no_regression(year_data(**{"2026": 990}))
            with pytest.raises(RuntimeError):
                builder.verify_no_regression(year_data(**{"2026": 989}))


class TestVerifyDataFreshness:
    def _write_cache_info(self, builder, when: datetime, **extra):
        payload = {"download_time": when.isoformat(), **extra}
        (builder.cache_dir / "cache_info.json").write_text(json.dumps(payload))
        builder.source_provenance.cache_clear()

    def test_accepts_fresh_data(self, builder):
        self._write_cache_info(builder, datetime.now(UTC) - timedelta(hours=2))
        builder.verify_data_freshness()

    def test_rejects_stale_data(self, builder):
        self._write_cache_info(builder, datetime.now(UTC) - timedelta(days=50))
        with pytest.raises(RuntimeError, match="over the 24.0h limit"):
            builder.verify_data_freshness()

    def test_missing_cache_info_warns_but_passes(self, builder):
        """An unreadable cache info should not block a build on its own."""
        builder.source_provenance.cache_clear()
        builder.verify_data_freshness()


class TestSourceProvenance:
    def test_reports_age_and_source_fields(self, builder, tmp_path):
        when = datetime.now(UTC) - timedelta(hours=3)
        (tmp_path / "cache_info.json").write_text(json.dumps({
            "download_time": when.isoformat(),
            "source_last_run": "2026-08-18T01:07:27.380633+00:00",
            "source_cve_count": 378426,
        }))
        builder.source_provenance.cache_clear()
        p = builder.source_provenance()
        assert p["source_cve_count"] == 378426
        assert p["source_last_run"] == "2026-08-18T01:07:27.380633+00:00"
        assert 2.9 < p["data_age_hours"] < 3.1
        assert p["data_as_of"].endswith("Z")

    def test_naive_timestamp_is_read_as_utc(self, builder, tmp_path):
        """Older cache_info files predate the UTC fix."""
        naive = (datetime.now(UTC) - timedelta(hours=1)).replace(tzinfo=None)
        (tmp_path / "cache_info.json").write_text(json.dumps({"download_time": naive.isoformat()}))
        builder.source_provenance.cache_clear()
        p = builder.source_provenance()
        assert 0.9 < p["data_age_hours"] < 1.1

    def test_missing_file_returns_empty_provenance(self, builder):
        builder.source_provenance.cache_clear()
        p = builder.source_provenance()
        assert p["data_as_of"] is None
        assert p["data_age_hours"] is None


class TestGuardEnforcementMode:
    """The guards exist to stop bad data being published.

    A local build publishes nothing, so it warns rather than blocking a
    developer working from a deliberately old cache. CI is the deploy path.
    """

    def test_regression_warns_instead_of_raising_outside_ci(self, lenient_builder):
        with patch.object(CVESiteBuilder, "fetch_published_totals",
                          return_value=published(10000, **{"1999": 894, "2026": 9106})):
            lenient_builder.verify_no_regression(year_data(**{"2026": 9106}))

    def test_stale_data_warns_instead_of_raising_outside_ci(self, lenient_builder):
        stale = datetime.now(UTC) - timedelta(days=53)
        (lenient_builder.cache_dir / "cache_info.json").write_text(
            json.dumps({"download_time": stale.isoformat()})
        )
        lenient_builder.source_provenance.cache_clear()
        lenient_builder.verify_data_freshness()

    def test_strict_mode_is_inferred_from_ci_env(self, monkeypatch):
        monkeypatch.setenv("CI", "true")
        assert CVESiteBuilder(quiet=True).strict_data_guards is True

    def test_not_strict_without_ci_env(self, monkeypatch):
        monkeypatch.delenv("CI", raising=False)
        assert CVESiteBuilder(quiet=True).strict_data_guards is False
