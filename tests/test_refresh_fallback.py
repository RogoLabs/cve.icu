"""Tests for the data refresh path.

A refresh that downloads nothing must never report success. Before the
sequential fallback existed, a missing httpx made `build.py refresh --force`
print a success message and exit 0 in about a second, having fetched nothing.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from build import CVESiteBuilder


@pytest.fixture
def builder(tmp_path):
    b = CVESiteBuilder(quiet=True)
    b.cache_dir = tmp_path
    return b


class TestAsyncUnavailableFallback:
    def test_missing_httpx_falls_back_instead_of_claiming_success(self, builder):
        """The regression this file exists for."""
        with patch.object(CVESiteBuilder, "verify_source_manifest", return_value=None), \
             patch("build.AsyncCVEDownloader", side_effect=ImportError("httpx is required")), \
             patch.object(CVESiteBuilder, "refresh_data_sync", return_value=True) as fallback:
            assert builder.refresh_data(force=True) is True
            fallback.assert_called_once()
            assert fallback.call_args.kwargs["force"] is True

    def test_fallback_failure_is_reported(self, builder):
        with patch.object(CVESiteBuilder, "verify_source_manifest", return_value=None), \
             patch("build.AsyncCVEDownloader", side_effect=ImportError("httpx is required")), \
             patch.object(CVESiteBuilder, "refresh_data_sync", return_value=False):
            assert builder.refresh_data(force=True) is False


class TestRefreshDataSync:
    def _downloader(self):
        d = MagicMock()
        d.download_epss_data.return_value = "epss.gz"
        d.download_kev_data.return_value = "kev.json"
        return d

    def test_downloads_every_source(self, builder):
        d = self._downloader()
        with patch("download_cve_data.CVEDataDownloader", return_value=d):
            assert builder.refresh_data_sync(force=True) is True

        d.download_data.assert_called_once()
        d.download_cna_mapping_files.assert_called_once()
        d.download_epss_data.assert_called_once_with(force=True)
        d.parse_epss_csv.assert_called_once()
        d.download_kev_data.assert_called_once_with(force=True)
        d.parse_kev_json.assert_called_once()

    def test_passes_manifest_through_for_verification(self, builder):
        d = self._downloader()
        manifest = {"cve_count": 1, "last_run_iso": "x"}
        with patch("download_cve_data.CVEDataDownloader", return_value=d):
            builder.refresh_data_sync(force=False, manifest=manifest)

        assert d.download_data.call_args.kwargs["manifest"] == manifest
        d.persist_accepted_manifest.assert_called_once_with(manifest)

    def test_manifest_not_persisted_when_absent(self, builder):
        d = self._downloader()
        with patch("download_cve_data.CVEDataDownloader", return_value=d):
            builder.refresh_data_sync(force=False, manifest=None)
        d.persist_accepted_manifest.assert_not_called()

    def test_download_failure_returns_false(self, builder):
        """A failed download must not be reported as a successful refresh."""
        d = self._downloader()
        d.download_data.side_effect = OSError("Truncated download")
        with patch("download_cve_data.CVEDataDownloader", return_value=d):
            assert builder.refresh_data_sync(force=True) is False

    def test_skips_parsing_when_supplemental_download_fails(self, builder):
        """EPSS and KEV are non-critical, but a failed fetch must not be parsed."""
        d = self._downloader()
        d.download_epss_data.return_value = None
        with patch("download_cve_data.CVEDataDownloader", return_value=d):
            assert builder.refresh_data_sync(force=True) is True
        d.parse_epss_csv.assert_not_called()
        d.parse_kev_json.assert_called_once()
