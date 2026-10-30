"""Tests for retrying the nvd.json download and failing the build when it fails.

On 2026-10-30 two builds in a row lost the ~1.8 GB download to a connection
reset from R2. There was no retry, and because requests exceptions subclass
OSError, build.py's per-year handler swallowed the failure as "1999 failed",
downloaded again for 2000, and carried on until the zero-year guard stopped it.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from build import CVESiteBuilder
from data.download_cve_data import NVD_READ_TIMEOUT, CVEDataDownloader
from tests.fakes import FakeHttpClient, FakeHttpResponse


NVD_URL = "https://nvd.handsonhacking.org/nvd.json"
BODY = b'[{"cve": {"id": "CVE-2026-0001"}}]'


class ResetMidStream(FakeHttpResponse):
    """Sends part of the body, then dies the way urllib3 reports a reset."""

    def iter_content(self, chunk_size: int = 1):
        yield self._content[:5]
        raise requests.exceptions.ChunkedEncodingError("Connection broken: ConnectionResetError(104)")


class ScriptedHttpClient(FakeHttpClient):
    """Returns the queued responses (or raises the queued exceptions) in order."""

    def __init__(self, script: list) -> None:
        super().__init__()
        self._script = list(script)

    def get(self, url, *, timeout=None, stream=False):
        self._request_history.append({"url": url, "timeout": timeout, "stream": stream})
        step = self._script.pop(0)
        if isinstance(step, Exception):
            raise step
        return step


def ok_response() -> FakeHttpResponse:
    return FakeHttpResponse(content=BODY, headers={"content-length": str(len(BODY))})


def make_downloader(tmp_path, script) -> tuple[CVEDataDownloader, ScriptedHttpClient]:
    client = ScriptedHttpClient(script)
    d = CVEDataDownloader(cache_dir=tmp_path, quiet=True, http_client=client)
    d.download_retry_delays = (0, 0)
    return d, client


class TestNvdDownloadRetry:
    def test_recovers_from_a_mid_stream_reset(self, tmp_path):
        reset = ResetMidStream(content=BODY, headers={"content-length": str(len(BODY))})
        d, client = make_downloader(tmp_path, [reset, ok_response()])

        path = d.download_data(force=True)

        assert path.read_bytes() == BODY
        assert client.request_count == 2

    def test_recovers_from_a_refused_connection(self, tmp_path):
        d, client = make_downloader(tmp_path, [requests.ConnectionError("refused"), ok_response()])

        assert d.download_data(force=True).read_bytes() == BODY
        assert client.request_count == 2

    def test_retries_a_short_body(self, tmp_path):
        short = FakeHttpResponse(content=BODY[:10], headers={"content-length": str(len(BODY))})
        d, client = make_downloader(tmp_path, [short, ok_response()])

        assert d.download_data(force=True).read_bytes() == BODY
        assert client.request_count == 2

    def test_gives_up_after_the_last_attempt(self, tmp_path):
        d, client = make_downloader(tmp_path, [requests.ConnectionError("reset")] * 3)

        with pytest.raises(requests.ConnectionError):
            d.download_data(force=True)
        assert client.request_count == 3
        assert not d.cache_file.exists()

    def test_does_not_retry_http_errors(self, tmp_path):
        d, client = make_downloader(tmp_path, [FakeHttpResponse(status_code=403)])

        with pytest.raises(Exception, match="HTTP 403"):
            d.download_data(force=True)
        assert client.request_count == 1

    def test_sets_a_read_timeout(self, tmp_path):
        d, client = make_downloader(tmp_path, [ok_response()])

        d.download_data(force=True)

        assert client.request_history[0]["timeout"] == NVD_READ_TIMEOUT
        assert client.request_history[0]["stream"] is True

    def test_waits_between_attempts(self, tmp_path):
        d, _ = make_downloader(tmp_path, [requests.ConnectionError("a"), requests.ConnectionError("b"), ok_response()])
        d.download_retry_delays = (10, 30)

        with patch("data.download_cve_data.time.sleep") as sleep:
            d.download_data(force=True)

        assert [c.args[0] for c in sleep.call_args_list] == [10, 30]


class TestYearDataFailsOnDownloadError:
    def test_download_failure_fails_the_build_instead_of_dropping_a_year(self, tmp_path):
        builder = CVESiteBuilder(quiet=True)
        builder.data_dir = tmp_path

        analyzer = MagicMock()
        analyzer.ensure_data_loaded.side_effect = requests.exceptions.ChunkedEncodingError("Connection broken")

        with patch("cve_years.CVEYearsAnalyzer", return_value=analyzer):
            with pytest.raises(RuntimeError, match="CVE data download failed"):
                builder.generate_year_data_json()

        analyzer.get_year_data.assert_not_called()
