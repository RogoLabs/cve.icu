#!/usr/bin/env python3
"""
Tests for async CVE data downloader.

Tests parallel download functionality and async HTTP client behavior.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / 'data'))

from tests.fakes import FakeAsyncHttpClient, FakeAsyncHttpResponse


class TestFakeAsyncHttpClient:
    """Tests for FakeAsyncHttpClient test double."""
    
    @pytest.mark.asyncio
    async def test_returns_configured_response(self):
        """Fake async client returns configured response for URL."""
        client = FakeAsyncHttpClient()
        client.add_response(
            'https://example.com/api',
            json_data={'status': 'ok'}
        )
        
        async with client:
            response = await client.get('https://example.com/api')
        
        assert response.status_code == 200
        assert response.json() == {'status': 'ok'}
    
    @pytest.mark.asyncio
    async def test_returns_404_for_unknown_url(self):
        """Fake async client returns 404 for unconfigured URLs."""
        client = FakeAsyncHttpClient()
        
        async with client:
            response = await client.get('https://unknown.com')
        
        assert response.status_code == 404
    
    @pytest.mark.asyncio
    async def test_tracks_request_history(self):
        """Fake async client tracks all requests made."""
        client = FakeAsyncHttpClient()
        client.set_default_response(json_data={})
        
        async with client:
            await client.get('https://example.com/a')
            await client.get('https://example.com/b', timeout=30)
        
        assert client.request_count == 2
        assert client.request_history[0]['url'] == 'https://example.com/a'
        assert client.request_history[1]['timeout'] == 30
    
    @pytest.mark.asyncio
    async def test_parallel_requests(self):
        """Fake async client handles parallel requests."""
        client = FakeAsyncHttpClient()
        client.add_response('https://api1.com', json_data={'source': 'api1'})
        client.add_response('https://api2.com', json_data={'source': 'api2'})
        client.add_response('https://api3.com', json_data={'source': 'api3'})
        
        async with client:
            responses = await asyncio.gather(
                client.get('https://api1.com'),
                client.get('https://api2.com'),
                client.get('https://api3.com'),
            )
        
        assert len(responses) == 3
        sources = {r.json()['source'] for r in responses}
        assert sources == {'api1', 'api2', 'api3'}
        assert client.request_count == 3


class TestAsyncDownloaderIntegration:
    """Integration tests for AsyncCVEDownloader with fakes."""
    
    @pytest.mark.asyncio
    async def test_download_result_dataclass(self):
        """DownloadResult dataclass works correctly."""
        # Import here to avoid issues if httpx not installed
        try:
            from async_downloader import DownloadResult
        except ImportError:
            pytest.skip("async_downloader not available")
        
        result = DownloadResult(
            source="test",
            success=True,
            path=Path("/tmp/test.json"),
            size_bytes=1024,
            duration_seconds=0.5,
        )
        
        assert result.source == "test"
        assert result.success is True
        assert result.size_bytes == 1024
        assert result.from_cache is False
    
    @pytest.mark.asyncio
    async def test_async_downloader_initialization(self, tmp_path):
        """AsyncCVEDownloader initializes correctly."""
        try:
            from async_downloader import AsyncCVEDownloader
        except ImportError:
            pytest.skip("async_downloader not available")
        
        downloader = AsyncCVEDownloader(cache_dir=tmp_path, quiet=True)
        
        assert downloader.cache_dir == tmp_path
        assert downloader.nvd_file == tmp_path / "nvd.json"
        assert downloader.epss_cache_file == tmp_path / "epss_scores-current.csv.gz"
        assert downloader.kev_cache_file == tmp_path / "known_exploited_vulnerabilities.json"


class TestAsyncDownloaderCacheValidity:
    """Tests for cache validity checking."""
    
    def test_cache_validity_for_missing_file(self, tmp_path):
        """Missing file should report invalid cache."""
        try:
            from async_downloader import AsyncCVEDownloader
        except ImportError:
            pytest.skip("async_downloader not available")
        
        downloader = AsyncCVEDownloader(cache_dir=tmp_path, quiet=True)
        
        assert downloader._is_cache_valid(tmp_path / "missing.json") is False
    
    def test_cache_validity_for_existing_file(self, tmp_path):
        """Recent file should report valid cache."""
        try:
            from async_downloader import AsyncCVEDownloader
        except ImportError:
            pytest.skip("async_downloader not available")
        
        test_file = tmp_path / "test.json"
        test_file.write_text('{"test": true}')
        
        downloader = AsyncCVEDownloader(cache_dir=tmp_path, quiet=True)
        
        assert downloader._is_cache_valid(test_file) is True


class TestEpssKevParsing:
    """Tests for EPSS and KEV data parsing."""
    
    def test_parse_kev_json(self, tmp_path):
        """KEV JSON parsing works correctly."""
        try:
            from async_downloader import AsyncCVEDownloader
        except ImportError:
            pytest.skip("async_downloader not available")
        
        # Create fake KEV data
        kev_data = {
            "vulnerabilities": [
                {"cveID": "CVE-2024-0001"},
                {"cveID": "CVE-2024-0002"},
                {"cveID": "CVE-2023-9999"},
            ]
        }
        
        downloader = AsyncCVEDownloader(cache_dir=tmp_path, quiet=True)
        downloader.kev_cache_file.write_text(json.dumps(kev_data))
        
        result = downloader.parse_kev()
        
        assert result is not None
        assert len(result) == 3
        assert "CVE-2024-0001" in result
        assert "CVE-2024-0002" in result
        assert "CVE-2023-9999" in result
    
    def test_parse_kev_handles_missing_file(self, tmp_path):
        """KEV parsing handles missing file gracefully."""
        try:
            from async_downloader import AsyncCVEDownloader
        except ImportError:
            pytest.skip("async_downloader not available")
        
        downloader = AsyncCVEDownloader(cache_dir=tmp_path, quiet=True)
        
        result = downloader.parse_kev()
        
        assert result is None


class TestParallelDownloadBehavior:
    """Tests demonstrating parallel download behavior."""
    
    @pytest.mark.asyncio
    async def test_gather_collects_all_results(self):
        """asyncio.gather collects results from parallel tasks."""
        async def fake_download(name: str, delay: float) -> dict:
            await asyncio.sleep(delay)
            return {'source': name, 'success': True}
        
        # All downloads complete in ~0.1s total (parallel)
        # vs ~0.3s if sequential
        results = await asyncio.gather(
            fake_download('nvd', 0.05),
            fake_download('epss', 0.05),
            fake_download('kev', 0.05),
        )
        
        assert len(results) == 3
        sources = {r['source'] for r in results}
        assert sources == {'nvd', 'epss', 'kev'}
    
    @pytest.mark.asyncio
    async def test_gather_handles_exceptions(self):
        """asyncio.gather with return_exceptions handles failures."""
        async def succeed() -> str:
            return "ok"
        
        async def fail() -> str:
            raise ValueError("download failed")
        
        results = await asyncio.gather(
            succeed(),
            fail(),
            succeed(),
            return_exceptions=True,
        )
        
        assert results[0] == "ok"
        assert isinstance(results[1], ValueError)
        assert results[2] == "ok"
