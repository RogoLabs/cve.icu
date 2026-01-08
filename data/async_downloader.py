#!/usr/bin/env python3
"""
Async CVE Data Downloader

Provides parallel download capabilities for CVE data from multiple sources.
Uses httpx for async HTTP requests, enabling ~3x faster downloads by
fetching from NVD, EPSS, KEV, and CNA sources simultaneously.

Usage:
    # Async context manager for parallel downloads
    async with AsyncCVEDownloader() as downloader:
        results = await downloader.download_all_sources()
    
    # Or use the sync wrapper
    downloader = AsyncCVEDownloader()
    results = downloader.download_all_sync()
"""
from __future__ import annotations

import asyncio
import csv
import gzip
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

try:
    from data.logging_config import get_logger
except ImportError:
    from logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class DownloadResult:
    """Result of a single download operation."""
    source: str
    success: bool
    path: Path | None = None
    size_bytes: int = 0
    duration_seconds: float = 0.0
    error: str | None = None
    from_cache: bool = False


@dataclass
class AsyncCVEDownloader:
    """Async downloader for CVE data from multiple sources.
    
    Downloads data from 5 sources in parallel:
    1. NVD CVE database (nvd.json) - Main CVE data
    2. CNA List (cna_list.json) - CNA organization list
    3. CNA Name Map (cna_name_map.json) - CNA name mappings  
    4. EPSS Scores (epss_scores-current.csv.gz) - Exploit prediction scores
    5. KEV Catalog (known_exploited_vulnerabilities.json) - Known exploited CVEs
    
    Attributes:
        cache_dir: Directory for cached downloads
        cache_duration: How long to consider cache valid
        timeout: HTTP request timeout in seconds
        quiet: Suppress info logging
    """
    cache_dir: Path = field(default_factory=lambda: Path(__file__).parent / 'cache')
    cache_duration: timedelta = field(default_factory=lambda: timedelta(hours=4))
    timeout: int = 120
    quiet: bool = False
    
    # URL configurations
    nvd_url: str = "https://nvd.handsonhacking.org/nvd.json"
    cna_list_url: str = "https://raw.githubusercontent.com/CVEProject/cve-website/dev/src/assets/data/CNAsList.json"
    cna_name_map_url: str = "https://www.cve.org/cve-partner-name-map.json"
    epss_url: str = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
    kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    _client: Any = field(default=None, init=False, repr=False)
    
    def __post_init__(self) -> None:
        """Ensure cache directory exists."""
        self.cache_dir = Path(self.cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Define cache file paths
        self.nvd_file = self.cache_dir / "nvd.json"
        self.cna_list_file = self.cache_dir / "cna_list.json"
        self.cna_name_map_file = self.cache_dir / "cna_name_map.json"
        self.epss_cache_file = self.cache_dir / "epss_scores-current.csv.gz"
        self.epss_parsed_file = self.cache_dir / "epss_scores-current.json"
        self.kev_cache_file = self.cache_dir / "known_exploited_vulnerabilities.json"
        self.kev_parsed_file = self.cache_dir / "known_exploited_vulnerabilities_parsed.json"
        self.cache_info_file = self.cache_dir / "cache_info.json"
    
    async def __aenter__(self) -> "AsyncCVEDownloader":
        """Create async HTTP client on context entry."""
        if not HTTPX_AVAILABLE:
            raise ImportError("httpx is required for async downloads. Install with: pip install httpx")
        self._client = httpx.AsyncClient(timeout=self.timeout, follow_redirects=True)
        return self
    
    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Close async HTTP client on context exit."""
        if self._client:
            await self._client.aclose()
            self._client = None
    
    def _is_cache_valid(self, cache_file: Path) -> bool:
        """Check if a cache file exists and is not expired."""
        if not cache_file.exists():
            return False
        try:
            mtime = datetime.fromtimestamp(cache_file.stat().st_mtime)
            return datetime.now() - mtime < self.cache_duration
        except OSError:
            return False
    
    async def _download_file(
        self,
        url: str,
        cache_file: Path,
        source_name: str,
        force: bool = False,
        is_binary: bool = False,
    ) -> DownloadResult:
        """Download a single file with caching support.
        
        Args:
            url: URL to download from
            cache_file: Path to save the file
            source_name: Human-readable name for logging
            force: Force download even if cache is valid
            is_binary: Whether to save as binary (for gzip files)
            
        Returns:
            DownloadResult with success status and metadata
        """
        start_time = datetime.now()
        
        # Check cache first
        if not force and self._is_cache_valid(cache_file):
            if not self.quiet:
                logger.debug(f"  ✅ Using cached {source_name}")
            return DownloadResult(
                source=source_name,
                success=True,
                path=cache_file,
                size_bytes=cache_file.stat().st_size if cache_file.exists() else 0,
                duration_seconds=0.0,
                from_cache=True,
            )
        
        if not self.quiet:
            logger.info(f"  🔽 Downloading {source_name}...")
        
        try:
            response = await self._client.get(url)
            response.raise_for_status()
            
            # Save content
            if is_binary:
                cache_file.write_bytes(response.content)
            else:
                cache_file.write_text(response.text, encoding='utf-8')
            
            duration = (datetime.now() - start_time).total_seconds()
            size = len(response.content)
            
            if not self.quiet:
                size_str = f"{size / (1024*1024):.2f} MB" if size > 1024*1024 else f"{size / 1024:.1f} KB"
                logger.info(f"  ✅ {source_name} complete ({size_str} in {duration:.1f}s)")
            
            return DownloadResult(
                source=source_name,
                success=True,
                path=cache_file,
                size_bytes=size,
                duration_seconds=duration,
            )
            
        except httpx.HTTPError as e:
            duration = (datetime.now() - start_time).total_seconds()
            error_msg = str(e)
            
            # Try to use stale cache as fallback
            if cache_file.exists():
                logger.warning(f"  ⚠️  {source_name} download failed, using stale cache: {error_msg}")
                return DownloadResult(
                    source=source_name,
                    success=True,
                    path=cache_file,
                    size_bytes=cache_file.stat().st_size,
                    duration_seconds=duration,
                    from_cache=True,
                    error=f"Using stale cache: {error_msg}",
                )
            
            logger.error(f"  ❌ {source_name} download failed: {error_msg}")
            return DownloadResult(
                source=source_name,
                success=False,
                duration_seconds=duration,
                error=error_msg,
            )
    
    async def download_nvd(self, force: bool = False) -> DownloadResult:
        """Download NVD CVE database."""
        result = await self._download_file(
            self.nvd_url, self.nvd_file, "NVD CVE Data", force
        )
        
        # Update cache info if successful
        if result.success and not result.from_cache:
            cache_info = {
                'download_time': datetime.now().isoformat(),
                'file_size': result.size_bytes,
                'file_hash': self._calculate_hash(self.nvd_file),
                'source_url': self.nvd_url,
            }
            self.cache_info_file.write_text(json.dumps(cache_info, indent=2))
        
        return result
    
    async def download_cna_list(self, force: bool = False) -> DownloadResult:
        """Download CNA organization list."""
        return await self._download_file(
            self.cna_list_url, self.cna_list_file, "CNA List", force
        )
    
    async def download_cna_name_map(self, force: bool = False) -> DownloadResult:
        """Download CNA name mapping."""
        return await self._download_file(
            self.cna_name_map_url, self.cna_name_map_file, "CNA Name Map", force
        )
    
    async def download_epss(self, force: bool = False) -> DownloadResult:
        """Download EPSS scores (gzipped CSV)."""
        return await self._download_file(
            self.epss_url, self.epss_cache_file, "EPSS Scores", force, is_binary=True
        )
    
    async def download_kev(self, force: bool = False) -> DownloadResult:
        """Download CISA KEV catalog."""
        return await self._download_file(
            self.kev_url, self.kev_cache_file, "KEV Catalog", force
        )
    
    async def download_all_sources(self, force: bool = False) -> dict[str, DownloadResult]:
        """Download all data sources in parallel.
        
        This is the main method that provides ~3x speedup by running
        all downloads concurrently.
        
        Args:
            force: Force download even if caches are valid
            
        Returns:
            Dict mapping source names to DownloadResult objects
        """
        if not self.quiet:
            logger.info("🚀 Starting parallel download of all CVE data sources...")
        
        start_time = datetime.now()
        
        # Run all downloads in parallel
        results = await asyncio.gather(
            self.download_nvd(force),
            self.download_cna_list(force),
            self.download_cna_name_map(force),
            self.download_epss(force),
            self.download_kev(force),
            return_exceptions=True,
        )
        
        # Convert to dict and handle exceptions
        source_names = ['nvd', 'cna_list', 'cna_name_map', 'epss', 'kev']
        results_dict: dict[str, DownloadResult] = {}
        
        for name, result in zip(source_names, results):
            if isinstance(result, Exception):
                results_dict[name] = DownloadResult(
                    source=name,
                    success=False,
                    error=str(result),
                )
            else:
                results_dict[name] = result
        
        total_duration = (datetime.now() - start_time).total_seconds()
        
        # Summary logging
        if not self.quiet:
            successful = sum(1 for r in results_dict.values() if r.success)
            total_bytes = sum(r.size_bytes for r in results_dict.values() if r.success)
            cached = sum(1 for r in results_dict.values() if r.from_cache)
            
            logger.info(f"\n📊 Download Summary:")
            logger.info(f"  ✅ Successful: {successful}/{len(results_dict)}")
            logger.info(f"  📦 Total size: {total_bytes / (1024*1024):.2f} MB")
            logger.info(f"  💾 From cache: {cached}")
            logger.info(f"  ⏱️  Total time: {total_duration:.1f}s")
        
        return results_dict
    
    def _calculate_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of file."""
        hash_sha256 = hashlib.sha256()
        content = file_path.read_bytes()
        hash_sha256.update(content)
        return hash_sha256.hexdigest()
    
    def parse_epss(self) -> dict[str, dict[str, float]] | None:
        """Parse EPSS CSV into JSON mapping.
        
        Returns dict like:
        {
            "CVE-2024-12345": {"epss_score": 0.1234, "epss_percentile": 0.9876},
            ...
        }
        """
        if not self.epss_cache_file.exists():
            return None
        
        if not self.quiet:
            logger.info("  🔍 Parsing EPSS CSV...")
        
        mapping: dict[str, dict[str, float]] = {}
        try:
            with gzip.open(self.epss_cache_file, mode="rt", encoding="utf-8") as f:
                lines = (line for line in f if not line.startswith('#'))
                reader = csv.DictReader(lines)
                for row in reader:
                    cve_id = row.get("cve") or row.get("CVE")
                    if not cve_id:
                        continue
                    try:
                        score = float(row.get("epss", "0") or 0)
                    except ValueError:
                        score = 0.0
                    try:
                        percentile = float(row.get("percentile", "0") or 0)
                    except ValueError:
                        percentile = 0.0
                    mapping[cve_id.strip()] = {
                        "epss_score": score,
                        "epss_percentile": percentile,
                    }
            
            # Save parsed JSON
            self.epss_parsed_file.write_text(json.dumps(mapping), encoding='utf-8')
            
            if not self.quiet:
                logger.info(f"  ✅ EPSS parsed: {len(mapping):,} CVEs")
            
            return mapping
            
        except (gzip.BadGzipFile, csv.Error, OSError) as e:
            logger.warning(f"  ⚠️  EPSS parse failed: {e}")
            return None
    
    def parse_kev(self) -> dict[str, bool] | None:
        """Parse KEV JSON into CVE set.
        
        Returns dict like:
        {
            "CVE-2024-12345": True,
            ...
        }
        """
        if not self.kev_cache_file.exists():
            return None
        
        if not self.quiet:
            logger.info("  🔍 Parsing KEV JSON...")
        
        try:
            raw = json.loads(self.kev_cache_file.read_text(encoding='utf-8'))
            
            vulnerabilities = raw.get("vulnerabilities")
            if vulnerabilities is None and isinstance(raw, list):
                vulnerabilities = raw
            
            mapping: dict[str, bool] = {
                cve_id.strip(): True
                for entry in (vulnerabilities if isinstance(vulnerabilities, list) else [])
                if (cve_id := entry.get("cveID") or entry.get("cveId") or entry.get("cve"))
                and isinstance(cve_id, str)
                and cve_id.startswith("CVE-")
            }
            
            # Save parsed JSON
            self.kev_parsed_file.write_text(json.dumps(mapping), encoding='utf-8')
            
            if not self.quiet:
                logger.info(f"  ✅ KEV parsed: {len(mapping):,} CVEs")
            
            return mapping
            
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"  ⚠️  KEV parse failed: {e}")
            return None
    
    def download_all_sync(self, force: bool = False) -> dict[str, DownloadResult]:
        """Synchronous wrapper for download_all_sources().
        
        Use this when you need to call from non-async code.
        
        Example:
            downloader = AsyncCVEDownloader()
            results = downloader.download_all_sync()
        """
        async def _run() -> dict[str, DownloadResult]:
            async with self as dl:
                return await dl.download_all_sources(force)
        
        return asyncio.run(_run())


async def main_async() -> None:
    """Async main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Download CVE data (async)")
    parser.add_argument('--force', action='store_true', help='Force download')
    parser.add_argument('--cache-dir', help='Custom cache directory')
    
    args = parser.parse_args()
    
    cache_dir = Path(args.cache_dir) if args.cache_dir else None
    
    async with AsyncCVEDownloader(cache_dir=cache_dir) as downloader:
        results = await downloader.download_all_sources(force=args.force)
        
        # Parse supplemental data
        downloader.parse_epss()
        downloader.parse_kev()
        
        # Show results
        for name, result in results.items():
            status = "✅" if result.success else "❌"
            print(f"{status} {name}: {result.path or result.error}")


def main() -> None:
    """Sync main entry point."""
    asyncio.run(main_async())


if __name__ == '__main__':
    main()
