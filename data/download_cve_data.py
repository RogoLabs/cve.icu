#!/usr/bin/env python3
"""
CVE Data Download Script
Downloads and caches CVE data from NVD source for processing
Replaces the wget step from GitHub Actions with proper Python error handling
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import requests
from protocols import (
    DataReader,
    DataWriter,
    FileSystemDataReader,
    FileSystemDataWriter,
    HttpClient,
    RequestsHttpClient,
)


try:
    from data.logging_config import get_logger
except ImportError:
    from logging_config import get_logger

logger = get_logger(__name__)


class CVEDataDownloader:
    """Downloads and manages CVE data from NVD source.

    Supports dependency injection for testability:
    - http_client: HttpClient protocol for HTTP requests
    - data_reader: DataReader protocol for file reading
    - data_writer: DataWriter protocol for file writing

    When dependencies are not provided, uses default implementations
    (requests for HTTP, filesystem for files).
    """

    def __init__(
        self,
        cache_dir: Path | str | None = None,
        quiet: bool = False,
        *,
        http_client: HttpClient | None = None,
        data_reader: DataReader | None = None,
        data_writer: DataWriter | None = None,
    ) -> None:
        self.quiet: bool = quiet
        self.base_dir: Path = Path(__file__).parent
        self.cache_dir: Path = Path(cache_dir) if cache_dir else (self.base_dir / "cache")

        # Dependency injection with defaults
        self._http_client = http_client or RequestsHttpClient()
        self._data_reader = data_reader or FileSystemDataReader()
        self._data_writer = data_writer or FileSystemDataWriter()

        # Create cache directory using writer
        self._data_writer.mkdir(self.cache_dir)

        # Data source configuration
        self.nvd_url: str = "https://nvd.handsonhacking.org/nvd.json"
        self.cache_file: Path = self.cache_dir / "nvd.json"
        self.cache_info_file: Path = self.cache_dir / "cache_info.json"
        self.cache_duration: timedelta = timedelta(hours=4)  # Cache for 4 hours to match build schedule

        # Producer-published manifest describing the snapshot behind nvd.json.
        # Small (~2KB), no-cache, and written *after* the data object, so a
        # manifest that names a snapshot implies that snapshot is fully uploaded.
        self.manifest_url: str = "https://nvd.handsonhacking.org/metadata.json"
        # The last manifest we accepted, republished with the site so the next
        # build has a baseline without needing repo state. See docs in
        # verify_manifest_not_regressed().
        self.manifest_baseline_url: str = "https://cve.icu/data/source_manifest.json"
        self.manifest_file: Path = self.cache_dir / "source_manifest.json"
        # Producer reports its own completeness_ratio. This is a catastrophe
        # backstop only, NOT the primary defence: the regression check against
        # the last accepted manifest is. Calibration caveat: the only healthy
        # value observed so far is 0.9992, so the normal variance of this field
        # is unknown and the threshold is deliberately loose. Tighten it once
        # there is a distribution to set it from, rather than from one sample.
        self.min_completeness_ratio: float = 0.995

        # CNA mapping files for proper name resolution
        self.cna_list_url: str = (
            "https://raw.githubusercontent.com/CVEProject/cve-website/dev/src/assets/data/CNAsList.json"
        )
        self.cna_name_map_url: str = "https://www.cve.org/cve-partner-name-map.json"
        self.cna_list_file: Path = self.cache_dir / "cna_list.json"
        self.cna_name_map_file: Path = self.cache_dir / "cna_name_map.json"

        # EPSS data (Exploit Prediction Scoring System)
        # Current snapshot feed documented at https://www.first.org/epss/
        # Note: EPSS moved from cyentia.com to empiricalsecurity.com in late 2025
        self.epss_url: str = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
        self.epss_cache_file: Path = self.cache_dir / "epss_scores-current.csv.gz"
        self.epss_parsed_file: Path = self.cache_dir / "epss_scores-current.json"

        # CISA Known Exploited Vulnerabilities (KEV) catalog
        # Official catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
        # JSON feed: a list of objects with a cveID field.
        self.kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        self.kev_cache_file: Path = self.cache_dir / "known_exploited_vulnerabilities.json"
        self.kev_parsed_file: Path = self.cache_dir / "known_exploited_vulnerabilities_parsed.json"

        if not self.quiet:
            logger.info("🔽 CVE Data Downloader Initialized")
            logger.info(f"📁 Cache directory: {self.cache_dir}")
            logger.info(f"🌐 Data source: {self.nvd_url}")

    def is_cache_valid(self) -> bool:
        """Check if cached data is still valid"""
        if not self._data_reader.exists(self.cache_file) or not self._data_reader.exists(self.cache_info_file):
            return False

        try:
            cache_info = self._data_reader.read_json(self.cache_info_file)

            cache_time = datetime.fromisoformat(cache_info["download_time"])
            # Older cache_info files carry a naive local timestamp; treat those
            # as UTC so the comparison below stays valid across the format change.
            if cache_time.tzinfo is None:
                cache_time = cache_time.replace(tzinfo=UTC)
            if datetime.now(UTC) - cache_time > self.cache_duration:
                if not self.quiet:
                    logger.info(f"⏰ Cache expired (older than {self.cache_duration})")
                return False

            if not self.quiet:
                logger.info(f"✅ Cache is valid (downloaded {cache_time.strftime('%Y-%m-%d %H:%M:%S')})")
            return True

        except (json.JSONDecodeError, KeyError, ValueError) as e:
            if not self.quiet:
                logger.warning(f"⚠️  Cache info corrupted: {e}")
            return False

    def download_data(self, force: bool = False, manifest: dict[str, Any] | None = None) -> Path:
        """Download CVE data from NVD source.

        Args:
            force: bypass the local cache-validity check.
            manifest: producer manifest for this snapshot. When it carries
                'bytes' or 'sha256', the downloaded object is verified against
                them before being accepted.
        """
        if not force and self.is_cache_valid():
            if not self.quiet:
                logger.info("📋 Using cached data")
            return self.cache_file

        if not self.quiet:
            logger.info(f"🔽 Downloading CVE data from {self.nvd_url}")

        try:
            # Start download with progress tracking (use injected HTTP client)
            response = self._http_client.get(self.nvd_url, stream=True)
            response.raise_for_status()

            # Get file size for progress tracking
            total_size = int(response.headers.get("content-length", 0))
            downloaded_size = 0

            # Download with progress updates - collect chunks then write
            chunks: list[bytes] = []
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    chunks.append(chunk)
                    downloaded_size += len(chunk)

                    # Show progress every 10MB
                    if downloaded_size % (10 * 1024 * 1024) == 0 or downloaded_size == total_size:
                        if total_size > 0:
                            progress = (downloaded_size / total_size) * 100
                            logger.debug(
                                f"  📥 Downloaded {downloaded_size // (1024 * 1024)}MB / {total_size // (1024 * 1024)}MB ({progress:.1f}%)"
                            )

            # A dropped connection previously produced a short file that was
            # written and reported as a success. content-length is advisory,
            # but when the server sends one, a mismatch means truncation.
            if total_size and downloaded_size != total_size:
                raise OSError(
                    f"Truncated download: received {downloaded_size:,} of "
                    f"{total_size:,} bytes declared by content-length"
                )

            # Write using data writer
            self._data_writer.write_bytes(self.cache_file, b"".join(chunks))

            # Verify the object against the producer's manifest before we
            # treat it as usable. Raises on any mismatch.
            self.verify_download_against_manifest(manifest, downloaded_size)

            # Calculate file hash for integrity check
            file_hash = self.calculate_file_hash_streaming(self.cache_file)

            # Save cache info using data writer
            cache_info = {
                # UTC: this value is compared against build time to derive data
                # age, and a naive local timestamp made that comparison wrong.
                "download_time": datetime.now(UTC).isoformat(),
                "file_size": downloaded_size,
                "file_hash": file_hash,
                "source_url": self.nvd_url,
                "source_last_run": (manifest or {}).get("last_run_iso"),
                "source_cve_count": (manifest or {}).get("cve_count"),
                "source_commit_sha": (manifest or {}).get("commit_sha"),
            }

            self._data_writer.write_json(self.cache_info_file, cache_info)

            logger.info("✅ Download completed successfully")
            logger.info(f"📊 File size: {downloaded_size // (1024 * 1024)}MB")
            logger.debug(f"🔐 File hash: {file_hash[:16]}...")

            return self.cache_file

        except requests.RequestException as e:
            logger.error(f"❌ Download failed: {e}")
            # Try to use cached data if available, even if expired
            if self._data_reader.exists(self.cache_file):
                logger.warning("⚠️  Using expired cached data as fallback")
                return self.cache_file
            raise

        except (OSError, json.JSONDecodeError) as e:
            logger.error(f"❌ File or JSON error during download: {e}")
            raise

    def download_cna_mapping_files(self) -> None:
        """Download CNA mapping files for proper name resolution"""
        logger.info("🔽 Downloading CNA mapping files...")

        try:
            # Download CNA list (use injected HTTP client)
            logger.debug("  📥 Downloading CNA list from CVE.org...")
            response = self._http_client.get(self.cna_list_url, timeout=30)
            response.raise_for_status()

            self._data_writer.write_json(self.cna_list_file, response.json())
            logger.debug(f"  ✅ CNA list saved to {self.cna_list_file.name}")

            # Download CNA name mapping (use injected HTTP client)
            logger.debug("  📥 Downloading CNA name mapping from CVE.org...")
            response = self._http_client.get(self.cna_name_map_url, timeout=30)
            response.raise_for_status()

            self._data_writer.write_json(self.cna_name_map_file, response.json())
            logger.debug(f"  ✅ CNA name mapping saved to {self.cna_name_map_file.name}")

            logger.info("✅ CNA mapping files downloaded successfully")

        except requests.RequestException as e:
            logger.warning(f"⚠️  Warning: Could not download CNA mapping files: {e}")
            logger.warning("  📝 Will use raw sourceIdentifier values as fallback")
        except (OSError, json.JSONDecodeError) as e:
            logger.warning(f"⚠️  Warning: File or JSON error downloading CNA files: {e}")

    # ------------------------------------------------------------------
    # Source manifest handling
    #
    # The producer publishes metadata.json alongside nvd.json describing the
    # snapshot it just uploaded. Checking it before pulling the ~1.8GB object
    # turns several count heuristics into exact checks, and catches a short
    # snapshot before we spend the bandwidth on it.
    #
    # Keying note: manifest year_counts are keyed by CVE-ID year, while this
    # site buckets by publication date. The two are different partitions of
    # the same data (year 1999 is 1,579 by ID and 923 by publication date), so
    # manifest counts are only ever compared to *previous manifest* counts,
    # never to our own per-year outputs.
    # ------------------------------------------------------------------

    def fetch_source_manifest(self) -> dict[str, Any] | None:
        """Fetch the producer's manifest for the current snapshot.

        Returns None when the manifest cannot be retrieved or parsed, which
        callers treat as "unverified" rather than as a failure, so a producer
        that has not yet deployed the manifest does not break the build.
        """
        try:
            response = self._http_client.get(self.manifest_url, timeout=30)
            status = getattr(response, "status_code", 200)
            if status >= 400:
                logger.warning(f"⚠️  Source manifest returned HTTP {status}")
                return None
            manifest = response.json()
        except (requests.RequestException, ValueError, json.JSONDecodeError, OSError) as e:
            logger.warning(f"⚠️  Could not fetch source manifest: {e}")
            return None

        if not isinstance(manifest, dict) or "cve_count" not in manifest:
            logger.warning("⚠️  Source manifest is malformed; ignoring")
            return None

        logger.info(
            f"📄 Source manifest: {manifest['cve_count']:,} CVEs, run {manifest.get('last_run_iso', 'unknown')}"
        )
        return manifest

    def fetch_baseline_manifest(self) -> dict[str, Any] | None:
        """Fetch the last manifest we accepted, as republished with the site."""
        try:
            response = self._http_client.get(self.manifest_baseline_url, timeout=30)
            status = getattr(response, "status_code", 200)
            if status == 404:
                logger.info("📄 No published baseline manifest yet (first run)")
                return None
            if status >= 400:
                logger.warning(f"⚠️  Baseline manifest returned HTTP {status}")
                return None
            baseline = response.json()
        except (requests.RequestException, ValueError, json.JSONDecodeError, OSError) as e:
            logger.warning(f"⚠️  Could not fetch baseline manifest: {e}")
            return None

        if not isinstance(baseline, dict) or "cve_count" not in baseline:
            logger.warning("⚠️  Baseline manifest is malformed; ignoring")
            return None
        return baseline

    def verify_manifest_healthy(self, manifest: dict[str, Any]) -> None:
        """Reject a snapshot the producer itself reports as incomplete.

        Raises:
            ValueError: if the run was degraded, fell back to the API for any
                year, or came in under the completeness threshold.
        """
        if manifest.get("degraded"):
            raise ValueError(
                f"Producer reported a degraded run (last_run_iso={manifest.get('last_run_iso')}). Refusing to ingest."
            )

        years_via_api = manifest.get("years_via_api") or []
        if years_via_api:
            raise ValueError(
                f"Producer fell back to the REST API for year(s) {years_via_api}. "
                "That fallback drops records whose CVE-ID year and publication "
                "year differ. Refusing to ingest."
            )

        ratio = manifest.get("completeness_ratio")
        if ratio is not None and ratio < self.min_completeness_ratio:
            raise ValueError(
                f"Producer completeness_ratio {ratio} is below "
                f"{self.min_completeness_ratio} "
                f"({manifest.get('cve_count'):,} of an expected "
                f"{manifest.get('expected_total')}). Refusing to ingest."
            )

    def verify_manifest_not_regressed(
        self,
        manifest: dict[str, Any],
        baseline: dict[str, Any] | None,
    ) -> None:
        """Reject a snapshot smaller than the last one we accepted.

        Both sides are CVE-ID keyed, so this is a like-for-like comparison.
        CVEs are withdrawn occasionally, but a genuine withdrawal is a handful
        of records; every regression observed in this feed's history has been a
        producer-side fault of hundreds to thousands.

        Raises:
            ValueError: on any decrease in the total or in any per-year count.
        """
        if baseline is None:
            logger.info("📄 No baseline to compare against; accepting manifest")
            return

        problems: list[str] = []

        prev_total = baseline.get("cve_count", 0)
        new_total = manifest.get("cve_count", 0)
        if new_total < prev_total:
            problems.append(f"total {prev_total:,} -> {new_total:,} ({new_total - prev_total:,})")

        new_years = manifest.get("year_counts") or {}
        for year, prev_count in sorted((baseline.get("year_counts") or {}).items()):
            new_count = new_years.get(year, 0)
            if new_count < prev_count:
                problems.append(f"year {year} {prev_count:,} -> {new_count:,} ({new_count - prev_count:,})")

        if problems:
            raise ValueError(
                "Source manifest regressed against the last accepted snapshot:\n  "
                + "\n  ".join(problems)
                + "\nRefusing to ingest. Re-run once the producer publishes a "
                "complete snapshot, or pass --accept-baseline to override."
            )

        logger.info(f"✅ Manifest not regressed (total {prev_total:,} -> {new_total:,})")

    def verify_download_against_manifest(
        self,
        manifest: dict[str, Any] | None,
        downloaded_size: int,
    ) -> None:
        """Verify the downloaded object against the manifest's size and digest.

        Both fields are optional: they appear only from the first producer run
        after the integrity work landed, so their absence is logged, not fatal.

        Raises:
            OSError: on a size or digest mismatch.
        """
        if not manifest:
            return

        expected_bytes = manifest.get("bytes")
        if expected_bytes is None:
            logger.warning("⚠️  Manifest has no 'bytes' field; skipping size verification")
        elif downloaded_size != expected_bytes:
            raise OSError(
                f"Size mismatch: downloaded {downloaded_size:,} bytes, "
                f"manifest declares {expected_bytes:,}. Snapshot is incomplete."
            )
        else:
            logger.info(f"✅ Size verified against manifest ({downloaded_size:,} bytes)")

        expected_sha = manifest.get("sha256")
        if expected_sha is None:
            logger.warning("⚠️  Manifest has no 'sha256' field; skipping digest verification")
            return

        actual_sha = self.calculate_file_hash_streaming(self.cache_file)
        if actual_sha != expected_sha:
            raise OSError(f"SHA-256 mismatch: computed {actual_sha}, manifest declares {expected_sha}.")
        logger.info("✅ SHA-256 verified against manifest")

    def persist_accepted_manifest(self, manifest: dict[str, Any]) -> None:
        """Record the manifest we accepted so the site can republish it."""
        self._data_writer.write_json(self.manifest_file, manifest)
        logger.debug(f"  📄 Accepted manifest saved to {self.manifest_file.name}")

    def calculate_file_hash_streaming(self, file_path: Path, chunk_size: int = 8 * 1024 * 1024) -> str:
        """SHA-256 a file without loading it into memory.

        calculate_file_hash() reads the whole file, which is not viable for the
        ~1.8GB snapshot on a CI runner.
        """
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as fh:
            for chunk in iter(lambda: fh.read(chunk_size), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

    def calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of file for integrity checking"""
        hash_sha256 = hashlib.sha256()
        content = self._data_reader.read_bytes(file_path)
        hash_sha256.update(content)
        return hash_sha256.hexdigest()

    def validate_json_format(self, file_path: Path) -> bool:
        """Validate that the downloaded file contains valid CVE data (JSON array format)"""
        try:
            logger.info("🔍 Validating JSON format...")

            try:
                # Try to load as JSON array using data reader
                cve_data = self._data_reader.read_json(file_path)

                if not isinstance(cve_data, list):
                    raise ValueError("Expected JSON array format")

                total_records = len(cve_data)
                valid_cve_count = 0

                logger.debug(f"  📊 Found {total_records:,} records in JSON array")

                # Validate a sample of records
                sample_size = min(1000, total_records)
                for i in range(0, total_records, max(1, total_records // sample_size)):
                    if i >= total_records:
                        break

                    record = cve_data[i]
                    if isinstance(record, dict) and "cve" in record:
                        cve_id = record.get("cve", {}).get("id", "")
                        if cve_id.startswith("CVE-"):
                            valid_cve_count += 1

                logger.info("✅ Validation complete:")
                logger.info(f"  📊 Total records: {total_records:,}")
                logger.debug(f"  ✅ Valid CVEs (sampled): {valid_cve_count}/{sample_size}")
                logger.debug(f"  📈 Success rate: {(valid_cve_count / sample_size) * 100:.1f}%")

                if valid_cve_count == 0:
                    raise ValueError("No valid CVE records found in downloaded data")

                return True

            except json.JSONDecodeError as e:
                logger.error(f"❌ Failed to parse JSON: {e}")
                return False

        except (json.JSONDecodeError, KeyError, ValueError, OSError) as e:
            logger.error(f"❌ Validation failed: {e}")
            return False

    def get_data_stats(self) -> dict[str, Any] | None:
        """Get statistics about the cached data (JSON array format)"""
        if not self._data_reader.exists(self.cache_file):
            return None

        try:
            cache_info = self._data_reader.read_json(self.cache_info_file)

            # Load and process JSON array
            with open(self.cache_file, encoding="utf-8") as f:
                cve_data_array = json.load(f)

            # Quick scan for year distribution
            year_counts: dict[int, int] = {}
            total_cves = 0

            # Sample every 100th record for performance (still gives accurate stats)
            sample_size = max(1, len(cve_data_array) // 100)
            for i in range(0, len(cve_data_array), sample_size):
                try:
                    cve_record = cve_data_array[i]
                    cve_id = cve_record.get("cve", {}).get("id", "")

                    if cve_id.startswith("CVE-"):
                        # Extract year from CVE-YYYY-NNNN format
                        year = int(cve_id.split("-")[1])
                        year_counts[year] = year_counts.get(year, 0) + sample_size
                        total_cves += sample_size

                except (KeyError, ValueError, IndexError):
                    continue

            # Adjust for sampling
            actual_total = len(cve_data_array)

            return {
                "cache_info": cache_info,
                "total_cves": actual_total,
                "year_range": (min(year_counts.keys()), max(year_counts.keys())) if year_counts else (None, None),
                "year_counts": dict(sorted(year_counts.items())),
            }

        except (json.JSONDecodeError, KeyError, ValueError, OSError) as e:
            logger.warning(f"⚠️  Could not get data stats: {e}")
            return None

    def ensure_data_available(self, force_download: bool = False, accept_baseline: bool = False) -> Path:
        """Main method to ensure CVE data is available and valid.

        Args:
            force_download: bypass the local cache-validity check.
            accept_baseline: skip the manifest regression check. For the rare
                case where the producer legitimately publishes a smaller
                snapshot (a genuine mass withdrawal) and a human has confirmed it.
        """
        logger.info("\n🔽 Ensuring CVE data is available...")
        logger.info("=" * 50)

        try:
            # Check the producer's manifest before pulling ~1.8GB. A degraded or
            # regressed snapshot is rejected here, at zero bandwidth cost.
            manifest = self.fetch_source_manifest()
            if manifest is not None:
                if accept_baseline:
                    logger.warning("⚠️  --accept-baseline: skipping manifest regression check")
                else:
                    self.verify_manifest_healthy(manifest)
                    self.verify_manifest_not_regressed(manifest, self.fetch_baseline_manifest())
            else:
                logger.warning("⚠️  Proceeding without manifest verification (producer manifest unavailable)")

            # Download data if needed
            data_file = self.download_data(force=force_download, manifest=manifest)

            # Only record the manifest once the object it describes has been
            # downloaded and verified, so the published baseline can never name
            # a snapshot we did not actually accept.
            if manifest is not None:
                self.persist_accepted_manifest(manifest)

            # Download CNA mapping files
            self.download_cna_mapping_files()

            # Validate format
            if not self.validate_json_format(data_file):
                raise ValueError("Downloaded data failed validation")

            # Show statistics
            stats = self.get_data_stats()
            if stats:
                logger.info("\n📊 Data Statistics:")
                logger.info(f"  📅 Downloaded: {stats['cache_info']['download_time']}")
                logger.info(f"  📊 Total CVEs: {stats['total_cves']:,}")
                if stats["year_range"][0]:
                    logger.info(f"  📅 Year range: {stats['year_range'][0]}-{stats['year_range'][1]}")
                    logger.debug(f"  📈 Years covered: {len(stats['year_counts'])}")

            logger.info("\n" + "=" * 50)
            logger.info("✅ CVE data is ready for processing!")

            return data_file

        except (ValueError, requests.RequestException, OSError) as e:
            logger.error(f"\n❌ Failed to ensure data availability: {e}")
            raise

    # ------------------------------------------------------------------
    # EPSS data helpers
    # ------------------------------------------------------------------

    def download_epss_data(self, force: bool = False) -> Path | None:
        """Download and cache the EPSS scores CSV.

        Returns the path to the gzipped CSV file, or None on failure.
        Uses a similar cache duration to the main NVD data so GitHub
        Actions runs don't redownload unnecessarily.
        """

        if self.epss_cache_file.exists() and not force:
            # Basic age check: reuse if within cache_duration
            mtime = datetime.fromtimestamp(self.epss_cache_file.stat().st_mtime)
            if datetime.now() - mtime < self.cache_duration:
                if not self.quiet:
                    logger.info("✅ Using cached EPSS data")
                return self.epss_cache_file

        if not self.quiet:
            logger.info(f"🔽 Downloading EPSS data from {self.epss_url}")

        try:
            response = requests.get(self.epss_url, stream=True, timeout=120)
            response.raise_for_status()

            with open(self.epss_cache_file, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)

            if not self.quiet:
                size_mb = self.epss_cache_file.stat().st_size / (1024 * 1024)
                logger.info(f"✅ EPSS download complete ({size_mb:.2f} MB)")

            return self.epss_cache_file

        except requests.RequestException as e:
            logger.warning(f"⚠️  Warning: EPSS download failed: {e}")
            if self.epss_cache_file.exists():
                logger.warning("  📝 Using stale EPSS cache as fallback")
                return self.epss_cache_file
            return None

    def parse_epss_csv(self) -> Path | None:
        """Parse the cached EPSS CSV into a compact JSON mapping.

        Output format (written to self.epss_parsed_file):

        {
          "CVE-2024-12345": {"epss_score": 0.1234, "epss_percentile": 0.9876},
          ...
        }
        """

        epss_csv_gz = self.download_epss_data()
        if not epss_csv_gz or not epss_csv_gz.exists():
            logger.warning("⚠️  Warning: No EPSS CSV available to parse")
            return None

        if not self.quiet:
            logger.info("🔍 Parsing EPSS CSV into JSON mapping...")

        mapping = {}
        try:
            with gzip.open(epss_csv_gz, mode="rt", encoding="utf-8") as f:
                # Skip comment lines (start with #)
                lines = (line for line in f if not line.startswith("#"))
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

            with open(self.epss_parsed_file, "w", encoding="utf-8") as out:
                json.dump(mapping, out)

            if not self.quiet:
                logger.info(f"✅ EPSS mapping written to {self.epss_parsed_file.name} ({len(mapping):,} CVEs)")

            return self.epss_parsed_file

        except (gzip.BadGzipFile, csv.Error, OSError, json.JSONDecodeError) as e:
            logger.warning(f"⚠️  Warning: Failed to parse EPSS CSV: {e}")
            return None

    # ------------------------------------------------------------------
    # CISA KEV helpers
    # ------------------------------------------------------------------

    def download_kev_data(self, force: bool = False) -> Path | None:
        """Download and cache the CISA Known Exploited Vulnerabilities catalog.

        Returns the path to the JSON file, or None on failure. Best-effort only:
        if download fails but a stale cache exists, we will reuse it.
        """

        if self.kev_cache_file.exists() and not force:
            # Basic age check similar to NVD cache
            mtime = datetime.fromtimestamp(self.kev_cache_file.stat().st_mtime)
            if datetime.now() - mtime < self.cache_duration:
                if not self.quiet:
                    logger.info("✅ Using cached KEV data")
                return self.kev_cache_file

        if not self.quiet:
            logger.info(f"🔽 Downloading KEV data from {self.kev_url}")

        try:
            response = requests.get(self.kev_url, timeout=60)
            response.raise_for_status()

            with open(self.kev_cache_file, "w", encoding="utf-8") as f:
                f.write(response.text)

            if not self.quiet:
                size_kb = self.kev_cache_file.stat().st_size / 1024
                logger.info(f"✅ KEV download complete ({size_kb:.1f} KB)")

            return self.kev_cache_file

        except requests.RequestException as e:
            logger.warning(f"⚠️  Warning: KEV download failed: {e}")
            if self.kev_cache_file.exists():
                logger.warning("  📝 Using stale KEV cache as fallback")
                return self.kev_cache_file
            return None

    def parse_kev_json(self) -> Path | None:
        """Parse the KEV JSON into a compact mapping.

        Expected feed shape (subject to CISA changes):

        {
          "vulnerabilities": [
            { "cveID": "CVE-2024-12345", ... },
            ...
          ]
        }

        We persist a simplified structure for fast lookup:

        {
          "CVE-2024-12345": true,
          ...
        }
        """

        kev_json = self.download_kev_data()
        if not kev_json or not kev_json.exists():
            logger.warning("⚠️  Warning: No KEV JSON available to parse")
            return None

        if not self.quiet:
            logger.info("🔍 Parsing KEV JSON into CVE mapping...")

        try:
            with open(kev_json, encoding="utf-8") as f:
                raw = json.load(f)

            # CISA’s feed wraps the list in a top-level key in most formats
            vulnerabilities = raw.get("vulnerabilities")
            if vulnerabilities is None and isinstance(raw, list):
                vulnerabilities = raw

            mapping = {
                cve_id.strip(): True
                for entry in (vulnerabilities if isinstance(vulnerabilities, list) else [])
                if (cve_id := entry.get("cveID") or entry.get("cveId") or entry.get("cve"))
                and isinstance(cve_id, str)
                and cve_id.startswith("CVE-")
            }

            with open(self.kev_parsed_file, "w", encoding="utf-8") as out:
                json.dump(mapping, out)

            if not self.quiet:
                logger.info(f"✅ KEV mapping written to {self.kev_parsed_file.name} ({len(mapping):,} CVEs)")

            return self.kev_parsed_file

        except (json.JSONDecodeError, KeyError, OSError) as e:
            logger.warning(f"⚠️  Warning: Failed to parse KEV JSON: {e}")
            return None


def main() -> None:
    """Main entry point for standalone execution"""
    import argparse

    from data.logging_config import setup_logging

    parser = argparse.ArgumentParser(description="Download and cache CVE data")
    parser.add_argument("--force", action="store_true", help="Force download even if cache is valid")
    parser.add_argument("--stats", action="store_true", help="Show data statistics only")
    parser.add_argument("--cache-dir", help="Custom cache directory")
    parser.add_argument(
        "--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="INFO", help="Logging level"
    )

    args = parser.parse_args()

    setup_logging(level=args.log_level)

    downloader = CVEDataDownloader(cache_dir=args.cache_dir)

    if args.stats:
        stats = downloader.get_data_stats()
        if stats:
            print(json.dumps(stats, indent=2, default=str))
        else:
            logger.warning("No cached data available")
    else:
        downloader.ensure_data_available(force_download=args.force)


if __name__ == "__main__":
    main()
