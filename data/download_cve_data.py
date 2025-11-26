#!/usr/bin/env python3
"""
CVE Data Download Script
Downloads and caches CVE data from NVD source for processing
Replaces the wget step from GitHub Actions with proper Python error handling
"""

import os
import requests
import json
import gzip
from pathlib import Path
from datetime import datetime, timedelta
import hashlib
import time
import csv

class CVEDataDownloader:
    """Downloads and manages CVE data from NVD source"""
    
    def __init__(self, cache_dir=None, quiet=False):
        self.quiet = quiet
        self.base_dir = Path(__file__).parent
        self.cache_dir = cache_dir or (self.base_dir / 'cache')
        self.cache_dir.mkdir(exist_ok=True)
        
        # Data source configuration
        self.nvd_url = "https://nvd.handsonhacking.org/nvd.json"
        self.cache_file = self.cache_dir / "nvd.json"
        self.cache_info_file = self.cache_dir / "cache_info.json"
        self.cache_duration = timedelta(hours=4)  # Cache for 4 hours to match build schedule
        
        # CNA mapping files for proper name resolution
        self.cna_list_url = "https://raw.githubusercontent.com/CVEProject/cve-website/dev/src/assets/data/CNAsList.json"
        self.cna_name_map_url = "https://www.cve.org/cve-partner-name-map.json"
        self.cna_list_file = self.cache_dir / "cna_list.json"
        self.cna_name_map_file = self.cache_dir / "cna_name_map.json"

        # EPSS data (Exploit Prediction Scoring System)
        # Current snapshot feed documented at https://www.first.org/epss/
        # Note: EPSS moved from cyentia.com to empiricalsecurity.com in late 2025
        self.epss_url = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
        self.epss_cache_file = self.cache_dir / "epss_scores-current.csv.gz"
        self.epss_parsed_file = self.cache_dir / "epss_scores-current.json"

        # CISA Known Exploited Vulnerabilities (KEV) catalog
        # Official catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
        # JSON feed: a list of objects with a cveID field.
        self.kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        self.kev_cache_file = self.cache_dir / "known_exploited_vulnerabilities.json"
        self.kev_parsed_file = self.cache_dir / "known_exploited_vulnerabilities_parsed.json"

        if not self.quiet:
            print(f"🔽 CVE Data Downloader Initialized")
            print(f"📁 Cache directory: {self.cache_dir}")
            print(f"🌐 Data source: {self.nvd_url}")
    
    def is_cache_valid(self):
        """Check if cached data is still valid"""
        if not self.cache_file.exists() or not self.cache_info_file.exists():
            return False
        
        try:
            with open(self.cache_info_file, 'r') as f:
                cache_info = json.load(f)
            
            cache_time = datetime.fromisoformat(cache_info['download_time'])
            if datetime.now() - cache_time > self.cache_duration:
                if not self.quiet:
                    print(f"⏰ Cache expired (older than {self.cache_duration})")
                return False
            
            if not self.quiet:
                print(f"✅ Cache is valid (downloaded {cache_time.strftime('%Y-%m-%d %H:%M:%S')})")
            return True
            
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            if not self.quiet:
                print(f"⚠️  Cache info corrupted: {e}")
            return False
    
    def download_data(self, force=False):
        """Download CVE data from NVD source"""
        if not force and self.is_cache_valid():
            if not self.quiet:
                print("📋 Using cached data")
            return self.cache_file
        
        if not self.quiet:
            print(f"🔽 Downloading CVE data from {self.nvd_url}")
        
        try:
            # Start download with progress tracking
            response = requests.get(self.nvd_url, stream=True)
            response.raise_for_status()
            
            # Get file size for progress tracking
            total_size = int(response.headers.get('content-length', 0))
            downloaded_size = 0
            
            # Download with progress updates
            with open(self.cache_file, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded_size += len(chunk)
                        
                        # Show progress every 10MB
                        if downloaded_size % (10 * 1024 * 1024) == 0 or downloaded_size == total_size:
                            if total_size > 0:
                                progress = (downloaded_size / total_size) * 100
                                print(f"  📥 Downloaded {downloaded_size // (1024*1024)}MB / {total_size // (1024*1024)}MB ({progress:.1f}%)")
            
            # Calculate file hash for integrity check
            file_hash = self.calculate_file_hash(self.cache_file)
            
            # Save cache info
            cache_info = {
                'download_time': datetime.now().isoformat(),
                'file_size': downloaded_size,
                'file_hash': file_hash,
                'source_url': self.nvd_url
            }
            
            with open(self.cache_info_file, 'w') as f:
                json.dump(cache_info, f, indent=2)
            
            print(f"✅ Download completed successfully")
            print(f"📊 File size: {downloaded_size // (1024*1024)}MB")
            print(f"🔐 File hash: {file_hash[:16]}...")
            
            return self.cache_file
            
        except requests.RequestException as e:
            print(f"❌ Download failed: {e}")
            # Try to use cached data if available, even if expired
            if self.cache_file.exists():
                print("⚠️  Using expired cached data as fallback")
                return self.cache_file
            raise
        
        except Exception as e:
            print(f"❌ Unexpected error during download: {e}")
            raise
    
    def download_cna_mapping_files(self):
        """Download CNA mapping files for proper name resolution"""
        print("🔽 Downloading CNA mapping files...")
        
        try:
            # Download CNA list
            print(f"  📥 Downloading CNA list from CVE.org...")
            response = requests.get(self.cna_list_url, timeout=30)
            response.raise_for_status()
            
            with open(self.cna_list_file, 'w', encoding='utf-8') as f:
                json.dump(response.json(), f, indent=2)
            print(f"  ✅ CNA list saved to {self.cna_list_file.name}")
            
            # Download CNA name mapping
            print(f"  📥 Downloading CNA name mapping from CVE.org...")
            response = requests.get(self.cna_name_map_url, timeout=30)
            response.raise_for_status()
            
            with open(self.cna_name_map_file, 'w', encoding='utf-8') as f:
                json.dump(response.json(), f, indent=2)
            print(f"  ✅ CNA name mapping saved to {self.cna_name_map_file.name}")
            
            print("✅ CNA mapping files downloaded successfully")
            
        except requests.RequestException as e:
            print(f"⚠️  Warning: Could not download CNA mapping files: {e}")
            print("  📝 Will use raw sourceIdentifier values as fallback")
        except Exception as e:
            print(f"⚠️  Warning: Unexpected error downloading CNA files: {e}")
    
    def calculate_file_hash(self, file_path):
        """Calculate SHA256 hash of file for integrity checking"""
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    
    def validate_json_format(self, file_path):
        """Validate that the downloaded file contains valid CVE data (JSON array format)"""
        try:
            print("🔍 Validating JSON format...")
            
            with open(file_path, 'r', encoding='utf-8') as f:
                try:
                    # Try to load as JSON array
                    cve_data = json.load(f)
                    
                    if not isinstance(cve_data, list):
                        raise ValueError("Expected JSON array format")
                    
                    total_records = len(cve_data)
                    valid_cve_count = 0
                    
                    print(f"  📊 Found {total_records:,} records in JSON array")
                    
                    # Validate a sample of records
                    sample_size = min(1000, total_records)
                    for i in range(0, total_records, max(1, total_records // sample_size)):
                        if i >= total_records:
                            break
                            
                        record = cve_data[i]
                        if isinstance(record, dict) and 'cve' in record:
                            cve_id = record.get('cve', {}).get('id', '')
                            if cve_id.startswith('CVE-'):
                                valid_cve_count += 1
                    
                    print(f"✅ Validation complete:")
                    print(f"  📊 Total records: {total_records:,}")
                    print(f"  ✅ Valid CVEs (sampled): {valid_cve_count}/{sample_size}")
                    print(f"  📈 Success rate: {(valid_cve_count/sample_size)*100:.1f}%")
                    
                    if valid_cve_count == 0:
                        raise ValueError("No valid CVE records found in downloaded data")
                    
                    return True
                    
                except json.JSONDecodeError as e:
                    print(f"❌ Failed to parse JSON: {e}")
                    return False
            
        except Exception as e:
            print(f"❌ Validation failed: {e}")
            return False
    
    def get_data_stats(self):
        """Get statistics about the cached data (JSON array format)"""
        if not self.cache_file.exists():
            return None
        
        try:
            with open(self.cache_info_file, 'r') as f:
                cache_info = json.load(f)
            
            # Load and process JSON array
            with open(self.cache_file, 'r', encoding='utf-8') as f:
                cve_data_array = json.load(f)
            
            # Quick scan for year distribution
            year_counts = {}
            total_cves = 0
            
            # Sample every 100th record for performance (still gives accurate stats)
            sample_size = max(1, len(cve_data_array) // 100)
            for i in range(0, len(cve_data_array), sample_size):
                try:
                    cve_record = cve_data_array[i]
                    cve_id = cve_record.get('cve', {}).get('id', '')
                    
                    if cve_id.startswith('CVE-'):
                        # Extract year from CVE-YYYY-NNNN format
                        year = int(cve_id.split('-')[1])
                        year_counts[year] = year_counts.get(year, 0) + sample_size
                        total_cves += sample_size
                
                except (KeyError, ValueError, IndexError):
                    continue
            
            # Adjust for sampling
            actual_total = len(cve_data_array)
            
            return {
                'cache_info': cache_info,
                'total_cves': actual_total,
                'year_range': (min(year_counts.keys()), max(year_counts.keys())) if year_counts else (None, None),
                'year_counts': dict(sorted(year_counts.items()))
            }
            
        except Exception as e:
            print(f"⚠️  Could not get data stats: {e}")
            return None
    
    def ensure_data_available(self, force_download=False):
        """Main method to ensure CVE data is available and valid"""
        print("\n🔽 Ensuring CVE data is available...")
        print("=" * 50)
        
        try:
            # Download data if needed
            data_file = self.download_data(force=force_download)
            
            # Download CNA mapping files
            self.download_cna_mapping_files()
            
            # Validate format
            if not self.validate_json_format(data_file):
                raise ValueError("Downloaded data failed validation")
            
            # Show statistics
            stats = self.get_data_stats()
            if stats:
                print(f"\n📊 Data Statistics:")
                print(f"  📅 Downloaded: {stats['cache_info']['download_time']}")
                print(f"  📊 Total CVEs: {stats['total_cves']:,}")
                if stats['year_range'][0]:
                    print(f"  📅 Year range: {stats['year_range'][0]}-{stats['year_range'][1]}")
                    print(f"  📈 Years covered: {len(stats['year_counts'])}")
            
            print("\n" + "=" * 50)
            print("✅ CVE data is ready for processing!")
            
            return data_file
            
        except Exception as e:
            print(f"\n❌ Failed to ensure data availability: {e}")
            raise

    # ------------------------------------------------------------------
    # EPSS data helpers
    # ------------------------------------------------------------------

    def download_epss_data(self, force: bool = False):
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
                    print("✅ Using cached EPSS data")
                return self.epss_cache_file

        if not self.quiet:
            print(f"🔽 Downloading EPSS data from {self.epss_url}")

        try:
            response = requests.get(self.epss_url, stream=True, timeout=120)
            response.raise_for_status()

            with open(self.epss_cache_file, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)

            if not self.quiet:
                size_mb = self.epss_cache_file.stat().st_size / (1024 * 1024)
                print(f"✅ EPSS download complete ({size_mb:.2f} MB)")

            return self.epss_cache_file

        except requests.RequestException as e:
            print(f"⚠️  Warning: EPSS download failed: {e}")
            if self.epss_cache_file.exists():
                print("  📝 Using stale EPSS cache as fallback")
                return self.epss_cache_file
            return None

    def parse_epss_csv(self):
        """Parse the cached EPSS CSV into a compact JSON mapping.

        Output format (written to self.epss_parsed_file):

        {
          "CVE-2024-12345": {"epss_score": 0.1234, "epss_percentile": 0.9876},
          ...
        }
        """

        epss_csv_gz = self.download_epss_data()
        if not epss_csv_gz or not epss_csv_gz.exists():
            print("⚠️  Warning: No EPSS CSV available to parse")
            return None

        if not self.quiet:
            print("🔍 Parsing EPSS CSV into JSON mapping...")

        mapping = {}
        try:
            with gzip.open(epss_csv_gz, mode="rt", encoding="utf-8") as f:
                # Skip comment lines (start with #)
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

            with open(self.epss_parsed_file, "w", encoding="utf-8") as out:
                json.dump(mapping, out)

            if not self.quiet:
                print(f"✅ EPSS mapping written to {self.epss_parsed_file.name} ({len(mapping):,} CVEs)")

            return self.epss_parsed_file

        except Exception as e:
            print(f"⚠️  Warning: Failed to parse EPSS CSV: {e}")
            return None

    # ------------------------------------------------------------------
    # CISA KEV helpers
    # ------------------------------------------------------------------

    def download_kev_data(self, force: bool = False):
        """Download and cache the CISA Known Exploited Vulnerabilities catalog.

        Returns the path to the JSON file, or None on failure. Best-effort only:
        if download fails but a stale cache exists, we will reuse it.
        """

        if self.kev_cache_file.exists() and not force:
            # Basic age check similar to NVD cache
            mtime = datetime.fromtimestamp(self.kev_cache_file.stat().st_mtime)
            if datetime.now() - mtime < self.cache_duration:
                if not self.quiet:
                    print("✅ Using cached KEV data")
                return self.kev_cache_file

        if not self.quiet:
            print(f"🔽 Downloading KEV data from {self.kev_url}")

        try:
            response = requests.get(self.kev_url, timeout=60)
            response.raise_for_status()

            with open(self.kev_cache_file, "w", encoding="utf-8") as f:
                f.write(response.text)

            if not self.quiet:
                size_kb = self.kev_cache_file.stat().st_size / 1024
                print(f"✅ KEV download complete ({size_kb:.1f} KB)")

            return self.kev_cache_file

        except requests.RequestException as e:
            print(f"⚠️  Warning: KEV download failed: {e}")
            if self.kev_cache_file.exists():
                print("  📝 Using stale KEV cache as fallback")
                return self.kev_cache_file
            return None

    def parse_kev_json(self):
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
            print("⚠️  Warning: No KEV JSON available to parse")
            return None

        if not self.quiet:
            print("🔍 Parsing KEV JSON into CVE mapping...")

        try:
            with open(kev_json, "r", encoding="utf-8") as f:
                raw = json.load(f)

            # CISA’s feed wraps the list in a top-level key in most formats
            vulnerabilities = raw.get("vulnerabilities")
            if vulnerabilities is None and isinstance(raw, list):
                vulnerabilities = raw

            mapping = {}
            if isinstance(vulnerabilities, list):
                for entry in vulnerabilities:
                    cve_id = entry.get("cveID") or entry.get("cveId") or entry.get("cve")
                    if isinstance(cve_id, str) and cve_id.startswith("CVE-"):
                        mapping[cve_id.strip()] = True

            with open(self.kev_parsed_file, "w", encoding="utf-8") as out:
                json.dump(mapping, out)

            if not self.quiet:
                print(f"✅ KEV mapping written to {self.kev_parsed_file.name} ({len(mapping):,} CVEs)")

            return self.kev_parsed_file

        except Exception as e:
            print(f"⚠️  Warning: Failed to parse KEV JSON: {e}")
            return None

def main():
    """Main entry point for standalone execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Download and cache CVE data")
    parser.add_argument('--force', action='store_true', help='Force download even if cache is valid')
    parser.add_argument('--stats', action='store_true', help='Show data statistics only')
    parser.add_argument('--cache-dir', help='Custom cache directory')
    
    args = parser.parse_args()
    
    downloader = CVEDataDownloader(cache_dir=args.cache_dir)
    
    if args.stats:
        stats = downloader.get_data_stats()
        if stats:
            print(json.dumps(stats, indent=2, default=str))
        else:
            print("No cached data available")
    else:
        downloader.ensure_data_available(force_download=args.force)

if __name__ == '__main__':
    main()
