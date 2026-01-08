#!/usr/bin/env python3
"""
CVE V5 Processor Module
Handles CVE V5 list data processing as the single source of truth for CNA analysis
"""
from __future__ import annotations

import json
import subprocess
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from typing import Any

from download_cve_data import CVEDataDownloader

try:
    from data.logging_config import get_logger
except ImportError:
    from logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class CVEV5Processor:
    """Processes CVE V5 list data for authoritative CNA analysis"""
    base_dir: Path
    cache_dir: Path
    data_dir: Path
    quiet: bool = False
    current_year: int = field(default_factory=lambda: datetime.now().year)
    v5_cache_dir: Path = field(init=False)
    epss_mapping: dict[str, dict[str, float]] = field(default_factory=dict, init=False)
    kev_cve_set: set[str] = field(default_factory=set, init=False)
    
    def __post_init__(self) -> None:
        """Convert paths and load threat intelligence data."""
        self.base_dir = Path(self.base_dir)
        self.cache_dir = Path(self.cache_dir)
        self.data_dir = Path(self.data_dir)
        self.v5_cache_dir = self.cache_dir / 'cvelistV5'
        # Load threat intelligence data
        self._load_epss_mapping()
        self._load_kev_set()

    def _load_epss_mapping(self) -> None:
        """Load EPSS mapping from cache if available.

        Uses the same cache directory as CVEDataDownloader to avoid
        duplicate downloads. If EPSS data is unavailable or parsing
        fails, this method leaves epss_mapping empty and continues
        silently so that CNA analysis is not blocked.
        """
        try:
            downloader = CVEDataDownloader(cache_dir=self.cache_dir, quiet=True)
            epss_json_path = downloader.epss_parsed_file
            # If parsed file does not exist yet, attempt to parse from CSV
            if not epss_json_path.exists():
                epss_json_path = downloader.parse_epss_csv()

            if epss_json_path and Path(epss_json_path).exists():
                with open(epss_json_path, 'r', encoding='utf-8') as f:
                    self.epss_mapping = json.load(f)
                if not self.quiet:
                    logger.info(f"  ✅ Loaded EPSS mapping for {len(self.epss_mapping):,} CVEs")
            else:
                if not self.quiet:
                    logger.warning("  ⚠️  EPSS mapping not available; proceeding without enrichment")
        except (FileNotFoundError, json.JSONDecodeError, OSError) as e:
            if not self.quiet:
                logger.warning(f"  ⚠️  Could not load EPSS mapping: {e}")
            self.epss_mapping = {}

    def _load_kev_set(self) -> None:
        """Load KEV CVE IDs into a set for fast lookup"""
        kev_file = self.cache_dir / 'known_exploited_vulnerabilities_parsed.json'
        if kev_file.exists():
            try:
                with open(kev_file, 'r') as f:
                    kev_data = json.load(f)
                self.kev_cve_set = set(kev_data.keys())
                if not self.quiet:
                    logger.info(f"  ✅ Loaded KEV set with {len(self.kev_cve_set):,} CVEs")
            except (FileNotFoundError, json.JSONDecodeError, OSError) as e:
                if not self.quiet:
                    logger.warning(f"  ⚠️  Could not load KEV data: {e}")
                self.kev_cve_set = set()
        else:
            if not self.quiet:
                logger.warning("  ⚠️  KEV data not available; proceeding without KEV enrichment")

        # CNA type classification patterns
        self.cna_type_patterns = {
            'Vendor': [
                'microsoft', 'apple', 'google', 'oracle', 'cisco', 'adobe', 'ibm',
                'redhat', 'canonical', 'suse', 'debian', 'ubuntu', 'mozilla',
                'vmware', 'intel', 'amd', 'nvidia', 'qualcomm', 'samsung',
                'huawei', 'lenovo', 'hp', 'dell', 'netapp', 'citrix'
            ],
            'Security Researcher': [
                'patchstack', 'wordfence', 'vuldb', 'zerodayinitiative', 'trendmicro',
                'rapid7', 'tenable', 'qualys', 'checkmarx', 'veracode'
            ],
            'CERT': [
                'cert', 'cisa', 'ncsc', 'jpcert', 'kr-cert', 'au-cert',
                'ca-cert', 'de-cert', 'fr-cert', 'nl-cert'
            ],
            'Government': [
                'cisa', 'nist', 'dhs', 'gov', 'mil', 'defense',
                'homeland', 'treasury', 'energy', 'state'
            ],
            'Academic': [
                'edu', 'university', 'college', 'research', 'institute',
                'academic', 'school', 'campus'
            ],
            'Open Source': [
                'github', 'gitlab', 'apache', 'eclipse', 'linux', 'kernel',
                'gnu', 'fsf', 'oss', 'opensource'
            ]
        }
        
    def clone_or_update_cve_v5_repo(self) -> bool:
        """Clone or update the CVE V5 repository with shallow clone"""
        logger.info(f"  📥 Setting up CVE V5 repository...")
        
        if self.v5_cache_dir.exists():
            # Check if it's a valid git repository
            git_dir = self.v5_cache_dir / '.git'
            if not git_dir.exists():
                logger.warning(f"    ⚠️ Invalid git repository, re-cloning...")
                shutil.rmtree(self.v5_cache_dir)
                return self._clone_fresh_repo()
            
            logger.info(f"    🔄 Updating existing CVE V5 repository...")
            try:
                # First try a simple git pull (no --depth flag for existing repos)
                result = subprocess.run(
                    ['git', 'pull', 'origin', 'main'],
                    cwd=self.v5_cache_dir,
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                if result.returncode == 0:
                    logger.info(f"    ✅ Successfully updated CVE V5 repository")
                    return True
                else:
                    # Try to reset and pull if there are conflicts
                    logger.info(f"    🔄 Pull failed, trying reset and pull...")
                    reset_result = subprocess.run(
                        ['git', 'reset', '--hard', 'origin/main'],
                        cwd=self.v5_cache_dir,
                        capture_output=True,
                        text=True,
                        timeout=60
                    )
                    if reset_result.returncode == 0:
                        pull_result = subprocess.run(
                            ['git', 'pull', 'origin', 'main'],
                            cwd=self.v5_cache_dir,
                            capture_output=True,
                            text=True,
                            timeout=300
                        )
                        if pull_result.returncode == 0:
                            logger.info(f"    ✅ Successfully updated CVE V5 repository after reset")
                            return True
                    
                    # Only re-clone as last resort
                    logger.warning(f"    ⚠️ All update attempts failed, re-cloning as last resort...")
                    logger.debug(f"    📝 Git pull error: {result.stderr}")
                    shutil.rmtree(self.v5_cache_dir)
                    return self._clone_fresh_repo()
                    
            except subprocess.TimeoutExpired:
                logger.warning(f"    ⏰ Git pull timed out, repository may be up to date")
                return True  # Don't re-clone on timeout, assume it's working
            except (subprocess.SubprocessError, OSError) as e:
                logger.warning(f"    ⚠️ Update failed with exception: {e}")
                # Only re-clone if it's a critical error
                if "not a git repository" in str(e).lower():
                    shutil.rmtree(self.v5_cache_dir)
                    return self._clone_fresh_repo()
                else:
                    logger.debug(f"    📝 Assuming repository is usable despite error")
                    return True
        else:
            return self._clone_fresh_repo()
    
    def _clone_fresh_repo(self) -> bool:
        """Clone fresh CVE V5 repository"""
        logger.info(f"    📦 Cloning CVE V5 repository (shallow clone)...")
        try:
            # Ensure cache directory exists
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            
            # Shallow clone with depth=1 to minimize data transfer
            result = subprocess.run([
                'git', 'clone', 
                '--depth=1',
                '--single-branch',
                'https://github.com/CVEProject/cvelistV5.git',
                str(self.v5_cache_dir)
            ], capture_output=True, text=True, timeout=600)
            
            if result.returncode == 0:
                logger.info(f"    ✅ Successfully cloned CVE V5 repository")
                return True
            else:
                logger.error(f"    ❌ Failed to clone CVE V5 repository: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.error(f"    ❌ Clone operation timed out")
            return False
        except (subprocess.SubprocessError, OSError) as e:
            logger.error(f"    ❌ Clone failed: {e}")
            return False
    
    def get_repo_stats(self) -> dict[str, Any] | None:
        """Get basic statistics about the cloned repository"""
        if not self.v5_cache_dir.exists():
            return None
            
        cves_dir = self.v5_cache_dir / 'cves'
        if not cves_dir.exists():
            return None
            
        stats = {
            'total_years': 0,
            'total_cves': 0,
            'years_available': []
        }
        
        for year_dir in sorted(cves_dir.iterdir()):
            if year_dir.is_dir() and year_dir.name.isdigit():
                year = int(year_dir.name)
                stats['years_available'].append(year)
                stats['total_years'] += 1
                
                # Count CVE files in this year (handle nested structure)
                year_cve_count = 0
                for subdir in year_dir.iterdir():
                    if subdir.is_dir():
                        cve_files = list(subdir.glob('CVE-*.json'))
                        year_cve_count += len(cve_files)
                stats['total_cves'] += year_cve_count
        
        return stats
    
    def classify_cna_type(self, org_id: str, short_name: str) -> list[str]:
        """Classify CNA type based on organization ID and short name"""
        # Combine org_id and short_name for pattern matching
        search_text = f"{org_id} {short_name}".lower()
        
        # Special cases first
        if 'mitre' in search_text:
            return ['Program']  # MITRE is the CVE Program
        
        # Check patterns for each type
        matched_types = []
        for cna_type, patterns in self.cna_type_patterns.items():
            for pattern in patterns:
                if pattern in search_text:
                    matched_types.append(cna_type)
                    break  # Only add each type once
        
        # If no specific type matched, use comprehensive inference patterns
        if not matched_types:
            # Academic institutions
            if any(domain in search_text for domain in ['.edu', 'university', 'college', 'institut', 'research', 'academic', 'school']):
                matched_types.append('Academic')
            # Government and military
            elif any(gov in search_text for gov in ['.gov', '.mil', 'government', 'cisa', 'nist', 'dhs', 'defense', 'homeland']):
                matched_types.append('Government')
            # CERT and security organizations
            elif any(cert in search_text for cert in ['cert', 'csirt', 'security', 'cyber']):
                matched_types.append('CERT')
            # Open source projects and repositories
            elif any(oss in search_text for oss in ['github', 'gitlab', 'apache', 'linux', 'kernel', 'gnu', 'eclipse', 'mozilla', 'debian', 'ubuntu', 'redhat', 'canonical', 'suse']):
                matched_types.append('Open Source')
            # Security researchers and vulnerability research
            elif any(sec in search_text for sec in ['vulnerability', 'exploit', 'security', 'research', 'bug', 'bounty', 'pentest', 'audit']):
                matched_types.append('Security Researcher')
            # Technology vendors (broad patterns)
            elif any(vendor in search_text for vendor in ['corp', 'inc', 'ltd', 'llc', 'gmbh', 'co', 'company', 'tech', 'software', 'systems', 'solutions', 'technologies']):
                matched_types.append('Vendor')
            # Email domain-based classification
            elif '@' in search_text:
                domain = search_text.split('@')[-1] if '@' in search_text else ''
                if '.edu' in domain or 'university' in domain:
                    matched_types.append('Academic')
                elif '.gov' in domain or '.mil' in domain:
                    matched_types.append('Government')
                elif any(tech in domain for tech in ['.com', '.org', '.net', 'tech', 'software', 'systems']):
                    matched_types.append('Vendor')
                else:
                    matched_types.append('Other')
            else:
                # Final fallback - assume most are vendors/organizations
                matched_types.append('Vendor')
        
        return matched_types if matched_types else ['Vendor']
    
    def calculate_enhanced_statistics(self, cna_list: list[dict[str, Any]]) -> dict[str, Any]:
        """Calculate enhanced statistics for CNA analysis"""
        if not cna_list:
            return {}
        
        total_cves = sum(cna['count'] for cna in cna_list)
        total_cnas = len(cna_list)
        
        # Market concentration (top 5 CNAs)
        top_5_cves = sum(cna['count'] for cna in cna_list[:5])
        market_concentration = (top_5_cves / total_cves * 100) if total_cves > 0 else 0
        
        # High volume CNAs (1000+ CVEs)
        high_volume_cnas = len([cna for cna in cna_list if cna['count'] >= 1000])
        
        # Activity statistics
        active_cnas = len([cna for cna in cna_list if cna['activity_status'] == 'Active'])
        inactive_cnas = total_cnas - active_cnas
        
        # Years active statistics
        years_active_list = [cna['years_active'] for cna in cna_list if cna.get('years_active', 0) > 0]
        median_years_active = 0
        if years_active_list:
            years_active_list.sort()
            n = len(years_active_list)
            median_years_active = years_active_list[n // 2] if n % 2 == 1 else (years_active_list[n // 2 - 1] + years_active_list[n // 2]) / 2
        
        # Type distribution
        type_counts = defaultdict(int)
        for cna in cna_list:
            cna_types = cna.get('cna_types', ['Other'])
            for cna_type in cna_types:
                type_counts[cna_type] += 1
        
        # Convert to format expected by JavaScript using comprehensions
        # JavaScript expects: type_distribution.sorted_types and type_distribution.type_percentages
        sorted_type_items = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)
        
        # List comprehension for sorted_types (JavaScript expects [type, count] pairs)
        sorted_types = [[cna_type, count] for cna_type, count in sorted_type_items]
        
        # Dict comprehension for type_percentages
        type_percentages = {
            cna_type: round((count / total_cnas * 100), 1) if total_cnas > 0 else 0
            for cna_type, count in sorted_type_items
        }
        
        # Create the structure expected by JavaScript
        type_distribution = {
            'sorted_types': sorted_types,
            'type_percentages': type_percentages
        }
        
        return {
            'total_cves': total_cves,
            'total_cnas': total_cnas,
            'active_cnas': active_cnas,
            'inactive_cnas': inactive_cnas,
            'high_volume_cnas': high_volume_cnas,
            'market_concentration': round(market_concentration, 1),
            'median_years_active': round(median_years_active, 1),
            'type_distribution': type_distribution
        }
    
    def parse_cve_v5_record(self, cve_file_path):
        """Parse a single CVE V5 record and extract CNA information"""
        try:
            with open(cve_file_path, 'r', encoding='utf-8') as f:
                cve_data = json.load(f)
            
            # Extract CVE metadata
            cve_metadata = cve_data.get('cveMetadata', {})
            cve_id = cve_metadata.get('cveId', '')
            state = cve_metadata.get('state', '')
            
            # Skip REJECTED CVEs - they don't represent valid vulnerabilities
            if state == 'REJECTED':
                return None
            
            # Extract CNA information from V5 format
            assigner_org_id = cve_metadata.get('assignerOrgId', '')
            assigner_short_name = cve_metadata.get('assignerShortName', '')
            
            # Extract publication date
            date_published = cve_metadata.get('datePublished', '')
            date_updated = cve_metadata.get('dateUpdated', '')
            
            # Use publication date for accurate CNA activity tracking
            # (date_updated reflects record modifications, not actual CVE assignment)
            pub_date = date_published if date_published else date_updated
            
            record = {
                'cve_id': cve_id,
                'assigner_org_id': assigner_org_id,
                'assigner_short_name': assigner_short_name,
                'date_published': date_published,
                'date_updated': date_updated,
                'publication_date': pub_date,
                'year': int(cve_id.split('-')[1]) if cve_id.startswith('CVE-') else None
            }

            # Attach EPSS enrichment if available
            if cve_id and self.epss_mapping:
                epss = self.epss_mapping.get(cve_id)
                if epss:
                    record['epss_score'] = epss.get('epss_score')
                    record['epss_percentile'] = epss.get('epss_percentile')

            return record
            
        except (json.JSONDecodeError, KeyError, ValueError, OSError) as e:
            logger.warning(f"    ⚠️ Error parsing {cve_file_path}: {e}")
            return None
    
    def process_all_cves_single_pass(self):
        """Process ALL CVE records in a single pass, tracking by publication year.
        
        This is more efficient than processing year-by-year since:
        1. CVE folder year (e.g., cves/2024/) is the CVE ID year, not publication year
        2. A CVE-2024-XXXX might be published in 2025
        3. Single pass = read each file once instead of multiple times
        """
        print(f"  📊 Processing all CVE files in single pass...")
        
        # Initialize CNA stats with publication year tracking
        all_cna_stats = defaultdict(lambda: {
            'count': 0,
            'cves': [],
            'first_date': None,
            'last_date': None,
            'first_year': None,
            'last_year': None,
            'assigner_org_id': '',
            'assigner_short_name': '',
            'cves_by_pub_year': defaultdict(int),  # Keyed by PUBLICATION year
            'kev_count': 0,
            'epss_high_count': 0,
            'epss_elevated_count': 0,
            'cwe_counts': defaultdict(int)
        })
        
        # Collect all CVE files from all year directories
        cves_dir = self.v5_cache_dir / 'cves'
        all_cve_files = []
        
        for year_dir in sorted(cves_dir.iterdir()):
            if year_dir.is_dir() and year_dir.name.isdigit():
                for subdir in year_dir.iterdir():
                    if subdir.is_dir():
                        all_cve_files.extend(subdir.glob('CVE-*.json'))
        
        total_files = len(all_cve_files)
        print(f"  📊 Found {total_files} total CVE files to process")
        
        processed = 0
        for cve_file in all_cve_files:
            cve_record = self.parse_cve_v5_record(cve_file)
            if cve_record and cve_record['assigner_org_id']:
                org_id = cve_record['assigner_org_id']
                cve_id = cve_record['cve_id']
                pub_date = cve_record['publication_date']
                
                # Extract publication year from the date
                pub_year = None
                if pub_date:
                    try:
                        pub_year = datetime.fromisoformat(pub_date.replace('Z', '+00:00')).year
                    except:
                        pass
                
                # Update CNA statistics
                all_cna_stats[org_id]['count'] += 1
                all_cna_stats[org_id]['cves'].append(cve_id)
                all_cna_stats[org_id]['assigner_org_id'] = org_id
                all_cna_stats[org_id]['assigner_short_name'] = cve_record['assigner_short_name']
                
                # Track by PUBLICATION year (not CVE ID year)
                if pub_year:
                    all_cna_stats[org_id]['cves_by_pub_year'][pub_year] += 1
                
                # Track date ranges
                if pub_date:
                    if not all_cna_stats[org_id]['first_date'] or pub_date < all_cna_stats[org_id]['first_date']:
                        all_cna_stats[org_id]['first_date'] = pub_date
                        all_cna_stats[org_id]['first_year'] = pub_year
                    if not all_cna_stats[org_id]['last_date'] or pub_date > all_cna_stats[org_id]['last_date']:
                        all_cna_stats[org_id]['last_date'] = pub_date
                        all_cna_stats[org_id]['last_year'] = pub_year
                
                # Track KEV membership inline
                if cve_id in self.kev_cve_set:
                    all_cna_stats[org_id]['kev_count'] += 1
                
                # Track EPSS scores inline
                if cve_id in self.epss_mapping:
                    epss_score = self.epss_mapping[cve_id].get('epss_score', 0)
                    if epss_score > 0.5:
                        all_cna_stats[org_id]['epss_high_count'] += 1
                    if epss_score > 0.1:
                        all_cna_stats[org_id]['epss_elevated_count'] += 1
            
            processed += 1
            if processed % 10000 == 0:
                print(f"    📈 Processed {processed}/{total_files} files...")
        
        print(f"  ✅ Processed {processed} CVE files, found {len(all_cna_stats)} unique CNAs")
        return dict(all_cna_stats)

    def process_year_data(self, year):
        """Process all CVE records for a specific year"""
        logger.info(f"    📅 Processing CVE data for year {year}...")
        
        year_dir = self.v5_cache_dir / 'cves' / str(year)
        if not year_dir.exists():
            logger.warning(f"    ⚠️ No data found for year {year}")
            return {}
        
        cna_stats = defaultdict(lambda: {
            'count': 0,
            'cves': [],
            'first_date': None,
            'last_date': None,
            'assigner_org_id': '',
            'assigner_short_name': ''
        })
        
        # CVE V5 has nested directory structure (0xxx, 1xxx, etc.)
        cve_files = []
        for subdir in year_dir.iterdir():
            if subdir.is_dir():
                cve_files.extend(subdir.glob('CVE-*.json'))
        
        total_files = len(cve_files)
        processed = 0
        
        if not self.quiet:
            logger.info(f"    📊 Found {total_files} CVE files for {year}")
        
        for cve_file in cve_files:
            cve_record = self.parse_cve_v5_record(cve_file)
            if cve_record and cve_record['assigner_org_id']:
                org_id = cve_record['assigner_org_id']
                
                # Update CNA statistics
                cna_stats[org_id]['count'] += 1
                cna_stats[org_id]['cves'].append(cve_record['cve_id'])
                cna_stats[org_id]['assigner_org_id'] = org_id
                cna_stats[org_id]['assigner_short_name'] = cve_record['assigner_short_name']
                
                # Track date ranges
                pub_date = cve_record['publication_date']
                if pub_date:
                    if not cna_stats[org_id]['first_date'] or pub_date < cna_stats[org_id]['first_date']:
                        cna_stats[org_id]['first_date'] = pub_date
                    if not cna_stats[org_id]['last_date'] or pub_date > cna_stats[org_id]['last_date']:
                        cna_stats[org_id]['last_date'] = pub_date
            
            processed += 1
            if processed % 1000 == 0 and not self.quiet:
                logger.debug(f"    📈 Processed {processed}/{total_files} files...")
        
        if not self.quiet:
            logger.info(f"    ✅ Processed {processed} CVE files, found {len(cna_stats)} CNAs for {year}")
        return dict(cna_stats)
    
    def generate_comprehensive_cna_analysis(self) -> dict[str, Any] | None:
        """Generate comprehensive CNA analysis using CVE V5 data as single source of truth"""
        logger.info(f"  🏢 Generating comprehensive CNA analysis from CVE V5 data...")
        
        # Ensure we have the latest CVE V5 data
        if not self.clone_or_update_cve_v5_repo():
            logger.error(f"  ❌ Failed to setup CVE V5 repository")
            return None
        
        # Get repository statistics
        repo_stats = self.get_repo_stats()
        if not repo_stats:
            logger.error(f"  ❌ Failed to get repository statistics")
            return None
            
        print(f"  📊 Repository contains {repo_stats['total_cves']} CVEs across {repo_stats['total_years']} years")
        
        # Use single-pass processing (reads each file once, tracks by publication year)
        all_cna_stats = self.process_all_cves_single_pass()
        
        # Convert to final format
        cna_list = []
        total_cnas = len(all_cna_stats)
        print(f"  📊 Building CNA list from {total_cnas} CNAs...")
        processed_cnas = 0
        for org_id, stats in all_cna_stats.items():
            processed_cnas += 1
            if processed_cnas % 50 == 0:
                print(f"    📈 Processing CNA {processed_cnas}/{total_cnas}...")
            # Calculate years active using publication dates
            years_active_count = 1
            first_pub_year = None
            last_pub_year = None
            if stats['first_date']:
                try:
                    first_pub_year = datetime.fromisoformat(stats['first_date'].replace('Z', '+00:00')).year
                except (ValueError, TypeError):
                    pass
            if stats['last_date']:
                try:
                    last_pub_year = datetime.fromisoformat(stats['last_date'].replace('Z', '+00:00')).year
                except (ValueError, TypeError):
                    pass
            if first_pub_year and last_pub_year:
                years_active_count = max(1, last_pub_year - first_pub_year + 1)

            # Calculate days since last CVE
            days_since_last = 365  # Default to inactive
            if stats['last_date']:
                try:
                    last_date = datetime.fromisoformat(stats['last_date'].replace('Z', '+00:00'))
                    days_since_last = (datetime.now(last_date.tzinfo) - last_date).days
                except (ValueError, TypeError):
                    days_since_last = 365

            # Determine activity status
            activity_status = 'Active' if days_since_last < 365 else 'Inactive'

            # Classify CNA type
            cna_types = self.classify_cna_type(org_id, stats['assigner_short_name'])

            # KEV and EPSS are already tracked inline during single-pass processing
            kev_count = stats.get('kev_count', 0)
            epss_high_count = stats.get('epss_high_count', 0)
            epss_elevated_count = stats.get('epss_elevated_count', 0)

            # Severity and CWE aggregation is expensive - use simpler approach
            severity_distribution = {}
            top_cwe_types = {}
            
            cna_entry = {
                'name': stats['assigner_short_name'] or org_id,
                'assigner_org_id': org_id,
                'count': stats['count'],
                'years_active': years_active_count,
                'first_cve_year': first_pub_year,
                'last_cve_year': last_pub_year,
                'first_cve_date': stats['first_date'],
                'last_cve_date': stats['last_date'],
                'days_since_last_cve': days_since_last,
                'activity_status': activity_status,
                'is_official': True,  # All CVE V5 records are from official CNAs
                'cna_types': cna_types,  # Add CNA type classification
                'cves_by_year': dict(stats.get('cves_by_pub_year', {})),  # Use publication year
                'years_active_list': [first_pub_year, last_pub_year] if first_pub_year and last_pub_year else [],
                # Add placeholder fields for compatibility
                'severity_distribution': severity_distribution,
                'top_cwe_types': top_cwe_types,
                # Threat intelligence metrics
                'kev_count': kev_count,
                'epss_high_count': epss_high_count,
                'epss_elevated_count': epss_elevated_count,
                'top_cwes': list(top_cwe_types.items())[:5]  # For template compatibility
            }
            cna_list.append(cna_entry)
        
        # Sort by CVE count (descending)
        cna_list.sort(key=lambda x: x['count'], reverse=True)
        
        # Add ranks
        for i, cna in enumerate(cna_list):
            cna['rank'] = i + 1
        
        # Calculate enhanced statistics
        enhanced_stats = self.calculate_enhanced_statistics(cna_list)
        
        # Calculate actual published CVE count (sum of all CNA counts, excludes REJECTED)
        total_published_cves = sum(cna['count'] for cna in cna_list)
        
        # Update repo_stats with published count (not raw file count)
        repo_stats['total_cves'] = total_published_cves
        
        # Create comprehensive analysis data structure
        comprehensive_data = {
            'generated_at': datetime.now().isoformat(),
            'source': 'CVE V5 List (Authoritative)',
            'repository_stats': repo_stats,
            'total_cnas': enhanced_stats.get('total_cnas', len(cna_list)),
            'active_cnas': enhanced_stats.get('active_cnas', 0),
            'inactive_cnas': enhanced_stats.get('inactive_cnas', 0),
            'official_cnas': enhanced_stats.get('total_cnas', len(cna_list)),  # All are official in V5 data
            'unofficial_cnas': 0,  # None are unofficial in V5 data
            'high_volume_cnas': enhanced_stats.get('high_volume_cnas', 0),
            'market_concentration': enhanced_stats.get('market_concentration', 0),
            'median_years_active': enhanced_stats.get('median_years_active', 0),
            'type_distribution': enhanced_stats.get('type_distribution', []),
            'cna_list': cna_list,
            'cna_assigners': cna_list  # For backward compatibility
        }
        
        # Save comprehensive analysis
        output_file = self.data_dir / 'cna_analysis.json'
        with open(output_file, 'w') as f:
            json.dump(comprehensive_data, f, indent=2)
        
        logger.info(f"  📄 Generated comprehensive CNA analysis with {len(cna_list)} CNAs")
        logger.info(f"  📊 Active: {enhanced_stats.get('active_cnas', 0)}, Inactive: {enhanced_stats.get('inactive_cnas', 0)}")
        
        return comprehensive_data
    
    def process_current_year_by_publication_date(self) -> dict[str, dict[str, Any]]:
        """Process CVEs from ALL years, filtering by current year publication date"""
        logger.info(f"    🔍 Scanning all CVE years for {self.current_year} publications...")
        
        cves_dir = self.v5_cache_dir / 'cves'
        if not cves_dir.exists():
            logger.error(f"    ❌ CVEs directory not found")
            return {}
        
        cna_stats = defaultdict(lambda: {
            'count': 0,
            'cves': [],
            'first_date': None,
            'last_date': None,
            'assigner_org_id': '',
            'assigner_short_name': ''
        })
        
        total_processed = 0
        current_year_cves = 0
        
        # Scan all year directories
        for year_dir in sorted(cves_dir.iterdir()):
            if not year_dir.is_dir() or not year_dir.name.isdigit():
                continue
                
            year = int(year_dir.name)
            if not self.quiet:
                logger.debug(f"    📂 Scanning CVE-{year}-* files for {self.current_year} publications...")
            
            # Get all CVE files in this year directory (handle nested structure)
            cve_files = []
            for subdir in year_dir.iterdir():
                if subdir.is_dir():
                    cve_files.extend(subdir.glob('CVE-*.json'))
            
            year_current_cves = 0
            for cve_file in cve_files:
                cve_record = self.parse_cve_v5_record(cve_file)
                if cve_record and cve_record['assigner_org_id']:
                    # Check if this CVE was published in the current year
                    pub_date = cve_record['publication_date']
                    if pub_date:
                        try:
                            pub_year = datetime.fromisoformat(pub_date.replace('Z', '+00:00')).year
                            if pub_year == self.current_year:
                                # This CVE was published in current year
                                org_id = cve_record['assigner_org_id']
                                
                                # Update CNA statistics
                                cna_stats[org_id]['count'] += 1
                                cna_stats[org_id]['cves'].append(cve_record['cve_id'])
                                cna_stats[org_id]['assigner_org_id'] = org_id
                                cna_stats[org_id]['assigner_short_name'] = cve_record['assigner_short_name']
                                
                                # Track date ranges
                                if not cna_stats[org_id]['first_date'] or pub_date < cna_stats[org_id]['first_date']:
                                    cna_stats[org_id]['first_date'] = pub_date
                                if not cna_stats[org_id]['last_date'] or pub_date > cna_stats[org_id]['last_date']:
                                    cna_stats[org_id]['last_date'] = pub_date
                                
                                year_current_cves += 1
                                current_year_cves += 1
                        except (ValueError, TypeError):
                            # Skip CVEs with invalid dates
                            pass
                
                total_processed += 1
                if total_processed % 5000 == 0 and not self.quiet:
                    logger.debug(f"    📈 Processed {total_processed} files, found {current_year_cves} {self.current_year} publications...")
            
            if year_current_cves > 0 and not self.quiet:
                logger.debug(f"    ✅ Found {year_current_cves} CVEs published in {self.current_year} from CVE-{year}-* files")
        
        if not self.quiet:
            logger.info(f"    🎯 Total: {current_year_cves} CVEs published in {self.current_year}, from {len(cna_stats)} CNAs")
        return dict(cna_stats)
    
    def generate_current_year_analysis(self) -> dict[str, Any] | None:
        """Generate current year CNA analysis from CVE V5 data based on publication date"""
        logger.info(f"  📅 Generating {self.current_year} CNA analysis from CVE V5 data (by publication date)...")
        
        # Process data from ALL years, filtering by publication date
        current_year_data = self.process_current_year_by_publication_date()
        
        if not current_year_data:
            logger.warning(f"  ⚠️ No CVEs published in {self.current_year} found")
            return None
        
        # Load comprehensive analysis to get full CNA history for years_active calculation
        logger.info(f"    📊 Loading comprehensive analysis for full CNA history...")
        comprehensive_file = self.data_dir / 'cna_analysis.json'
        comprehensive_cnas = {}
        if comprehensive_file.exists():
            try:
                with open(comprehensive_file, 'r') as f:
                    comprehensive_data = json.load(f)
                    if 'cna_list' in comprehensive_data:
                        # Create lookup by assigner_org_id for quick access
                        for cna in comprehensive_data['cna_list']:
                            if 'assigner_org_id' in cna:
                                comprehensive_cnas[cna['assigner_org_id']] = cna
                logger.info(f"    ✅ Loaded {len(comprehensive_cnas)} CNAs from comprehensive analysis")
            except (FileNotFoundError, json.JSONDecodeError, KeyError, OSError) as e:
                logger.warning(f"    ⚠️ Could not load comprehensive analysis: {e}")
        
        # Convert to final format
        current_year_cnas = []
        for org_id, stats in current_year_data.items():
            # Classify CNA type
            cna_types = self.classify_cna_type(org_id, stats['assigner_short_name'])
            # Use years_active from comprehensive analysis for consistency
            years_active = 1  # Default fallback
            first_cve_year = None
            last_cve_year = None
            if org_id in comprehensive_cnas:
                comprehensive_cna = comprehensive_cnas[org_id]
                years_active = comprehensive_cna.get('years_active', 1)
                first_cve_year = comprehensive_cna.get('first_cve_year')
                last_cve_year = comprehensive_cna.get('last_cve_year')
            else:
                if stats['first_date'] and stats['last_date']:
                    try:
                        first_cve_year = datetime.fromisoformat(stats['first_date'].replace('Z', '+00:00')).year
                        last_cve_year = datetime.fromisoformat(stats['last_date'].replace('Z', '+00:00')).year
                        years_active = max(1, last_cve_year - first_cve_year + 1)
                    except (ValueError, TypeError):
                        years_active = 1
            # Aggregate severity and CWE types for current year
            severity_counts = defaultdict(int)
            cwe_counts = defaultdict(int)
            for cve_id in stats['cves']:
                # Find CVE file in all year dirs
                found_file = None
                for year_dir in (self.v5_cache_dir / 'cves').iterdir():
                    if year_dir.is_dir():
                        for subdir in year_dir.iterdir():
                            if subdir.is_dir():
                                candidate = subdir / f"{cve_id}.json"
                                if candidate.exists():
                                    found_file = candidate
                                    break
                        if found_file:
                            break
                if found_file:
                    try:
                        with open(found_file, 'r', encoding='utf-8') as f:
                            cve_data = json.load(f)
                        # Severity extraction (CVSS)
                        metrics = cve_data.get('metrics', {})
                        cvss = metrics.get('cvssMetricV31', metrics.get('cvssMetricV30', []))
                        if cvss and isinstance(cvss, list):
                            for metric in cvss:
                                base_score = metric.get('cvssData', {}).get('baseScore')
                                if base_score is not None:
                                    match base_score:
                                        case s if s >= 9:
                                            severity_counts['Critical'] += 1
                                        case s if s >= 7:
                                            severity_counts['High'] += 1
                                        case s if s >= 4:
                                            severity_counts['Medium'] += 1
                                        case _:
                                            severity_counts['Low'] += 1
                        # CWE extraction
                        weaknesses = cve_data.get('weaknesses', [])
                        for weakness in weaknesses:
                            for desc in weakness.get('description', []):
                                cwe_id = desc.get('value')
                                if cwe_id and cwe_id.startswith('CWE-'):
                                    cwe_counts[cwe_id] += 1
                    except (json.JSONDecodeError, KeyError, TypeError, OSError):
                        pass
            top_cwe_types = dict(sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)[:5])
            severity_distribution = dict(severity_counts)
            
            # Compute threat intelligence metrics from CVE IDs
            kev_count = 0
            epss_high_count = 0
            epss_elevated_count = 0
            
            for cve_id in stats['cves']:
                if cve_id in self.kev_cve_set:
                    kev_count += 1
                if cve_id in self.epss_mapping:
                    epss_score = self.epss_mapping[cve_id].get('epss_score', 0)
                    if epss_score > 0.5:
                        epss_high_count += 1
                    if epss_score > 0.1:
                        epss_elevated_count += 1
            
            cna_entry = {
                'name': stats['assigner_short_name'] or org_id,
                'assigner_org_id': org_id,
                'count': stats['count'],
                'rank': 0,  # Will be set after sorting
                'first_cve_date': stats['first_date'],
                'last_cve_date': stats['last_date'],
                'years_active': years_active,  # Use comprehensive value
                'first_cve_year': first_cve_year,
                'last_cve_year': last_cve_year,
                'is_official': True,  # All CVE V5 records are from official CNAs
                'activity_status': 'Active',  # All current year CNAs are active
                'cna_types': cna_types,  # Add CNA type classification
                'severity_distribution': severity_distribution,
                'top_cwe_types': top_cwe_types,
                # Threat intelligence metrics
                'kev_count': kev_count,
                'epss_high_count': epss_high_count,
                'epss_elevated_count': epss_elevated_count,
                'top_cwes': list(top_cwe_types.items())[:5]
            }
            current_year_cnas.append(cna_entry)
        
        # Sort by count and add ranks
        current_year_cnas.sort(key=lambda x: x['count'], reverse=True)
        for i, cna in enumerate(current_year_cnas):
            cna['rank'] = i + 1
        
        # Create current year data structure
        current_year_analysis = {
            'generated_at': datetime.now().isoformat(),
            'source': 'CVE V5 List (Authoritative)',
            'year': self.current_year,
            'total_cnas': len(current_year_cnas),
            'active_cnas': len(current_year_cnas),
            'inactive_cnas': 0,
            'official_cnas': len(current_year_cnas),  # All are official
            'unofficial_cnas': 0,  # None are unofficial
            'cna_list': current_year_cnas,
            'cna_assigners': current_year_cnas  # For backward compatibility
        }
        
        # Save current year analysis
        output_file = self.data_dir / 'cna_analysis_current_year.json'
        with open(output_file, 'w') as f:
            json.dump(current_year_analysis, f, indent=2)
        
        logger.info(f"  📄 Generated {self.current_year} CNA analysis with {len(current_year_cnas)} CNAs")
        
        return current_year_analysis
