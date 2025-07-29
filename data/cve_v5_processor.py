#!/usr/bin/env python3
"""
CVE V5 Processor Module
Handles CVE V5 list data processing as the single source of truth for CNA analysis
"""

import json
import subprocess
import shutil
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import os


class CVEV5Processor:
    """Processes CVE V5 list data for authoritative CNA analysis"""
    
    def __init__(self, base_dir, cache_dir, data_dir, quiet=False):
        self.quiet = quiet
        self.base_dir = Path(base_dir)
        self.cache_dir = Path(cache_dir)
        self.data_dir = Path(data_dir)
        self.current_year = datetime.now().year
        self.v5_cache_dir = self.cache_dir / 'cvelistV5'
        
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
        
    def clone_or_update_cve_v5_repo(self):
        """Clone or update the CVE V5 repository with shallow clone"""
        print(f"  📥 Setting up CVE V5 repository...")
        
        if self.v5_cache_dir.exists():
            # Check if it's a valid git repository
            git_dir = self.v5_cache_dir / '.git'
            if not git_dir.exists():
                print(f"    ⚠️ Invalid git repository, re-cloning...")
                shutil.rmtree(self.v5_cache_dir)
                return self._clone_fresh_repo()
            
            print(f"    🔄 Updating existing CVE V5 repository...")
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
                    print(f"    ✅ Successfully updated CVE V5 repository")
                    return True
                else:
                    # Try to reset and pull if there are conflicts
                    print(f"    🔄 Pull failed, trying reset and pull...")
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
                            print(f"    ✅ Successfully updated CVE V5 repository after reset")
                            return True
                    
                    # Only re-clone as last resort
                    print(f"    ⚠️ All update attempts failed, re-cloning as last resort...")
                    print(f"    📝 Git pull error: {result.stderr}")
                    shutil.rmtree(self.v5_cache_dir)
                    return self._clone_fresh_repo()
                    
            except subprocess.TimeoutExpired:
                print(f"    ⏰ Git pull timed out, repository may be up to date")
                return True  # Don't re-clone on timeout, assume it's working
            except Exception as e:
                print(f"    ⚠️ Update failed with exception: {e}")
                # Only re-clone if it's a critical error
                if "not a git repository" in str(e).lower():
                    shutil.rmtree(self.v5_cache_dir)
                    return self._clone_fresh_repo()
                else:
                    print(f"    📝 Assuming repository is usable despite error")
                    return True
        else:
            return self._clone_fresh_repo()
        
        return True
    
    def _clone_fresh_repo(self):
        """Clone fresh CVE V5 repository"""
        print(f"    📦 Cloning CVE V5 repository (shallow clone)...")
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
                print(f"    ✅ Successfully cloned CVE V5 repository")
                return True
            else:
                print(f"    ❌ Failed to clone CVE V5 repository: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"    ❌ Clone operation timed out")
            return False
        except Exception as e:
            print(f"    ❌ Clone failed: {e}")
            return False
    
    def get_repo_stats(self):
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
    
    def classify_cna_type(self, org_id, short_name):
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
    
    def calculate_enhanced_statistics(self, cna_list):
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
        
        # Convert to format expected by JavaScript
        # JavaScript expects: type_distribution.sorted_types and type_distribution.type_percentages
        sorted_types = []
        type_percentages = {}
        
        # Sort by count (descending)
        sorted_type_items = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)
        
        for cna_type, count in sorted_type_items:
            percentage = (count / total_cnas * 100) if total_cnas > 0 else 0
            sorted_types.append([cna_type, count])  # JavaScript expects [type, count] pairs
            type_percentages[cna_type] = round(percentage, 1)
        
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
            
            # Extract CNA information from V5 format
            assigner_org_id = cve_metadata.get('assignerOrgId', '')
            assigner_short_name = cve_metadata.get('assignerShortName', '')
            
            # Extract publication date
            date_published = cve_metadata.get('datePublished', '')
            date_updated = cve_metadata.get('dateUpdated', '')
            
            # Use publication date for accurate CNA activity tracking
            # (date_updated reflects record modifications, not actual CVE assignment)
            pub_date = date_published if date_published else date_updated
            
            return {
                'cve_id': cve_id,
                'assigner_org_id': assigner_org_id,
                'assigner_short_name': assigner_short_name,
                'date_published': date_published,
                'date_updated': date_updated,
                'publication_date': pub_date,
                'year': int(cve_id.split('-')[1]) if cve_id.startswith('CVE-') else None
            }
            
        except Exception as e:
            print(f"    ⚠️ Error parsing {cve_file_path}: {e}")
            return None
    
    def process_year_data(self, year):
        """Process all CVE records for a specific year"""
        print(f"    📅 Processing CVE data for year {year}...")
        
        year_dir = self.v5_cache_dir / 'cves' / str(year)
        if not year_dir.exists():
            print(f"    ⚠️ No data found for year {year}")
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
            print(f"    📊 Found {total_files} CVE files for {year}")
        
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
                print(f"    📈 Processed {processed}/{total_files} files...")
        
        if not self.quiet:
            print(f"    ✅ Processed {processed} CVE files, found {len(cna_stats)} CNAs for {year}")
        return dict(cna_stats)
    
    def generate_comprehensive_cna_analysis(self):
        """Generate comprehensive CNA analysis using CVE V5 data as single source of truth"""
        print(f"  🏢 Generating comprehensive CNA analysis from CVE V5 data...")
        
        # Ensure we have the latest CVE V5 data
        if not self.clone_or_update_cve_v5_repo():
            print(f"  ❌ Failed to setup CVE V5 repository")
            return None
        
        # Get repository statistics
        repo_stats = self.get_repo_stats()
        if not repo_stats:
            print(f"  ❌ Failed to get repository statistics")
            return None
            
        print(f"  📊 Repository contains {repo_stats['total_cves']} CVEs across {repo_stats['total_years']} years")
        print(f"  📅 Years available: {repo_stats['years_available']}")
        
        # Process all years to build comprehensive CNA statistics
        all_cna_stats = defaultdict(lambda: {
            'count': 0,
            'years_active': set(),
            'first_date': None,
            'last_date': None,
            'first_year': None,
            'last_year': None,
            'assigner_org_id': '',
            'assigner_short_name': '',
            'cves_by_year': defaultdict(int)
        })
        
        # Process each year
        for year in repo_stats['years_available']:
            year_data = self.process_year_data(year)
            
            for org_id, stats in year_data.items():
                # Aggregate statistics across all years
                all_cna_stats[org_id]['count'] += stats['count']
                all_cna_stats[org_id]['years_active'].add(year)
                all_cna_stats[org_id]['cves_by_year'][year] = stats['count']
                all_cna_stats[org_id]['assigner_org_id'] = stats['assigner_org_id']
                all_cna_stats[org_id]['assigner_short_name'] = stats['assigner_short_name']
                
                # Update date ranges
                if stats['first_date']:
                    if not all_cna_stats[org_id]['first_date'] or stats['first_date'] < all_cna_stats[org_id]['first_date']:
                        all_cna_stats[org_id]['first_date'] = stats['first_date']
                        all_cna_stats[org_id]['first_year'] = year
                        
                if stats['last_date']:
                    if not all_cna_stats[org_id]['last_date'] or stats['last_date'] > all_cna_stats[org_id]['last_date']:
                        all_cna_stats[org_id]['last_date'] = stats['last_date']
                        all_cna_stats[org_id]['last_year'] = year
        
        # Convert to final format
        cna_list = []
        for org_id, stats in all_cna_stats.items():
            # Calculate years active
            years_active_count = len(stats['years_active'])
            
            # Calculate days since last CVE
            days_since_last = 365  # Default to inactive
            if stats['last_date']:
                try:
                    last_date = datetime.fromisoformat(stats['last_date'].replace('Z', '+00:00'))
                    days_since_last = (datetime.now(last_date.tzinfo) - last_date).days
                except:
                    days_since_last = 365
            
            # Determine activity status
            activity_status = 'Active' if days_since_last < 365 else 'Inactive'
            
            # Classify CNA type
            cna_types = self.classify_cna_type(org_id, stats['assigner_short_name'])
            
            cna_entry = {
                'name': stats['assigner_short_name'] or org_id,
                'assigner_org_id': org_id,
                'count': stats['count'],
                'years_active': years_active_count,
                'first_cve_year': stats['first_year'],
                'last_cve_year': stats['last_year'],
                'first_cve_date': stats['first_date'],
                'last_cve_date': stats['last_date'],
                'days_since_last_cve': days_since_last,
                'activity_status': activity_status,
                'is_official': True,  # All CVE V5 records are from official CNAs
                'cna_types': cna_types,  # Add CNA type classification
                'cves_by_year': dict(stats['cves_by_year']),
                'years_active_list': sorted(list(stats['years_active'])),
                # Add placeholder fields for compatibility
                'severity_distribution': {},
                'top_cwe_types': {}
            }
            cna_list.append(cna_entry)
        
        # Sort by CVE count (descending)
        cna_list.sort(key=lambda x: x['count'], reverse=True)
        
        # Add ranks
        for i, cna in enumerate(cna_list):
            cna['rank'] = i + 1
        
        # Calculate enhanced statistics
        enhanced_stats = self.calculate_enhanced_statistics(cna_list)
        
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
        
        print(f"  📄 Generated comprehensive CNA analysis with {len(cna_list)} CNAs")
        print(f"  📊 Active: {enhanced_stats.get('active_cnas', 0)}, Inactive: {enhanced_stats.get('inactive_cnas', 0)}")
        
        return comprehensive_data
    
    def process_current_year_by_publication_date(self):
        """Process CVEs from ALL years, filtering by current year publication date"""
        print(f"    🔍 Scanning all CVE years for {self.current_year} publications...")
        
        cves_dir = self.v5_cache_dir / 'cves'
        if not cves_dir.exists():
            print(f"    ❌ CVEs directory not found")
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
                print(f"    📂 Scanning CVE-{year}-* files for {self.current_year} publications...")
            
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
                        except Exception as e:
                            # Skip CVEs with invalid dates
                            pass
                
                total_processed += 1
                if total_processed % 5000 == 0 and not self.quiet:
                    print(f"    📈 Processed {total_processed} files, found {current_year_cves} {self.current_year} publications...")
            
            if year_current_cves > 0 and not self.quiet:
                print(f"    ✅ Found {year_current_cves} CVEs published in {self.current_year} from CVE-{year}-* files")
        
        if not self.quiet:
            print(f"    🎯 Total: {current_year_cves} CVEs published in {self.current_year}, from {len(cna_stats)} CNAs")
        return dict(cna_stats)
    
    def generate_current_year_analysis(self):
        """Generate current year CNA analysis from CVE V5 data based on publication date"""
        print(f"  📅 Generating {self.current_year} CNA analysis from CVE V5 data (by publication date)...")
        
        # Process data from ALL years, filtering by publication date
        current_year_data = self.process_current_year_by_publication_date()
        
        if not current_year_data:
            print(f"  ⚠️ No CVEs published in {self.current_year} found")
            return None
        
        # Load comprehensive analysis to get full CNA history for years_active calculation
        print(f"    📊 Loading comprehensive analysis for full CNA history...")
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
                print(f"    ✅ Loaded {len(comprehensive_cnas)} CNAs from comprehensive analysis")
            except Exception as e:
                print(f"    ⚠️ Could not load comprehensive analysis: {e}")
        
        # Convert to final format
        current_year_cnas = []
        for org_id, stats in current_year_data.items():
            # Classify CNA type
            cna_types = self.classify_cna_type(org_id, stats['assigner_short_name'])
            
            # Calculate years active using full CNA history from comprehensive analysis
            years_active = 1  # Default fallback
            if org_id in comprehensive_cnas:
                # Use the comprehensive analysis years_active which includes full history
                comprehensive_cna = comprehensive_cnas[org_id]
                if 'years_active' in comprehensive_cna:
                    years_active = comprehensive_cna['years_active']
                    if not self.quiet:
                        print(f"    📅 {stats['assigner_short_name']}: Using full history {years_active} years")
                elif 'first_cve_year' in comprehensive_cna and 'last_cve_year' in comprehensive_cna:
                    # Calculate from full year range
                    years_active = max(1, comprehensive_cna['last_cve_year'] - comprehensive_cna['first_cve_year'] + 1)
                    print(f"    📅 {stats['assigner_short_name']}: Calculated {years_active} years from {comprehensive_cna['first_cve_year']}-{comprehensive_cna['last_cve_year']}")
            else:
                # Fallback: calculate from current year dates only (will be 1 year for most)
                if stats['first_date'] and stats['last_date']:
                    try:
                        first_year = datetime.fromisoformat(stats['first_date'].replace('Z', '+00:00')).year
                        last_year = datetime.fromisoformat(stats['last_date'].replace('Z', '+00:00')).year
                        years_active = max(1, last_year - first_year + 1)
                    except:
                        years_active = 1
                print(f"    ⚠️ {stats['assigner_short_name']}: No comprehensive data, using fallback {years_active} year(s)")
            
            cna_entry = {
                'name': stats['assigner_short_name'] or org_id,
                'assigner_org_id': org_id,
                'count': stats['count'],
                'rank': 0,  # Will be set after sorting
                'first_cve_date': stats['first_date'],
                'last_cve_date': stats['last_date'],
                'years_active': years_active,  # Add years active calculation
                'is_official': True,  # All CVE V5 records are from official CNAs
                'activity_status': 'Active',  # All current year CNAs are active
                'cna_types': cna_types,  # Add CNA type classification
                # Add placeholder fields for compatibility
                'severity_distribution': {},
                'top_cwe_types': {}
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
        
        print(f"  📄 Generated {self.current_year} CNA analysis with {len(current_year_cnas)} CNAs")
        
        return current_year_analysis
