#!/usr/bin/env python3
"""
CVE Years Analyzer
Processes CVE data from JSONL file and generates yearly analysis data
Handles historical data (1999-2016) and individual years (2017-present)
"""

import json
import re
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict, Counter
from urllib.parse import urlparse
from download_cve_data import CVEDataDownloader

class CVEYearsAnalyzer:
    """Analyzes CVE data by year and generates structured data for visualization"""
    
    def __init__(self, quiet=False):
        self.quiet = quiet
        self.base_dir = Path(__file__).parent
        self.downloader = CVEDataDownloader(quiet=quiet)
        self.data_file = None
        self.year_data_cache = {}
        
        # CNA mapping data for proper name resolution
        self.cna_list = {}
        self.cna_name_map = {}
        
        if not self.quiet:
            print(f"📊 CVE Years Analyzer Initialized")
            print(f"📅 Target coverage: 1999-{datetime.now().year}")
    
    def ensure_data_loaded(self):
        """Ensure CVE data is downloaded and available"""
        if self.data_file is None:
            if not self.quiet:
                print("🔽 Loading CVE data...")
            self.data_file = self.downloader.ensure_data_available()
            if not self.quiet:
                print(f"✅ Data loaded from: {self.data_file}")
            
            # Load CNA mapping data
            self.load_cna_mappings()
    
    def load_cna_mappings(self):
        """Load CNA mapping files for proper name resolution"""
        try:
            # Load CNA list
            cna_list_file = self.downloader.cache_dir / "cna_list.json"
            if cna_list_file.exists():
                with open(cna_list_file, 'r', encoding='utf-8') as f:
                    cna_data = json.load(f)
                    # Convert to lookup dict by sourceIdentifier
                    for cna in cna_data.get('data', []):
                        source_id = cna.get('sourceIdentifier', '')
                        if source_id:
                            self.cna_list[source_id] = cna
                if not self.quiet:
                    print(f"✅ Loaded {len(self.cna_list)} CNA entries")
            
            # Load CNA name mapping
            cna_name_map_file = self.downloader.cache_dir / "cna_name_map.json"
            if cna_name_map_file.exists():
                with open(cna_name_map_file, 'r', encoding='utf-8') as f:
                    self.cna_name_map = json.load(f)
                if not self.quiet:
                    print(f"✅ Loaded CNA name mappings for {len(self.cna_name_map)} entries")
                
        except Exception as e:
            if not self.quiet:
                print(f"⚠️  Warning: Could not load CNA mappings: {e}")
                print("  📝 Will use raw sourceIdentifier values as fallback")
    
    def parse_cve_date(self, cve_data):
        """Extract publication date from CVE data"""
        try:
            # Try multiple date fields in order of preference
            date_fields = [
                ['publishedDate'],
                ['lastModifiedDate'],
                ['cve', 'CVE_data_meta', 'DATE_PUBLIC'],
                ['cve', 'published'],
                ['cve', 'lastModified']
            ]
            
            for field_path in date_fields:
                try:
                    value = cve_data
                    for field in field_path:
                        value = value[field]
                    
                    if value:
                        # Parse various date formats
                        if isinstance(value, str):
                            # Handle ISO format dates
                            if 'T' in value:
                                return datetime.fromisoformat(value.replace('Z', '+00:00'))
                            # Handle simple date formats
                            for fmt in ['%Y-%m-%d', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%dT%H:%M:%S.%f']:
                                try:
                                    return datetime.strptime(value[:len(fmt.replace('%f', ''))], fmt)
                                except ValueError:
                                    continue
                        
                except (KeyError, TypeError, ValueError):
                    continue
            
            # Fallback: extract year from CVE ID (CVE-YYYY-NNNN)
            cve_id = cve_data.get('cve', {}).get('CVE_data_meta', {}).get('ID', '')
            if cve_id.startswith('CVE-'):
                year = int(cve_id.split('-')[1])
                return datetime(year, 1, 1)  # Default to January 1st
            
            return None
            
        except Exception as e:
            return None
    
    def extract_severity_info(self, cve_data):
        """Extract CVSS severity information from all versions (V2, V3.0, V3.1, V4.0)"""
        try:
            # Get metrics from the CVE data structure
            metrics = cve_data.get('cve', {}).get('metrics', {})
            
            # Priority order: V4.0 > V3.1 > V3.0 > V2.0 (prefer newer versions)
            
            # Try CVSS v4.0 first (cvssMetricV40)
            if 'cvssMetricV40' in metrics:
                cvss_metrics = metrics['cvssMetricV40']
                if isinstance(cvss_metrics, list) and len(cvss_metrics) > 0:
                    cvss_data = cvss_metrics[0].get('cvssData', {})
                    base_score = cvss_data.get('baseScore', 0)
                    base_severity = cvss_data.get('baseSeverity', 'UNKNOWN')  # V4.0: severity in cvssData
                    return {
                        'version': 'v4.0',
                        'score': base_score,
                        'severity': base_severity.upper()
                    }
                elif isinstance(cvss_metrics, dict):
                    cvss_data = cvss_metrics.get('cvssData', {})
                    base_score = cvss_data.get('baseScore', 0)
                    base_severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                    return {
                        'version': 'v4.0',
                        'score': base_score,
                        'severity': base_severity.upper()
                    }    
            
            # Try CVSS v3.1 (cvssMetricV31)
            if 'cvssMetricV31' in metrics:
                cvss_metrics = metrics['cvssMetricV31']
                if isinstance(cvss_metrics, list) and len(cvss_metrics) > 0:
                    cvss_data = cvss_metrics[0].get('cvssData', {})
                    base_score = cvss_data.get('baseScore', 0)
                    base_severity = cvss_data.get('baseSeverity', 'UNKNOWN')  # V3.1: severity in cvssData
                    return {
                        'version': 'v3.1',
                        'score': base_score,
                        'severity': base_severity.upper()
                    }
                elif isinstance(cvss_metrics, dict):
                    cvss_data = cvss_metrics.get('cvssData', {})
                    base_score = cvss_data.get('baseScore', 0)
                    base_severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                    return {
                        'version': 'v3.1',
                        'score': base_score,
                        'severity': base_severity.upper()
                    }    
            
            # Try CVSS v3.0 (cvssMetricV30)
            if 'cvssMetricV30' in metrics:
                cvss_metrics = metrics['cvssMetricV30']
                if isinstance(cvss_metrics, list) and len(cvss_metrics) > 0:
                    cvss_data = cvss_metrics[0].get('cvssData', {})
                    base_score = cvss_data.get('baseScore', 0)
                    base_severity = cvss_data.get('baseSeverity', 'UNKNOWN')  # V3.0: severity in cvssData
                    return {
                        'version': 'v3.0',
                        'score': base_score,
                        'severity': base_severity.upper()
                    }
                elif isinstance(cvss_metrics, dict):
                    cvss_data = cvss_metrics.get('cvssData', {})
                    base_score = cvss_data.get('baseScore', 0)
                    base_severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                    return {
                        'version': 'v3.0',
                        'score': base_score,
                        'severity': base_severity.upper()
                    }    
            
            # Try CVSS v2 (cvssMetricV2)
            if 'cvssMetricV2' in metrics:
                cvss_metrics = metrics['cvssMetricV2']
                if isinstance(cvss_metrics, list) and len(cvss_metrics) > 0:
                    cvss_data = cvss_metrics[0].get('cvssData', {})
                    base_score = cvss_data.get('baseScore', 0)
                    base_severity = cvss_metrics[0].get('baseSeverity', '')  # V2: severity at top level
                    
                    # If no severity provided, calculate from score (V2 fallback)
                    if not base_severity:
                        if base_score >= 7.0:
                            base_severity = 'HIGH'
                        elif base_score >= 4.0:
                            base_severity = 'MEDIUM'
                        else:
                            base_severity = 'LOW'
                    
                    return {
                        'version': 'v2.0',
                        'score': base_score,
                        'severity': base_severity.upper()
                    }
                elif isinstance(cvss_metrics, dict):
                    cvss_data = cvss_metrics.get('cvssData', {})
                    base_score = cvss_data.get('baseScore', 0)
                    base_severity = cvss_metrics.get('baseSeverity', '')
                    
                    # If no severity provided, calculate from score (V2 fallback)
                    if not base_severity:
                        if base_score >= 7.0:
                            base_severity = 'HIGH'
                        elif base_score >= 4.0:
                            base_severity = 'MEDIUM'
                        else:
                            base_severity = 'LOW'
                    
                    return {
                        'version': 'v2.0',
                        'score': base_score,
                        'severity': base_severity.upper()
                    }    
            
            return {
                'version': 'unknown',
                'score': 0,
                'severity': 'UNKNOWN'
            }
            
        except Exception:
            return {
                'version': 'unknown',
                'score': 0,
                'severity': 'UNKNOWN'
            }
    
    def extract_vendor_info(self, cve_data):
        """Extract vendor/CNA assigner information with proper name resolution"""
        vendors = []
        try:
            # Extract CNA assigner (sourceIdentifier)
            source_identifier = cve_data.get('cve', {}).get('sourceIdentifier', '')
            if source_identifier:
                # Apply special case handling
                if source_identifier == '416baaa9-dc9f-4396-8d5f-8c081fb06d67':
                    source_identifier = 'cve@kernel.org'
                
                # Try to resolve using official CNA mappings
                resolved_name = self.resolve_cna_name(source_identifier)
                if resolved_name:
                    vendors.append(resolved_name)
                else:
                    # Fallback to domain extraction for email-like identifiers
                    if '@' in source_identifier:
                        domain = source_identifier.split('@')[-1]
                        vendors.append(domain)
                    else:
                        vendors.append(source_identifier)
            
            return vendors
            
        except Exception:
            return []
    
    def resolve_cna_name(self, source_identifier):
        """Resolve CNA sourceIdentifier to proper organization name using comprehensive mapping"""
        try:
            # First try the official UUID-based name mapping file
            if source_identifier in self.cna_name_map:
                return self.cna_name_map[source_identifier]
            
            # Create comprehensive domain-to-organization mapping
            domain_mappings = {
                'mitre.org': 'MITRE Corporation',
                'oracle.com': 'Oracle Corporation',
                'adobe.com': 'Adobe Inc.',
                'redhat.com': 'Red Hat, Inc.',
                'microsoft.com': 'Microsoft Corporation',
                'cisco.com': 'Cisco Systems, Inc.',
                'apple.com': 'Apple Inc.',
                'google.com': 'Google LLC',
                'mozilla.org': 'Mozilla Foundation',
                'us.ibm.com': 'IBM Corporation',
                'android.com': 'Google LLC',
                'cert.org': 'CERT Coordination Center',
                'jpcert.or.jp': 'JPCERT/CC',
                'debian.org': 'Debian Project',
                'ubuntu.com': 'Canonical Ltd.',
                'hq.dhs.gov': 'US Department of Homeland Security',
                'opentext.com': 'OpenText Corporation',
                'emc.com': 'Dell EMC',
                'symantec.com': 'NortonLifeLock Inc.',
                'nvidia.com': 'NVIDIA Corporation',
                'suse.com': 'SUSE LLC',
                'vmware.com': 'VMware, Inc.',
                'hp.com': 'HP Inc.',
                'intel.com': 'Intel Corporation',
                'linux.org': 'Linux Foundation',
                'kernel.org': 'Linux Kernel Organization',
                'apache.org': 'Apache Software Foundation',
                'eclipse.org': 'Eclipse Foundation',
                'nodejs.org': 'Node.js Foundation',
                'python.org': 'Python Software Foundation',
                'ruby-lang.org': 'Ruby Association',
                'php.net': 'PHP Group',
                'postgresql.org': 'PostgreSQL Global Development Group',
                'mysql.com': 'Oracle Corporation',
                'mariadb.org': 'MariaDB Foundation',
                'mongodb.com': 'MongoDB, Inc.',
                'elastic.co': 'Elastic N.V.',
                'jenkins.io': 'Jenkins Project',
                'docker.com': 'Docker, Inc.',
                'kubernetes.io': 'Cloud Native Computing Foundation',
                'github.com': 'GitHub, Inc.',
                'gitlab.com': 'GitLab Inc.',
                'atlassian.com': 'Atlassian Corporation',
                'jetbrains.com': 'JetBrains s.r.o.',
                'salesforce.com': 'Salesforce, Inc.',
                'zoom.us': 'Zoom Video Communications, Inc.',
                'slack.com': 'Slack Technologies, Inc.',
                'dropbox.com': 'Dropbox, Inc.',
                'box.com': 'Box, Inc.',
                'spotify.com': 'Spotify Technology S.A.',
                'netflix.com': 'Netflix, Inc.',
                'amazon.com': 'Amazon.com, Inc.',
                'aws.amazon.com': 'Amazon Web Services, Inc.',
                'facebook.com': 'Meta Platforms, Inc.',
                'meta.com': 'Meta Platforms, Inc.',
                'twitter.com': 'Twitter, Inc.',
                'linkedin.com': 'LinkedIn Corporation',
                'snapchat.com': 'Snap Inc.',
                'tiktok.com': 'ByteDance Ltd.',
                'yahoo.com': 'Yahoo! Inc.',
                'verizon.com': 'Verizon Communications Inc.',
                'att.com': 'AT&T Inc.',
                'tmobile.com': 'T-Mobile US, Inc.',
                'sprint.com': 'Sprint Corporation',
                'comcast.com': 'Comcast Corporation',
                'sony.com': 'Sony Corporation',
                'samsung.com': 'Samsung Electronics Co., Ltd.',
                'lg.com': 'LG Electronics Inc.',
                'huawei.com': 'Huawei Technologies Co., Ltd.',
                'xiaomi.com': 'Xiaomi Corporation',
                'lenovo.com': 'Lenovo Group Limited',
                'dell.com': 'Dell Technologies Inc.',
                'amd.com': 'Advanced Micro Devices, Inc.',
                'qualcomm.com': 'QUALCOMM Incorporated',
                'broadcom.com': 'Broadcom Inc.',
                'marvell.com': 'Marvell Technology Group Ltd.',
                'mediatek.com': 'MediaTek Inc.',
                'arm.com': 'Arm Limited',
                'siemens.com': 'Siemens AG',
                'ge.com': 'General Electric Company',
                'schneider-electric.com': 'Schneider Electric SE',
                'abb.com': 'ABB Ltd.',
                'rockwellautomation.com': 'Rockwell Automation, Inc.',
                'honeywell.com': 'Honeywell International Inc.',
                'emerson.com': 'Emerson Electric Co.',
                'yokogawa.com': 'Yokogawa Electric Corporation',
                'mitsubishielectric.com': 'Mitsubishi Electric Corporation',
                'omron.com': 'OMRON Corporation',
                'panasonic.com': 'Panasonic Corporation',
                'toshiba.com': 'Toshiba Corporation',
                'hitachi.com': 'Hitachi, Ltd.',
                'fujitsu.com': 'Fujitsu Limited',
                'nec.com': 'NEC Corporation',
                'canon.com': 'Canon Inc.',
                'ricoh.com': 'Ricoh Company, Ltd.',
                'xerox.com': 'Xerox Corporation',
                'epson.com': 'Seiko Epson Corporation'
            }
            
            # Try direct domain mapping
            if source_identifier in domain_mappings:
                return domain_mappings[source_identifier]
            
            # Try to match by extracting domain from email-like identifiers
            if '@' in source_identifier:
                domain = source_identifier.split('@')[-1]
                if domain in domain_mappings:
                    return domain_mappings[domain]
            
            # No mapping found - return None to use fallback
            return None
            
        except Exception:
            return None
    
    def create_complete_daily_array(self, daily_counts, year):
        """Create complete daily array with zeros for missing dates to prevent UI issues"""
        try:
            # Create date range for the entire year
            start_date = datetime(year, 1, 1)
            if year == datetime.now().year:
                # For current year, only go up to today
                end_date = datetime.now().date()
            else:
                # For past years, include the entire year
                end_date = datetime(year, 12, 31).date()
            
            complete_daily_counts = {}
            current_date = start_date.date()
            
            while current_date <= end_date:
                date_str = current_date.strftime('%Y-%m-%d')
                complete_daily_counts[date_str] = daily_counts.get(date_str, 0)
                current_date += timedelta(days=1)
            
            return complete_daily_counts
            
        except Exception as e:
            print(f"⚠️  Warning: Could not create complete daily array: {e}")
            return daily_counts
    
    def extract_cwe_info(self, cve_data):
        """Extract CWE (Common Weakness Enumeration) information from CVE data"""
        cwes = []
        try:
            # Look for CWE information in the weaknesses section
            weaknesses = cve_data.get('cve', {}).get('weaknesses', [])
            
            for weakness in weaknesses:
                descriptions = weakness.get('description', [])
                for desc in descriptions:
                    if desc.get('lang') == 'en':  # English descriptions only
                        cwe_value = desc.get('value', '')
                        if cwe_value and cwe_value.startswith('CWE-'):
                            # Filter out "Missing" CWEs as per original notebook
                            if 'Missing_' not in cwe_value:
                                cwes.append(cwe_value)
            
            return cwes
            
        except Exception:
            return []
    
    def extract_identifier_info(self, cve_data):
        """Extract CVE identifiers and references information (secure hostname check)"""
        identifiers = []
        try:
            # Extract references/identifiers from the CVE data
            references = cve_data.get('cve', {}).get('references', [])
            for ref in references:
                url = ref.get('url', '')
                if url:
                    try:
                        parsed = urlparse(url)
                        hostname = parsed.hostname or ''
                        if hostname == 'github.com' or hostname.endswith('.github.com'):
                            identifiers.append('GitHub')
                        elif hostname == 'nvd.nist.gov':
                            identifiers.append('NVD')
                        elif hostname == 'cve.mitre.org':
                            identifiers.append('MITRE')
                        elif hostname == 'security-tracker.debian.org':
                            identifiers.append('Debian')
                        elif hostname == 'access.redhat.com':
                            identifiers.append('Red Hat')
                        elif hostname == 'ubuntu.com' or hostname.endswith('.ubuntu.com'):
                            identifiers.append('Ubuntu')
                        elif 'bugzilla' in hostname:
                            identifiers.append('Bugzilla')
                        elif hostname == 'exploit-db.com' or hostname == 'www.exploit-db.com':
                            identifiers.append('Exploit-DB')
                        else:
                            if hostname:
                                identifiers.append(hostname)
                    except Exception:
                        pass
            return identifiers
        except Exception:
            return []
    
    def extract_cpe_vendor_info(self, cve_data):
        """Extract vendor information from CPE (Common Platform Enumeration) data"""
        vendors = []
        try:
            # Look in cve.configurations for CPE data (it's a list, not dict with nodes)
            configurations = cve_data.get('cve', {}).get('configurations', [])
            
            # configurations is a list of configuration objects
            for config in configurations:
                # Each config has nodes
                nodes = config.get('nodes', [])
                for node in nodes:
                    cpe_matches = node.get('cpeMatch', [])
                    for cpe in cpe_matches:
                        # The CPE URI is in 'criteria' field, not 'cpe23Uri'
                        cpe_uri = cpe.get('criteria', '')
                        if not cpe_uri:
                            # Fallback to cpe23Uri if criteria is empty
                            cpe_uri = cpe.get('cpe23Uri', '')
                        
                        if cpe_uri and cpe_uri.startswith('cpe:2.3:'):
                            # Parse CPE format: cpe:2.3:part:vendor:product:version:...
                            parts = cpe_uri.split(':')
                            if len(parts) > 3:
                                vendor = parts[3].replace('_', ' ').title()
                                if vendor and vendor.lower() not in ['*', 'n/a', 'unknown', '-', '']:
                                    vendors.append(vendor)
            
            return list(set(vendors))  # Remove duplicates
            
        except Exception:
            return []
    
    def process_year_data(self, year):
        """Process CVE data for a specific year"""
        if year in self.year_data_cache:
            return self.year_data_cache[year]
        
        self.ensure_data_loaded()
        
        if not self.quiet:
            print(f"📊 Processing CVE data for {year}...")
        
        # Initialize counters
        monthly_counts = [0] * 12
        daily_counts = {}  # For daily publication analysis
        # CVSS severity organized by version
        cvss_data = {
            'v2.0': {'severity_counts': Counter(), 'score_distribution': Counter(), 'total': 0},
            'v3.0': {'severity_counts': Counter(), 'score_distribution': Counter(), 'total': 0},
            'v3.1': {'severity_counts': Counter(), 'score_distribution': Counter(), 'total': 0},
            'v4.0': {'severity_counts': Counter(), 'score_distribution': Counter(), 'total': 0},
            'unknown': {'severity_counts': Counter(), 'score_distribution': Counter(), 'total': 0}
        }
        vendor_counts = Counter()
        cwe_counts = Counter()
        status_counts = Counter()  # CVE status tracking
        tag_counts = Counter()     # CVE tags tracking
        reference_tag_counts = Counter()  # Reference tags
        cpe_vendor_counts = Counter()     # CPE-based vendor analysis
        if not self.quiet:
            print("🔽 Loading CVE data...")
        
        # Load and parse JSON array data
        if not self.quiet:
            print("  📊 Reading JSON array format...")
        with open(self.data_file, 'r', encoding='utf-8') as f:
            try:
                # Load the entire JSON array
                all_cves = json.load(f)
                if not self.quiet:
                    print(f"  📊 Loaded {len(all_cves)} CVE records")
            except json.JSONDecodeError as e:
                print(f"  ❌ Failed to parse JSON: {e}")  # Always show errors
                return self.create_empty_year_data(year)
        
        # Process each CVE record
        total_cves = 0
        for cve_idx, cve_data in enumerate(all_cves):
            if cve_idx % 10000 == 0 and cve_idx > 0 and not self.quiet:
                print(f"  📊 Processed {cve_idx:,} CVEs...")
                
            try:
                # Get CVE ID and basic info
                cve_id = cve_data.get('cve', {}).get('id', '')
                if not cve_id.startswith('CVE-'):
                    continue
                    
                # Check CVE status and skip rejected CVEs
                vuln_status = cve_data.get('cve', {}).get('vulnStatus', '')
                if 'Rejected' in vuln_status:
                    continue
                    
                # Extract year from CVE ID for primary filtering
                cve_year = int(cve_id.split('-')[1])
                
                # For historical data (1999-2016), we need to check publication date
                # as CVE-2016-XXXX might contain older CVEs
                pub_date = self.parse_cve_date(cve_data)
                if pub_date:
                    actual_year = pub_date.year
                else:
                    actual_year = cve_year
                
                # Skip if not the year we're looking for
                if actual_year != year:
                    continue
                
                total_cves += 1
                
                # Count by month and day
                if pub_date:
                    month_idx = pub_date.month - 1
                    monthly_counts[month_idx] += 1
                    
                    # Daily publication tracking
                    date_str = pub_date.strftime('%Y-%m-%d')
                    daily_counts[date_str] = daily_counts.get(date_str, 0) + 1
                
                # Extract severity information organized by CVSS version
                severity_info = self.extract_severity_info(cve_data)
                cvss_version = severity_info['version']
                severity = severity_info['severity']
                score = severity_info['score']
                
                # Track severity and score distribution by CVSS version
                if cvss_version in cvss_data:
                    cvss_data[cvss_version]['severity_counts'][severity] += 1
                    # Round score to 1 decimal place for distribution tracking
                    score_key = round(float(score), 1) if score > 0 else 0.0
                    cvss_data[cvss_version]['score_distribution'][score_key] += 1
                    cvss_data[cvss_version]['total'] += 1
                else:
                    cvss_data['unknown']['severity_counts'][severity] += 1
                    score_key = round(float(score), 1) if score > 0 else 0.0
                    cvss_data['unknown']['score_distribution'][score_key] += 1
                    cvss_data['unknown']['total'] += 1
                
                # Extract additional NVD schema fields
                vuln_status = cve_data.get('cve', {}).get('vulnStatus', 'Unknown')
                status_counts[vuln_status] += 1
                
                # Extract CVE tags
                cve_tags = cve_data.get('cve', {}).get('cveTags', [])
                for tag in cve_tags:
                    # Handle both string tags and dictionary tags
                    if isinstance(tag, str):
                        tag_counts[tag] += 1
                    elif isinstance(tag, dict) and 'tag' in tag:
                        tag_counts[tag['tag']] += 1
                
                # Extract reference tags
                references = cve_data.get('cve', {}).get('references', [])
                for ref in references:
                    ref_tags = ref.get('tags', [])
                    for tag in ref_tags:
                        reference_tag_counts[tag] += 1
                
                # Extract CPE-based vendor information
                cpe_vendors = self.extract_cpe_vendor_info(cve_data)
                for vendor in cpe_vendors:
                    cpe_vendor_counts[vendor] += 1
                
                # Extract vendor information (CNA assigners)
                vendors = self.extract_vendor_info(cve_data)
                for vendor in vendors:
                    vendor_counts[vendor] += 1
                
                # Extract CWE information
                cwes = self.extract_cwe_info(cve_data)
                for cwe in cwes:
                    cwe_counts[cwe] += 1
                
            except (json.JSONDecodeError, KeyError, ValueError, IndexError) as e:
                if cve_idx <= 10:  # Only log first few errors
                    print(f"  ⚠️  Error processing CVE {cve_idx}: {e}")
                continue
                # Progress update every 10000 lines
                if line_num % 10000 == 0:
                    if not self.quiet:
                        print(f"    📋 Processed {line_num} lines, found {total_cves} CVEs for {year}")
        
        # Prepare CVSS data organized by version
        cvss_severity_data = {}
        for version, data in cvss_data.items():
            if data['total'] > 0:  # Only include versions with data
                cvss_severity_data[version] = {
                    'total': data['total'],
                    'severity_distribution': dict(data['severity_counts'].most_common())
                }
        
        # Prepare daily publication analysis
        # Create complete daily array with zero-filling for missing dates
        complete_daily_counts = self.create_complete_daily_array(daily_counts, year)
        
        # Prepare daily analysis with high/low day tracking
        if complete_daily_counts:
            # Only consider days with actual CVE publications for stats
            non_zero_days = {k: v for k, v in complete_daily_counts.items() if v > 0}
            if non_zero_days:
                daily_values = list(non_zero_days.values())
                daily_analysis = {
                    'total_days': len(non_zero_days),
                    'avg_per_day': round(sum(daily_values) / len(daily_values), 2),
                    'highest_day': {
                        'date': max(non_zero_days, key=non_zero_days.get),
                        'count': max(daily_values)
                    },
                    'lowest_day': {
                        'date': min(non_zero_days, key=non_zero_days.get),
                        'count': min(daily_values)
                    },
                    'daily_counts': complete_daily_counts  # Include all days with zeros
                }
            else:
                daily_analysis = {
                    'total_days': 0,
                    'avg_per_day': 0,
                    'highest_day': {'date': '', 'count': 0},
                    'lowest_day': {'date': '', 'count': 0},
                    'daily_counts': complete_daily_counts
                }
        else:
            daily_analysis = {
                'total_days': 0,
                'avg_per_day': 0,
                'highest_day': {'date': '', 'count': 0},
                'lowest_day': {'date': '', 'count': 0},
                'daily_counts': {}
            }
        
        # Prepare structured data with logical organization
        year_data = {
            # Basic metadata
            'year': year,
            'total_cves': total_cves,
            
            # Date-based analysis
            'date_data': {
                'monthly_distribution': {
                    str(i+1): monthly_counts[i] for i in range(12)
                },
                'daily_analysis': daily_analysis
            },
            
            # CVSS severity analysis
            'cvss': {
                version: {
                    'total': data['total'],
                    'severity_distribution': dict(data['severity_counts']),
                    'score_distribution': dict(data['score_distribution'])
                }
                for version, data in cvss_data.items()
                if data['total'] > 0  # Only include versions with data
            },
            
            # Vendor analysis (dual tracking)
            'vendors': {
                'cna_assigners': [
                    {'name': vendor, 'count': count}
                    for vendor, count in vendor_counts.most_common(20)
                ],
                'cpe_vendors': [
                    {'name': vendor, 'count': count}
                    for vendor, count in cpe_vendor_counts.most_common(20)
                ]
            },
            
            # Weakness analysis
            'cwe': {
                'top_cwes': [
                    {'cwe': cwe, 'count': count}
                    for cwe, count in cwe_counts.most_common(20)
                ]
            },
            
            # NVD metadata analysis
            'metadata': {
                'vulnerability_status': [
                    {'status': status, 'count': count}
                    for status, count in status_counts.most_common(10)
                ],
                'cve_tags': [
                    {'tag': tag, 'count': count}
                    for tag, count in tag_counts.most_common(10)
                ],
                'reference_tags': [
                    {'tag': tag, 'count': count}
                    for tag, count in reference_tag_counts.most_common(20)
                ]
            },
            
            # Processing information
            'processing_stats': {
                'processed_at': datetime.now().isoformat(),
                'data_source': 'data/cache/nvd.jsonl'
            }
        }
        
        # Cache the result
        self.year_data_cache[year] = year_data
        
        if not self.quiet:
            print(f"  ✅ Found {total_cves} CVEs for {year}")
        return year_data
    
    def get_year_data(self, year):
        """Main method to get processed data for a specific year"""
        current_year = datetime.now().year
        
        if year < 1999 or year > current_year:
            raise ValueError(f"Year {year} is outside valid range (1999-{current_year})")
        
        return self.process_year_data(year)
    
    def get_all_years_data(self):
        """Get data for all available years"""
        current_year = datetime.now().year
        all_data = {}
        
        print(f"📊 Processing all years (1999-{current_year})...")
        
        for year in range(1999, current_year + 1):
            try:
                all_data[year] = self.get_year_data(year)
            except Exception as e:
                print(f"⚠️  Failed to process {year}: {e}")
                # Create empty data structure for failed years
                all_data[year] = {
                    'year': year,
                    'total_cves': 0,
                    'monthly_counts': [0] * 12,
                    'severity_distribution': {},
                    'top_vendors': [],
                    'top_cwes': [],
                    'error': str(e)
                }
        
        return all_data
    
    def generate_summary_stats(self):
        """Generate overall summary statistics"""
        self.ensure_data_loaded()
        
        print("📊 Generating summary statistics...")
        
        total_cves = 0
        year_counts = Counter()
        severity_counts = Counter()
        
        with open(self.data_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                try:
                    cve_data = json.loads(line)
                    cve_id = cve_data.get('cve', {}).get('CVE_data_meta', {}).get('ID', '')
                    
                    if cve_id.startswith('CVE-'):
                        total_cves += 1
                        
                        # Count by year
                        pub_date = self.parse_cve_date(cve_data)
                        if pub_date:
                            year_counts[pub_date.year] += 1
                        else:
                            # Fallback to CVE ID year
                            year = int(cve_id.split('-')[1])
                            year_counts[year] += 1
                        
                        # Count by severity
                        severity_info = self.extract_severity_info(cve_data)
                        severity_counts[severity_info['severity']] += 1
                
                except (json.JSONDecodeError, KeyError, ValueError, IndexError):
                    continue
        
        return {
            'total_cves': total_cves,
            'year_range': (min(year_counts.keys()), max(year_counts.keys())),
            'years_covered': len(year_counts),
            'year_distribution': dict(sorted(year_counts.items())),
            'severity_distribution': dict(severity_counts.most_common()),
            'generated_at': datetime.now().isoformat()
        }

def main():
    """Main entry point for standalone testing"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Analyze CVE data by year")
    parser.add_argument('--year', type=int, help='Analyze specific year')
    parser.add_argument('--summary', action='store_true', help='Generate summary statistics')
    parser.add_argument('--all-years', action='store_true', help='Process all years')
    
    args = parser.parse_args()
    
    analyzer = CVEYearsAnalyzer()
    
    if args.summary:
        stats = analyzer.generate_summary_stats()
        print(json.dumps(stats, indent=2))
    elif args.year:
        year_data = analyzer.get_year_data(args.year)
        print(json.dumps(year_data, indent=2, default=str))
    elif args.all_years:
        all_data = analyzer.get_all_years_data()
        print(f"Processed {len(all_data)} years")
        for year, data in sorted(all_data.items()):
            print(f"  {year}: {data['total_cves']} CVEs")
    else:
        print("Please specify --year, --summary, or --all-years")

if __name__ == '__main__':
    main()
