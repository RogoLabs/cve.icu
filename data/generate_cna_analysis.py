#!/usr/bin/env python3
"""
Comprehensive CNA Analysis Generator
Processes all CVE data to generate complete CNA statistics including ALL active CNAs
"""

import json
import re
from datetime import datetime
from pathlib import Path
from collections import defaultdict, Counter
from download_cve_data import CVEDataDownloader

class ComprehensiveCNAAnalyzer:
    """Generates comprehensive CNA analysis with all active CNAs"""
    
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.downloader = CVEDataDownloader()
        self.data_file = None
        
        # CNA mapping data for proper name resolution
        self.cna_list = {}
        self.cna_name_map = {}
        
        print("🏢 Comprehensive CNA Analyzer Initialized")
        print("📊 Will process ALL CVE data to find every active CNA")
    
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
                    
                    # Handle different data structure formats
                    cna_entries = []
                    if isinstance(cna_data, dict) and 'data' in cna_data:
                        cna_entries = cna_data['data']
                    elif isinstance(cna_data, list):
                        cna_entries = cna_data
                    elif isinstance(cna_data, dict):
                        # Sometimes the data is directly in the root
                        cna_entries = [cna_data] if 'sourceIdentifier' in cna_data else []
                    
                    # Convert to lookup dict by sourceIdentifier
                    for cna in cna_entries:
                        if isinstance(cna, dict):
                            source_id = cna.get('sourceIdentifier', '')
                            if source_id:
                                self.cna_list[source_id] = cna
                
                print(f"✅ Loaded {len(self.cna_list)} CNA entries")
            
            # Load CNA name mapping
            cna_name_map_file = self.downloader.cache_dir / "cna_name_map.json"
            if cna_name_map_file.exists():
                with open(cna_name_map_file, 'r', encoding='utf-8') as f:
                    self.cna_name_map = json.load(f)
                print(f"✅ Loaded CNA name mappings for {len(self.cna_name_map)} entries")
                
        except Exception as e:
            print(f"⚠️  Warning: Could not load CNA mappings: {e}")
            print("  📝 Will use raw sourceIdentifier values as fallback")
    
    def resolve_cna_name(self, source_identifier):
        """Resolve CNA sourceIdentifier to proper organization name using comprehensive mapping"""
        try:
            # Handle special cases first
            if source_identifier == '416baaa9-dc9f-4396-8d5f-8c081fb06d67':
                return 'Linux Kernel Organization'
            
            # First try the official UUID-based name mapping file (most authoritative)
            if source_identifier in self.cna_name_map:
                resolved_name = self.cna_name_map[source_identifier]
                print(f"✅ Resolved UUID {source_identifier} to: {resolved_name}")
                return resolved_name
            
            # Create comprehensive domain-to-organization mapping
            domain_mappings = {
                'mitre.org': 'MITRE Corporation',
                'oracle.com': 'Oracle Corporation',
                'adobe.com': 'Adobe Inc.',
                'redhat.com': 'Red Hat, Inc.',
                'microsoft.com': 'Microsoft Corporation',
                'google.com': 'Google LLC',
                'github.com': 'GitHub, Inc.',
                'cisco.com': 'Cisco Systems, Inc.',
                'ibm.com': 'IBM Corporation',
                'apple.com': 'Apple Inc.',
                'intel.com': 'Intel Corporation',
                'mozilla.org': 'Mozilla Foundation',
                'canonical.com': 'Canonical Ltd.',
                'debian.org': 'Debian Project',
                'apache.org': 'Apache Software Foundation',
                'kernel.org': 'Linux Kernel Organization',
                'suse.com': 'SUSE LLC',
                'ubuntu.com': 'Canonical Ltd.',
                'fedoraproject.org': 'Red Hat, Inc.',
                'centos.org': 'Red Hat, Inc.',
                'php.net': 'PHP Group',
                'python.org': 'Python Software Foundation',
                'nodejs.org': 'Node.js Foundation',
                'ruby-lang.org': 'Ruby Association',
                'perl.org': 'Perl Foundation',
                'golang.org': 'Google LLC',
                'rust-lang.org': 'Rust Foundation',
                'jenkins.io': 'Jenkins Project',
                'docker.com': 'Docker Inc.',
                'kubernetes.io': 'Cloud Native Computing Foundation',
                'openssl.org': 'OpenSSL Software Foundation',
                'nginx.org': 'Nginx Inc.',
                'apache.org': 'Apache Software Foundation',
                'eclipse.org': 'Eclipse Foundation',
                'qt.io': 'The Qt Company',
                'gnome.org': 'GNOME Foundation',
                'kde.org': 'KDE e.V.',
                'freedesktop.org': 'freedesktop.org',
                'x.org': 'X.Org Foundation',
                'videolan.org': 'VideoLAN',
                'ffmpeg.org': 'FFmpeg Project',
                'imagemagick.org': 'ImageMagick Studio LLC',
                'gimp.org': 'GIMP Team',
                'blender.org': 'Blender Foundation',
                'libreoffice.org': 'The Document Foundation',
                'wordpress.org': 'WordPress Foundation',
                'drupal.org': 'Drupal Association',
                'joomla.org': 'Open Source Matters',
                'magento.com': 'Adobe Inc.',
                'shopify.com': 'Shopify Inc.',
                'salesforce.com': 'Salesforce.com, Inc.',
                'atlassian.com': 'Atlassian Corporation',
                'jetbrains.com': 'JetBrains s.r.o.',
                'vmware.com': 'VMware, Inc.',
                'citrix.com': 'Citrix Systems, Inc.',
                'hp.com': 'HP Inc.',
                'dell.com': 'Dell Technologies Inc.',
                'lenovo.com': 'Lenovo Group Limited',
                'asus.com': 'ASUSTeK Computer Inc.',
                'acer.com': 'Acer Inc.',
                'samsung.com': 'Samsung Electronics Co., Ltd.',
                'lg.com': 'LG Electronics Inc.',
                'sony.com': 'Sony Corporation',
                'panasonic.com': 'Panasonic Corporation',
                'toshiba.com': 'Toshiba Corporation',
                'fujitsu.com': 'Fujitsu Limited',
                'hitachi.com': 'Hitachi, Ltd.',
                'nec.com': 'NEC Corporation',
                'huawei.com': 'Huawei Technologies Co., Ltd.',
                'xiaomi.com': 'Xiaomi Inc.',
                'oppo.com': 'OPPO Electronics Corp.',
                'vivo.com': 'Vivo Communication Technology Co. Ltd.',
                'oneplus.com': 'OnePlus Technology (Shenzhen) Co., Ltd.',
                'realme.com': 'Realme Chongqing Mobile Telecommunications Corp., Ltd.',
                'qualcomm.com': 'QUALCOMM Incorporated',
                'mediatek.com': 'MediaTek Inc.',
                'broadcom.com': 'Broadcom Inc.',
                'marvell.com': 'Marvell Technology Group Ltd.',
                'nvidia.com': 'NVIDIA Corporation',
                'amd.com': 'Advanced Micro Devices, Inc.',
                'arm.com': 'Arm Limited',
                'xilinx.com': 'Xilinx, Inc.',
                'altera.com': 'Intel Corporation',
                'ti.com': 'Texas Instruments Incorporated',
                'analog.com': 'Analog Devices, Inc.',
                'maxim-ic.com': 'Maxim Integrated Products, Inc.',
                'microchip.com': 'Microchip Technology Inc.',
                'st.com': 'STMicroelectronics N.V.',
                'nxp.com': 'NXP Semiconductors N.V.',
                'infineon.com': 'Infineon Technologies AG',
                'renesas.com': 'Renesas Electronics Corporation',
                'rohm.com': 'ROHM Co., Ltd.',
                'onsemi.com': 'ON Semiconductor Corporation',
                'cypress.com': 'Cypress Semiconductor Corporation',
                'lattice.com': 'Lattice Semiconductor Corporation',
                'microsemi.com': 'Microsemi Corporation',
                'actel.com': 'Microsemi Corporation',
                'patchstack.com': 'patchstack.com',
                'vuldb.com': 'vuldb.com',
                'wordfence.com': 'wordfence.com',
                'wpscan.com': 'wpscan.com',
                'trendmicro.com': 'trendmicro.com',
                'huntr.dev': 'huntr.dev',
                'snyk.io': 'snyk.io',
                'bress.net': 'bress.net',
                'flexerasoftware.com': 'flexerasoftware.com',
                'hpe.com': 'hpe.com',
                'incibe.es': 'incibe.es',
                'sap.com': 'sap.com',
                'unisoc.com': 'unisoc.com',
                'freebsd.org': 'freebsd.org',
                'netbsd.org': 'NetBSD Foundation',
                'openbsd.org': 'OpenBSD Project',
                'dragonflybsd.org': 'DragonFly BSD Project',
                'gentoo.org': 'Gentoo Foundation',
                'archlinux.org': 'Arch Linux',
                'slackware.com': 'Slackware Linux, Inc.',
                'opensuse.org': 'openSUSE Project',
                'mandriva.com': 'Mandriva S.A.',
                'mageia.org': 'Mageia.Org',
                'pclinuxos.com': 'PCLinuxOS',
                'puppy.com': 'Puppy Linux',
                'tinycore.net': 'Tiny Core Linux',
                'alpinelinux.org': 'Alpine Linux',
                'voidlinux.org': 'Void Linux',
                'nixos.org': 'NixOS Foundation',
                'guix.gnu.org': 'GNU Project'
            }
            
            # Try domain mapping for email-like identifiers
            if '@' in source_identifier:
                domain = source_identifier.split('@')[-1].lower()
                if domain in domain_mappings:
                    return domain_mappings[domain]
                else:
                    # Return cleaned domain name
                    return domain
            
            # Try direct domain lookup
            if source_identifier.lower() in domain_mappings:
                return domain_mappings[source_identifier.lower()]
            
            # For other formats, try to extract meaningful name
            if '.' in source_identifier:
                # Looks like a domain
                domain = source_identifier.lower()
                if domain in domain_mappings:
                    return domain_mappings[domain]
                else:
                    return source_identifier
            
            # If it looks like a UUID but wasn't found in mapping, keep as-is for now
            if len(source_identifier) == 36 and source_identifier.count('-') == 4:
                print(f"⚠️  Warning: UUID {source_identifier} not found in official mapping")
                return source_identifier
            
            # Return as-is if no mapping found
            return source_identifier
            
        except Exception as e:
            print(f"⚠️  Warning: Error resolving CNA name for '{source_identifier}': {e}")
            return source_identifier
    
    def generate_comprehensive_cna_analysis(self):
        """Generate comprehensive CNA analysis with ALL active CNAs"""
        self.ensure_data_loaded()
        
        print("🏢 Generating comprehensive CNA analysis...")
        print("📊 Processing all CVE data to find every active CNA...")
        
        # Track all CNAs and their statistics
        cna_stats = defaultdict(lambda: {
            'count': 0,
            'years_active': set(),
            'first_cve': None,
            'last_cve': None,
            'severity_distribution': Counter(),
            'cwe_types': Counter()
        })
        
        total_cves_processed = 0
        cves_with_cna = 0
        
        print("📂 Loading JSON array from file...")
        try:
            with open(self.data_file, 'r', encoding='utf-8') as f:
                cve_array = json.load(f)
            
            if not isinstance(cve_array, list):
                raise ValueError(f"Expected JSON array, got {type(cve_array)}")
            
            print(f"✅ Loaded JSON array with {len(cve_array):,} entries")
            
        except Exception as e:
            print(f"❌ Error loading JSON array: {e}")
            return {}
        
        # Process each CVE entry in the array
        for entry_num, cve_data in enumerate(cve_array, 1):
            try:
                # Skip if data is not a dictionary
                if not isinstance(cve_data, dict):
                    continue
                
                # Extract CVE ID with robust error handling
                cve_id = ''
                try:
                    cve_section = cve_data.get('cve', {})
                    if isinstance(cve_section, dict):
                        cve_meta = cve_section.get('CVE_data_meta', {})
                        if isinstance(cve_meta, dict):
                            cve_id = cve_meta.get('ID', '')
                except (AttributeError, TypeError):
                    continue
                
                if not cve_id or not cve_id.startswith('CVE-'):
                    continue
                
                total_cves_processed += 1
                
                # Extract CNA information
                source_identifier = cve_data.get('cve', {}).get('sourceIdentifier', '')
                if source_identifier:
                    cves_with_cna += 1
                    
                    # Resolve CNA name
                    cna_name = self.resolve_cna_name(source_identifier)
                    
                    # Update CNA statistics
                    cna_stats[cna_name]['count'] += 1
                    
                    # Extract year from CVE ID or publication date
                    try:
                        # Try to get publication date first
                        pub_date = None
                        date_fields = [
                            ['publishedDate'],
                            ['lastModifiedDate'],
                            ['cve', 'published'],
                            ['cve', 'lastModified']
                        ]
                        
                        for field_path in date_fields:
                            try:
                                value = cve_data
                                for field in field_path:
                                    value = value[field]
                                if value:
                                    if isinstance(value, str):
                                        if 'T' in value:
                                            pub_date = datetime.fromisoformat(value.replace('Z', '+00:00'))
                                            break
                            except (KeyError, TypeError, ValueError):
                                continue
                        
                        # Fallback to CVE ID year
                        if not pub_date:
                            year = int(cve_id.split('-')[1])
                            pub_date = datetime(year, 1, 1)
                        
                        cna_stats[cna_name]['years_active'].add(pub_date.year)
                        
                        # Track first and last CVE dates
                        if not cna_stats[cna_name]['first_cve'] or pub_date < cna_stats[cna_name]['first_cve']:
                            cna_stats[cna_name]['first_cve'] = pub_date
                        if not cna_stats[cna_name]['last_cve'] or pub_date > cna_stats[cna_name]['last_cve']:
                            cna_stats[cna_name]['last_cve'] = pub_date
                    
                    except (ValueError, IndexError):
                        pass
                    
                    # Extract severity information
                    try:
                        metrics = cve_data.get('cve', {}).get('metrics', {})
                        severity = 'UNKNOWN'
                        
                        # Try different CVSS versions
                        for version_key in ['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                            if version_key in metrics:
                                cvss_metrics = metrics[version_key]
                                if isinstance(cvss_metrics, list) and len(cvss_metrics) > 0:
                                    if version_key == 'cvssMetricV2':
                                        severity = cvss_metrics[0].get('baseSeverity', 'UNKNOWN')
                                    else:
                                        cvss_data = cvss_metrics[0].get('cvssData', {})
                                        severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                                    break
                        
                        cna_stats[cna_name]['severity_distribution'][severity] += 1
                    except Exception:
                        cna_stats[cna_name]['severity_distribution']['UNKNOWN'] += 1
                    
                    # Extract CWE information
                    try:
                        weaknesses = cve_data.get('cve', {}).get('weaknesses', [])
                        for weakness in weaknesses:
                            descriptions = weakness.get('description', [])
                            for desc in descriptions:
                                if desc.get('lang') == 'en':
                                    cwe_value = desc.get('value', '')
                                    if cwe_value and cwe_value.startswith('CWE-') and 'Missing_' not in cwe_value:
                                        cna_stats[cna_name]['cwe_types'][cwe_value] += 1
                    except Exception:
                        pass
                    
                # Progress indicator
                if entry_num % 10000 == 0 and entry_num > 0 and not self.quiet:
                    print(f"  📊 Processed {entry_num:,} entries, found {len(cna_stats)} unique CNAs so far...")
            
            except (KeyError, ValueError, TypeError) as e:
                continue
        
        print(f"✅ Processing complete!")
        print(f"📊 Total CVEs processed: {total_cves_processed:,}")
        print(f"🏢 CVEs with CNA information: {cves_with_cna:,}")
        print(f"🎯 Unique CNAs found: {len(cna_stats):,}")
        
        # Convert to final format with activity status
        current_date = datetime.now()
        twelve_months_ago = current_date.replace(year=current_date.year - 1)
        
        cna_list = []
        active_cnas = 0
        inactive_cnas = 0
        
        for cna_name, stats in cna_stats.items():
            # Determine activity status based on last CVE publication
            is_active = stats['last_cve'] and stats['last_cve'] >= twelve_months_ago
            if is_active:
                active_cnas += 1
            else:
                inactive_cnas += 1
            
            cna_entry = {
                'name': cna_name,
                'count': stats['count'],
                'years_active': len(stats['years_active']),
                'first_cve_year': stats['first_cve'].year if stats['first_cve'] else None,
                'last_cve_year': stats['last_cve'].year if stats['last_cve'] else None,
                'last_cve_date': stats['last_cve'].isoformat() if stats['last_cve'] else None,
                'days_since_last_cve': (current_date - stats['last_cve']).days if stats['last_cve'] else None,
                'activity_status': 'Active' if is_active else 'Inactive',
                'activity_level': self.categorize_activity_level(stats['count']),
                'top_severities': dict(stats['severity_distribution'].most_common(3)),
                'top_cwes': dict(stats['cwe_types'].most_common(5))
            }
            cna_list.append(cna_entry)
        
        # Sort by CVE count (descending)
        cna_list.sort(key=lambda x: x['count'], reverse=True)
        
        # Generate analysis
        total_cves = sum(stats['count'] for stats in cna_stats.values())
        
        analysis = {
            'top_cna_assigners_all_time': [
                {'name': cna['name'], 'count': cna['count']} 
                for cna in cna_list
            ],
            'active_cna_assigners': [
                {'name': cna['name'], 'count': cna['count'], 'last_cve_date': cna['last_cve_date']} 
                for cna in cna_list if cna['activity_status'] == 'Active'
            ],
            'detailed_cna_stats': cna_list,
            'summary_statistics': {
                'total_unique_cnas': len(cna_list),
                'active_cnas': active_cnas,
                'inactive_cnas': inactive_cnas,
                'activity_rate': round(active_cnas / len(cna_list) * 100, 1) if cna_list else 0,
                'total_cves_assigned': total_cves,
                'cves_by_active_cnas': sum(cna['count'] for cna in cna_list if cna['activity_status'] == 'Active'),
                'average_cves_per_cna': round(total_cves / len(cna_list)) if cna_list else 0,
                'average_cves_per_active_cna': round(sum(cna['count'] for cna in cna_list if cna['activity_status'] == 'Active') / active_cnas) if active_cnas > 0 else 0,
                'top_10_share': sum(cna['count'] for cna in cna_list[:10]) / total_cves * 100 if total_cves > 0 else 0,
                'activity_distribution': self.get_activity_distribution(cna_list),
                'status_distribution': self.get_status_distribution(cna_list),
                'coverage_years': self.get_coverage_years(cna_list),
                'activity_threshold_date': twelve_months_ago.isoformat()
            },
            'processing_stats': {
                'processed_at': datetime.now().isoformat(),
                'total_cves_processed': total_cves_processed,
                'cves_with_cna_info': cves_with_cna,
                'data_source': 'comprehensive_nvd_jsonl_analysis'
            }
        }
        
        return analysis
    
    def categorize_activity_level(self, count):
        """Categorize CNA activity level based on CVE count"""
        if count >= 10000:
            return 'Very High'
        elif count >= 1000:
            return 'High'
        elif count >= 100:
            return 'Medium'
        elif count >= 10:
            return 'Low'
        else:
            return 'Minimal'
    
    def get_activity_distribution(self, cna_list):
        """Get distribution of CNAs by activity level"""
        distribution = Counter()
        for cna in cna_list:
            distribution[cna['activity_level']] += 1
        return dict(distribution)
    
    def get_status_distribution(self, cna_list):
        """Get distribution of CNAs by activity status"""
        distribution = Counter()
        for cna in cna_list:
            distribution[cna['activity_status']] += 1
        return dict(distribution)
    
    def get_coverage_years(self, cna_list):
        """Get coverage years with safe handling of empty data"""
        try:
            # Get all valid first and last CVE years
            first_years = [cna['first_cve_year'] for cna in cna_list if cna['first_cve_year'] is not None]
            last_years = [cna['last_cve_year'] for cna in cna_list if cna['last_cve_year'] is not None]
            
            if first_years and last_years:
                return {
                    'earliest': min(first_years),
                    'latest': max(last_years)
                }
            else:
                # Fallback if no valid years found
                current_year = datetime.now().year
                return {
                    'earliest': 1999,  # CVE program started in 1999
                    'latest': current_year
                }
        except Exception as e:
            print(f"⚠️  Warning: Error calculating coverage years: {e}")
            current_year = datetime.now().year
            return {
                'earliest': 1999,
                'latest': current_year
            }
    
    def save_analysis(self, analysis, output_file):
        """Save analysis to JSON file"""
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(analysis, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Comprehensive CNA analysis saved to: {output_path}")
        print(f"📊 Found {analysis['summary_statistics']['total_unique_cnas']:,} unique CNAs")
        print(f"🎯 Total CVEs assigned: {analysis['summary_statistics']['total_cves_assigned']:,}")

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate comprehensive CNA analysis")
    parser.add_argument('--output', '-o', 
                       default='../web/data/cna_analysis.json',
                       help='Output file path (default: ../web/data/cna_analysis.json)')
    
    args = parser.parse_args()
    
    analyzer = ComprehensiveCNAAnalyzer()
    analysis = analyzer.generate_comprehensive_cna_analysis()
    analyzer.save_analysis(analysis, args.output)

if __name__ == '__main__':
    main()
