#!/usr/bin/env python3
"""
CNA Analysis Module
Handles all CNA (CVE Numbering Authority) related data processing and analysis
"""

import json
from pathlib import Path
from datetime import datetime


class CNAAnalyzer:
    """Handles CNA-specific analysis and data processing"""
    
    def __init__(self, base_dir, cache_dir, data_dir):
        self.base_dir = Path(base_dir)
        self.cache_dir = Path(cache_dir)
        self.data_dir = Path(data_dir)
        self.current_year = datetime.now().year
        
    def load_cna_name_mappings(self):
        """Load CNA name mappings for UUID resolution"""
        print(f"    🗺️ Loading CNA name mappings...")
        mappings = {}
        
        # Load from cna_name_map.json (UUID to name mappings)
        cna_name_map_file = self.cache_dir / 'cna_name_map.json'
        if cna_name_map_file.exists():
            try:
                with open(cna_name_map_file, 'r') as f:
                    data = json.load(f)
                    
                # Handle different data structures
                if isinstance(data, dict) and 'data' in data:
                    # Structure: {"data": [...]}
                    for entry in data['data']:
                        if isinstance(entry, dict) and 'uuid' in entry and 'name' in entry:
                            mappings[entry['uuid']] = entry['name']
                elif isinstance(data, list):
                    # Structure: [{"uuid": "...", "name": "..."}, ...]
                    for entry in data:
                        if isinstance(entry, dict) and 'uuid' in entry and 'name' in entry:
                            mappings[entry['uuid']] = entry['name']
                elif isinstance(data, dict):
                    # Direct UUID to name mapping
                    mappings.update(data)
                    
                print(f"    ✅ Loaded {len(mappings)} UUID mappings from cna_name_map.json")
            except Exception as e:
                print(f"    ⚠️ Error loading cna_name_map.json: {e}")
        
        return mappings
    
    def load_official_cna_list(self):
        """Load official CNA list for comprehensive analysis"""
        print(f"    📋 Loading official CNA list...")
        official_cnas = []
        
        cna_list_file = self.cache_dir / 'cna_list.json'
        if cna_list_file.exists():
            try:
                with open(cna_list_file, 'r') as f:
                    data = json.load(f)
                    
                # Handle different data structures
                if isinstance(data, dict) and 'data' in data:
                    official_cnas = data['data']
                elif isinstance(data, list):
                    official_cnas = data
                    
                print(f"    ✅ Loaded {len(official_cnas)} official CNAs from cna_list.json")
            except Exception as e:
                print(f"    ⚠️ Error loading cna_list.json: {e}")
        
        return official_cnas
    
    def resolve_cna_name(self, source_identifier, mappings):
        """Resolve CNA name from source identifier using various methods"""
        if not source_identifier:
            return 'Unknown'
        
        # Check UUID mapping first
        if source_identifier in mappings:
            return mappings[source_identifier]
        
        # Domain-based mappings
        domain_mappings = {
            'mitre.org': 'MITRE Corporation',
            'cve@mitre.org': 'MITRE Corporation',
            'patchstack.com': 'Patchstack',
            'wordfence.com': 'Wordfence',
            'microsoft.com': 'Microsoft Corporation',
            'apple.com': 'Apple Inc.',
            'google.com': 'Google LLC',
            'redhat.com': 'Red Hat Inc.',
            'debian.org': 'Debian',
            'ubuntu.com': 'Canonical Ltd.',
            'suse.com': 'SUSE',
            'oracle.com': 'Oracle Corporation',
            'ibm.com': 'IBM Corporation',
            'cisco.com': 'Cisco Systems Inc.',
            'adobe.com': 'Adobe Inc.',
            'mozilla.org': 'Mozilla Foundation'
        }
        
        # Check domain mappings
        for domain, name in domain_mappings.items():
            if domain in source_identifier.lower():
                return name
        
        # Clean up the identifier for display
        if '@' in source_identifier:
            domain = source_identifier.split('@')[-1]
            return domain.replace('.com', '').replace('.org', '').title()
        
        # Return cleaned identifier
        return source_identifier.replace('_', ' ').title()
    
    def process_cna_type_distribution(self, official_cnas, cna_stats):
        """Process CNA type distribution from official data"""
        print(f"    📊 Processing CNA type distribution...")
        
        type_counts = {}
        type_percentages = {}
        
        # Count types from official CNAs using correct nested structure
        for cna in official_cnas:
            # Use the correct nested path: CNA.type
            cna_types = cna.get('CNA', {}).get('type', [])
            if not isinstance(cna_types, list):
                cna_types = [cna_types] if cna_types else ['Unknown']
            
            for cna_type in cna_types:
                if cna_type and cna_type != 'Unknown':
                    type_counts[cna_type] = type_counts.get(cna_type, 0) + 1
        
        # Calculate percentages
        total_official = len(official_cnas)
        if total_official > 0:
            for cna_type, count in type_counts.items():
                type_percentages[cna_type] = round((count / total_official) * 100, 1)
        
        # Sort by count (descending)
        sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)
        
        return {
            'type_counts': type_counts,
            'type_percentages': type_percentages,
            'sorted_types': sorted_types,
            'total_official_cnas': total_official
        }
    
    def generate_comprehensive_cna_analysis(self, all_year_data):
        """Generate comprehensive CNA analysis processing all CVEs and official CNA data"""
        print(f"  🏢 Generating comprehensive CNA analysis...")
        
        # Load CNA mappings and official data
        mappings = self.load_cna_name_mappings()
        official_cnas = self.load_official_cna_list()
        
        # Process CVE data to extract CNA statistics
        cna_stats = {}
        
        # Load CVE data from cache
        nvd_file = self.cache_dir / 'nvd.jsonl'
        if nvd_file.exists():
            if not self.quiet:
                print(f"    📂 Loading CVE data from {nvd_file}...")
            with open(nvd_file, 'r') as f:
                cve_data = json.load(f)
            
            print(f"    📊 Processing {len(cve_data)} CVEs for comprehensive CNA analysis...")
            
            for i, cve_entry in enumerate(cve_data):
                if i % 50000 == 0 and i > 0 and not self.quiet:
                    print(f"    📊 Processed {i:,} CVEs...")
                
                try:
                    cve_section = cve_entry.get('cve', {})
                    cve_id = cve_section.get('id', '')
                    source_identifier = cve_section.get('sourceIdentifier', '')
                    
                    if source_identifier:
                        cna_name = self.resolve_cna_name(source_identifier, mappings)
                        
                        if cna_name and cna_name != 'Unknown':
                            if cna_name not in cna_stats:
                                cna_stats[cna_name] = {
                                    'count': 0,
                                    'first_cve_date': cve_section.get('published', ''),
                                    'last_cve_date': cve_section.get('published', ''),
                                    'first_cve_year': None,
                                    'last_cve_year': None,
                                    'source_identifier': source_identifier
                                }
                            
                            cna_stats[cna_name]['count'] += 1
                            
                            # Update date tracking
                            pub_date = cve_section.get('published', '')
                            if pub_date:
                                if pub_date < cna_stats[cna_name]['first_cve_date'] or not cna_stats[cna_name]['first_cve_date']:
                                    cna_stats[cna_name]['first_cve_date'] = pub_date
                                if pub_date > cna_stats[cna_name]['last_cve_date']:
                                    cna_stats[cna_name]['last_cve_date'] = pub_date
                                
                                # Extract year from CVE ID
                                if cve_id.startswith('CVE-'):
                                    year = int(cve_id.split('-')[1])
                                    if cna_stats[cna_name]['first_cve_year'] is None or year < cna_stats[cna_name]['first_cve_year']:
                                        cna_stats[cna_name]['first_cve_year'] = year
                                    if cna_stats[cna_name]['last_cve_year'] is None or year > cna_stats[cna_name]['last_cve_year']:
                                        cna_stats[cna_name]['last_cve_year'] = year
                                        
                except Exception as e:
                    continue
            
            if not self.quiet:
                print(f"    ✅ Processed all CVEs, found {len(cna_stats)} CNAs with published CVEs")
        
        # Create comprehensive CNA list with official data integration
        cna_list = []
        official_cna_names = {cna.get('organizationName', '') for cna in official_cnas}
        
        # Process CNAs with published CVEs
        for cna_name, stats in cna_stats.items():
            # Find matching official CNA data
            official_info = None
            for cna in official_cnas:
                if cna.get('organizationName') == cna_name:
                    official_info = cna
                    break
            
            # Calculate years active based on CNA designation year (from cnaID) not CVE publication dates
            years_active = 1
            cna_designation_year = None
            
            # Extract CNA designation year from official CNA data if available
            if official_info and 'cnaID' in official_info:
                cna_id = official_info['cnaID']
                # Extract year from cnaID format like "CNA-2005-0001"
                try:
                    if cna_id.startswith('CNA-') and len(cna_id) >= 8:
                        year_part = cna_id[4:8]  # Extract "2005" from "CNA-2005-0001"
                        if year_part.isdigit():
                            extracted_year = int(year_part)
                            # Validate: CNA program started in 2005, so no CNA can be older
                            if extracted_year >= 2005:
                                cna_designation_year = extracted_year
                                years_active = max(1, self.current_year - cna_designation_year + 1)
                            else:
                                # If cnaID contains pre-2005 year, use 2005 as earliest possible
                                cna_designation_year = 2005
                                years_active = max(1, self.current_year - 2005 + 1)
                except (ValueError, IndexError):
                    pass
            
            # Fallback: if no cnaID available, use CVE publication date range (old method)
            if cna_designation_year is None and stats['first_cve_year'] and stats['last_cve_year']:
                calculated_years = max(1, stats['last_cve_year'] - stats['first_cve_year'] + 1)
                # Validate: No CNA can be older than the CNA program (started 2005)
                # Maximum possible years active = 2025 - 2005 + 1 = 21 years
                years_active = min(calculated_years, 21)
            
            # Calculate days since last CVE
            days_since_last = 0
            if stats['last_cve_date']:
                try:
                    last_date = datetime.fromisoformat(stats['last_cve_date'].replace('Z', '+00:00'))
                    days_since_last = (datetime.now() - last_date.replace(tzinfo=None)).days
                except:
                    days_since_last = 365  # Default to inactive if date parsing fails
            
            # Determine activity status
            activity_status = 'Active' if days_since_last < 365 else 'Inactive'
            
            cna_entry = {
                'name': cna_name,
                'count': stats['count'],
                'years_active': years_active,
                'first_cve_year': stats['first_cve_year'],
                'last_cve_year': stats['last_cve_year'],
                'first_cve_date': stats['first_cve_date'],
                'last_cve_date': stats['last_cve_date'],
                'days_since_last_cve': days_since_last,
                'activity_status': activity_status,
                'official_info': official_info,
                'is_official': cna_name in official_cna_names,
                'cna_types': official_info.get('CNA', {}).get('type', ['Unknown']) if official_info else ['Unknown']
            }
            cna_list.append(cna_entry)
        
        # Add official CNAs that don't have published CVEs
        for cna in official_cnas:
            cna_name = cna.get('organizationName', '')
            if cna_name and cna_name not in cna_stats:
                cna_entry = {
                    'name': cna_name,
                    'count': 0,
                    'years_active': 0,
                    'first_cve_year': None,
                    'last_cve_year': None,
                    'first_cve_date': '',
                    'last_cve_date': '',
                    'days_since_last_cve': 999999,  # Very high number for never published
                    'activity_status': 'Never Published',
                    'official_info': cna,
                    'is_official': True,
                    'cna_types': cna.get('CNA', {}).get('type', ['Unknown'])
                }
                cna_list.append(cna_entry)
        
        # Sort by CVE count (descending)
        cna_list.sort(key=lambda x: x['count'], reverse=True)
        
        # Process type distribution
        type_distribution = self.process_cna_type_distribution(official_cnas, cna_stats)
        
        # Create comprehensive analysis structure
        analysis_data = {
            'generated_at': datetime.now().isoformat(),
            'total_cnas': len(cna_list),
            'active_cnas': len([c for c in cna_list if c['activity_status'] == 'Active']),
            'inactive_cnas': len([c for c in cna_list if c['activity_status'] == 'Inactive']),
            'never_published_cnas': len([c for c in cna_list if c['activity_status'] == 'Never Published']),
            'official_cnas': len([c for c in cna_list if c['is_official']]),
            'unofficial_cnas': len([c for c in cna_list if not c['is_official']]),
            'cna_list': cna_list,
            'type_distribution': type_distribution
        }
        
        # Save to file
        output_file = self.data_dir / 'cna_analysis.json'
        with open(output_file, 'w') as f:
            json.dump(analysis_data, f, indent=2)
        
        print(f"  ✅ Generated comprehensive CNA analysis with {len(cna_list)} CNAs")
        return analysis_data
    
    def generate_current_year_cna_analysis(self, current_year_data):
        """Generate current year CNA analysis by filtering comprehensive analysis for current year CVEs"""
        print(f"    🏢 Generating current year CNA analysis for {self.current_year}...")
        
        # Load comprehensive CNA analysis first to get all CNA data
        comprehensive_file = self.data_dir / 'cna_analysis.json'
        comprehensive_data = {}
        
        if comprehensive_file.exists():
            with open(comprehensive_file, 'r') as f:
                comprehensive_data = json.load(f)
            print(f"    ✅ Loaded comprehensive CNA analysis with {len(comprehensive_data.get('cna_list', []))} CNAs")
        else:
            print(f"    ⚠️ No comprehensive CNA analysis found, generating from scratch...")
            # Generate comprehensive analysis if it doesn't exist
            comprehensive_data = self.generate_comprehensive_cna_analysis({})
        
        # Filter comprehensive data for current year CNAs
        current_year_cnas = []
        cna_counts = {}
        
        # Process all CNAs from comprehensive analysis
        for cna in comprehensive_data.get('cna_list', []):
            cna_name = cna.get('name', '')
            last_cve_year = cna.get('last_cve_year', 0)
            
            # Include CNAs that published CVEs in current year
            if last_cve_year == self.current_year:
                # Create current year CNA entry
                current_year_cna = {
                    'name': cna_name,
                    'count': 0,  # We'll calculate this from the raw data if available
                    'rank': len(current_year_cnas) + 1,
                    'years_active': cna.get('years_active', 1),
                    'first_cve_year': cna.get('first_cve_year', self.current_year),
                    'last_cve_year': self.current_year,
                    'first_cve_date': cna.get('first_cve_date', f'{self.current_year}-01-01T00:00:00'),
                    'last_cve_date': cna.get('last_cve_date', f'{self.current_year}-12-31T23:59:59'),
                    'days_since_last_cve': 0,  # Active in current year
                    'activity_status': 'Active',
                    'severity_distribution': cna.get('severity_distribution', {}),
                    'top_cwe_types': cna.get('top_cwe_types', {}),
                    'official_info': cna.get('official_info'),
                    'is_official': cna.get('is_official', True),
                    'cna_types': cna.get('cna_types', ['Unknown'])
                }
                current_year_cnas.append(current_year_cna)
                cna_counts[cna_name] = current_year_cna['count']
        
        # If we have access to raw CVE data for current year, get actual counts
        nvd_file = self.cache_dir / 'nvd.jsonl'
        if nvd_file.exists() and len(current_year_cnas) > 0:
            print(f"    📊 Calculating actual CVE counts for {self.current_year}...")
            try:
                with open(nvd_file, 'r') as f:
                    cve_data = json.load(f)
                
                # Count current year CVEs by CNA
                mappings = self.load_cna_name_mappings()
                actual_counts = {}
                
                for cve_entry in cve_data:
                    try:
                        cve_section = cve_entry.get('cve', {})
                        cve_id = cve_section.get('id', '')
                        
                        if cve_id.startswith(f'CVE-{self.current_year}-'):
                            source_identifier = cve_section.get('sourceIdentifier', '')
                            if source_identifier:
                                cna_name = self.resolve_cna_name(source_identifier, mappings)
                                if cna_name:
                                    actual_counts[cna_name] = actual_counts.get(cna_name, 0) + 1
                    except:
                        continue
                
                # Update counts in current year CNAs
                for cna in current_year_cnas:
                    cna_name = cna['name']
                    if cna_name in actual_counts:
                        cna['count'] = actual_counts[cna_name]
                
                print(f"    ✅ Updated actual CVE counts for {len(actual_counts)} CNAs")
                
            except Exception as e:
                print(f"    ⚠️ Could not calculate actual counts: {e}")
        
        # Sort by count (descending)
        current_year_cnas.sort(key=lambda x: x['count'], reverse=True)
        
        # Update ranks
        for i, cna in enumerate(current_year_cnas):
            cna['rank'] = i + 1
        
        print(f"    ✅ Found {len(current_year_cnas)} CNAs active in {self.current_year}")
        
        # Calculate type distribution for current year
        type_distribution = self._calculate_type_distribution_for_current_year(current_year_cnas)
        
        # Create comprehensive current year data structure with both cna_list and cna_assigners for compatibility
        current_year_cna_data = {
            'generated_at': datetime.now().isoformat(),
            'year': self.current_year,
            'total_cnas': len(current_year_cnas),
            'active_cnas': len(current_year_cnas),  # All are active in current year
            'inactive_cnas': 0,
            'never_published_cnas': 0,
            'official_cnas': len([c for c in current_year_cnas if c.get('is_official', True)]),
            'unofficial_cnas': len([c for c in current_year_cnas if not c.get('is_official', True)]),
            'cna_list': current_year_cnas,  # For consistency with all-time data
            'cna_assigners': current_year_cnas,  # For JavaScript compatibility
            'type_distribution': type_distribution
        }
        
        # Save current year analysis
        current_year_file = self.data_dir / 'cna_analysis_current_year.json'
        with open(current_year_file, 'w') as f:
            json.dump(current_year_cna_data, f, indent=2)
        
        print(f"    📄 Generated enhanced cna_analysis_current_year.json with {len(current_year_cnas)} CNAs")
        return current_year_cna_data
    
    def _calculate_type_distribution_for_current_year(self, cna_assigners):
        """Calculate CNA type distribution for current year data"""
        type_counts = {}
        type_percentages = {}
        
        # Count types from current year CNAs
        for cna in cna_assigners:
            cna_types = cna.get('cna_types', ['Unknown'])
            if not isinstance(cna_types, list):
                cna_types = [cna_types] if cna_types else ['Unknown']
            
            for cna_type in cna_types:
                if cna_type:
                    type_counts[cna_type] = type_counts.get(cna_type, 0) + 1
        
        # Calculate percentages
        total_cnas = len(cna_assigners)
        if total_cnas > 0:
            for cna_type, count in type_counts.items():
                type_percentages[cna_type] = round((count / total_cnas) * 100, 1)
        
        # Sort by count (descending)
        sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)
        
        return {
            'type_counts': type_counts,
            'type_percentages': type_percentages,
            'sorted_types': sorted_types,
            'total_official_cnas': total_cnas
        }
