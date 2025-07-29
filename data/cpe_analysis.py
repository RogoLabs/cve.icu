#!/usr/bin/env python3
"""
CPE Analysis Module
Handles all CPE (Common Platform Enumeration) related data processing and analysis
"""

import json
from pathlib import Path
from datetime import datetime
from collections import defaultdict, Counter


class CPEAnalyzer:
    """Handles CPE-specific analysis and data processing"""
    
    def __init__(self, base_dir, cache_dir, data_dir, quiet=False):
        self.quiet = quiet
        self.base_dir = Path(base_dir)
        self.cache_dir = Path(cache_dir)
        self.data_dir = Path(data_dir)
        self.current_year = datetime.now().year
    
    def extract_cpe_vendor(self, cpe_string):
        """Extract vendor from CPE string (cpe:2.3:a:vendor:product:...)"""
        try:
            parts = cpe_string.split(':')
            if len(parts) >= 4:
                return parts[3]  # vendor is at index 3
            return 'unknown'
        except:
            return 'unknown'
    
    def extract_cpe_product(self, cpe_string):
        """Extract product from CPE string (cpe:2.3:a:vendor:product:...)"""
        try:
            parts = cpe_string.split(':')
            if len(parts) >= 5:
                return parts[4]  # product is at index 4
            return 'unknown'
        except:
            return 'unknown'
    
    def extract_cpe_type(self, cpe_string):
        """Extract CPE type from CPE string (a=application, o=operating_system, h=hardware)"""
        try:
            parts = cpe_string.split(':')
            if len(parts) >= 3:
                cpe_type = parts[2]
                type_map = {
                    'a': 'Application',
                    'o': 'Operating System', 
                    'h': 'Hardware'
                }
                return type_map.get(cpe_type, 'Unknown')
            return 'Unknown'
        except:
            return 'Unknown'
    
    def generate_cpe_analysis(self, all_year_data):
        """Generate CPE analysis across all years"""
        if not self.quiet:
            print(f"  🔍 Generating CPE analysis...")
        
        # Process raw CVE data to extract CPE information
        cpe_data = self._process_cpe_data_from_cache()
        
        if not cpe_data:
            print("  ⚠️  No CPE data found, generating minimal analysis")
            return self._generate_minimal_cpe_analysis()
        
        # Analyze CPE patterns
        cpe_counts = Counter(cpe_data['cpe_list'])
        vendor_counts = Counter(cpe_data['vendor_list'])
        product_counts = Counter(cpe_data['product_list'])
        type_counts = Counter(cpe_data['type_list'])
        
        # Get top CPEs
        top_cpes = []
        for cpe, count in cpe_counts.most_common(50):
            vendor = self.extract_cpe_vendor(cpe)
            product = self.extract_cpe_product(cpe)
            cpe_type = self.extract_cpe_type(cpe)
            
            top_cpes.append({
                'cpe': cpe,
                'count': count,
                'vendor': vendor,
                'product': product,
                'type': cpe_type
            })
        
        # Get top vendors
        top_vendors = [{'vendor': vendor, 'count': count} 
                      for vendor, count in vendor_counts.most_common(20)]
        
        # Get top products
        top_products = [{'product': product, 'count': count} 
                       for product, count in product_counts.most_common(20)]
        
        # CPE type distribution
        cpe_type_distribution = [{'type': cpe_type, 'count': count, 'percentage': round(count / len(cpe_data['type_list']) * 100, 1)} 
                                for cpe_type, count in type_counts.most_common()]
        
        # Calculate CVEs with most CPEs
        cve_cpe_counts = Counter(cpe_data['cve_list'])
        cves_with_most_cpes = []
        for cve, cpe_count in cve_cpe_counts.most_common(20):
            cves_with_most_cpes.append({
                'cve': cve,
                'cpe_count': cpe_count
            })
        
        cpe_analysis = {
            'generated_at': datetime.now().isoformat(),
            'total_unique_cpes': len(cpe_counts),
            'total_cpe_entries': len(cpe_data['cpe_list']),
            'total_cves_with_cpes': len(set(cpe_data['cve_list'])),
            'total_unique_vendors': len(vendor_counts),
            'total_unique_products': len(product_counts),
            'top_cpes': top_cpes,
            'top_vendors': top_vendors,
            'top_products': top_products,
            'cpe_type_distribution': cpe_type_distribution,
            'cves_with_most_cpes': cves_with_most_cpes,
            'average_cpes_per_cve': round(len(cpe_data['cpe_list']) / len(set(cpe_data['cve_list'])), 1) if cpe_data['cve_list'] else 0
        }
        
        # Save to file
        output_file = self.data_dir / 'cpe_analysis.json'
        with open(output_file, 'w') as f:
            json.dump(cpe_analysis, f, indent=2)
        
        print(f"  ✅ Generated CPE analysis with {len(cpe_counts):,} unique CPEs")
        return cpe_analysis
    
    def generate_current_year_cpe_analysis(self, current_year_data):
        """Generate current year CPE analysis"""
        print(f"    🔍 Generating current year CPE analysis...")
        
        # Process current year CPE data from cache
        current_year_cpe_data = self._process_current_year_cpe_data()
        
        if not current_year_cpe_data:
            print(f"    ⚠️  No CPE data found for {self.current_year}")
            return {}
        
        # Analyze current year CPE patterns
        cpe_counts = Counter(current_year_cpe_data['cpe_list'])
        vendor_counts = Counter(current_year_cpe_data['vendor_list'])
        product_counts = Counter(current_year_cpe_data['product_list'])
        type_counts = Counter(current_year_cpe_data['type_list'])
        
        # Get top CPEs for current year
        top_cpes = []
        for cpe, count in cpe_counts.most_common(30):
            vendor = self.extract_cpe_vendor(cpe)
            product = self.extract_cpe_product(cpe)
            cpe_type = self.extract_cpe_type(cpe)
            
            top_cpes.append({
                'cpe': cpe,
                'count': count,
                'vendor': vendor,
                'product': product,
                'type': cpe_type
            })
        
        # Get top vendors for current year
        top_vendors = [{'vendor': vendor, 'count': count} 
                      for vendor, count in vendor_counts.most_common(15)]
        
        # Get top products for current year
        top_products = [{'product': product, 'count': count} 
                       for product, count in product_counts.most_common(15)]
        
        # CPE type distribution for current year
        cpe_type_distribution = [{'type': cpe_type, 'count': count, 'percentage': round(count / len(current_year_cpe_data['type_list']) * 100, 1)} 
                                for cpe_type, count in type_counts.most_common()]
        
        # Calculate CVEs with most CPEs for current year
        cve_cpe_counts = Counter(current_year_cpe_data['cve_list'])
        cves_with_most_cpes = []
        for cve, cpe_count in cve_cpe_counts.most_common(20):
            cves_with_most_cpes.append({
                'cve': cve,
                'cpe_count': cpe_count
            })
        
        current_year_cpe_analysis = {
            'generated_at': datetime.now().isoformat(),
            'year': self.current_year,
            'total_unique_cpes': len(cpe_counts),
            'total_cpe_entries': len(current_year_cpe_data['cpe_list']),
            'total_cves_with_cpes': len(set(current_year_cpe_data['cve_list'])),
            'total_unique_vendors': len(vendor_counts),
            'total_unique_products': len(product_counts),
            'top_cpes': top_cpes,
            'top_vendors': top_vendors,
            'top_products': top_products,
            'cpe_type_distribution': cpe_type_distribution,
            'cves_with_most_cpes': cves_with_most_cpes,
            'average_cpes_per_cve': round(len(current_year_cpe_data['cpe_list']) / len(set(current_year_cpe_data['cve_list'])), 1) if current_year_cpe_data['cve_list'] else 0
        }
        
        # Save current year analysis
        current_year_file = self.data_dir / 'cpe_analysis_current_year.json'
        with open(current_year_file, 'w') as f:
            json.dump(current_year_cpe_analysis, f, indent=2)
        
        print(f"    ✅ Generated current year CPE analysis with {len(cpe_counts)} unique CPEs")
        return current_year_cpe_analysis
    
    def _process_cpe_data_from_cache(self):
        """Process CPE data from cached nvd.jsonl file"""
        nvd_file = self.cache_dir / 'nvd.jsonl'
        
        if not nvd_file.exists():
            print(f"    ⚠️  NVD cache file not found: {nvd_file}")
            return None
        
        if not self.quiet:
            print(f"    📂 Processing CPE data from {nvd_file}")
        
        cpe_list = []
        vendor_list = []
        product_list = []
        type_list = []
        cve_list = []
        
        try:
            with open(nvd_file, 'r', encoding='utf-8') as f:
                if not self.quiet:
                    print(f"    📂 Loading NVD data from {nvd_file}...")
                nvd_data = json.load(f)
                
                # Handle different possible data structures
                cve_items = []
                if isinstance(nvd_data, list):
                    cve_items = nvd_data
                elif isinstance(nvd_data, dict):
                    # Check for common NVD data structure patterns
                    if 'CVE_Items' in nvd_data:
                        cve_items = nvd_data['CVE_Items']
                    elif 'vulnerabilities' in nvd_data:
                        cve_items = nvd_data['vulnerabilities']
                    else:
                        # Assume it's a single CVE item
                        cve_items = [nvd_data]
                
                if not self.quiet:
                    print(f"    📊 Processing {len(cve_items):,} CVE records...")
                
                for idx, cve_item in enumerate(cve_items):
                    if idx % 50000 == 0 and idx > 0 and not self.quiet:
                        print(f"    📊 Processed {idx:,} CVE records...")
                    
                    try:
                        # Handle different CVE data structures
                        cve_data = cve_item
                        if 'cve' in cve_item:
                            cve_data = cve_item['cve']
                        
                        cve_id = cve_data.get('id', cve_data.get('CVE_data_meta', {}).get('ID', ''))
                        
                        # Extract CPE data from configurations
                        configurations = cve_data.get('configurations', [])
                        if not configurations and 'configurations' in cve_item:
                            configurations = cve_item['configurations']
                        
                        for config in configurations:
                            for node in config.get('nodes', []):
                                if 'cpeMatch' in node:
                                    for cpe_match in node['cpeMatch']:
                                        if cpe_match.get('vulnerable', False):
                                            cpe_string = cpe_match.get('criteria', '')
                                            if cpe_string:
                                                cpe_list.append(cpe_string)
                                                cve_list.append(cve_id)
                                                vendor_list.append(self.extract_cpe_vendor(cpe_string))
                                                product_list.append(self.extract_cpe_product(cpe_string))
                                                type_list.append(self.extract_cpe_type(cpe_string))
                    
                    except Exception as e:
                        continue
        
        except Exception as e:
            print(f"    ❌ Error processing NVD file: {e}")
            return None
        
        if not self.quiet:
            print(f"    ✅ Processed {len(cpe_list):,} CPE entries from {len(set(cve_list)):,} CVEs")
        
        return {
            'cpe_list': cpe_list,
            'vendor_list': vendor_list,
            'product_list': product_list,
            'type_list': type_list,
            'cve_list': cve_list
        }
    
    def _process_current_year_cpe_data(self):
        """Process CPE data for current year only"""
        nvd_file = self.cache_dir / 'nvd.jsonl'
        
        if not nvd_file.exists():
            print(f"    ⚠️  NVD cache file not found: {nvd_file}")
            return None
        
        if not self.quiet:
            print(f"    📂 Processing current year CPE data from {nvd_file}")
        
        cpe_list = []
        vendor_list = []
        product_list = []
        type_list = []
        cve_list = []
        
        try:
            with open(nvd_file, 'r', encoding='utf-8') as f:
                if not self.quiet:
                    print(f"    📂 Loading NVD data for current year from {nvd_file}...")
                nvd_data = json.load(f)
                
                # Handle different possible data structures
                cve_items = []
                if isinstance(nvd_data, list):
                    cve_items = nvd_data
                elif isinstance(nvd_data, dict):
                    # Check for common NVD data structure patterns
                    if 'CVE_Items' in nvd_data:
                        cve_items = nvd_data['CVE_Items']
                    elif 'vulnerabilities' in nvd_data:
                        cve_items = nvd_data['vulnerabilities']
                    else:
                        # Assume it's a single CVE item
                        cve_items = [nvd_data]
                
                if not self.quiet:
                    print(f"    📊 Processing {len(cve_items):,} CVE records for current year...")
                
                for idx, cve_item in enumerate(cve_items):
                    if idx % 50000 == 0 and idx > 0 and not self.quiet:
                        print(f"    📊 Processed {idx:,} CVE records for current year...")
                    
                    try:
                        # Handle different CVE data structures
                        cve_data = cve_item
                        if 'cve' in cve_item:
                            cve_data = cve_item['cve']
                        
                        cve_id = cve_data.get('id', cve_data.get('CVE_data_meta', {}).get('ID', ''))
                        
                        # Check if CVE is from current year
                        published_date = cve_data.get('published', cve_data.get('publishedDate', ''))
                        if not published_date.startswith(str(self.current_year)):
                            continue
                        
                        # Extract CPE data from configurations
                        configurations = cve_data.get('configurations', [])
                        if not configurations and 'configurations' in cve_item:
                            configurations = cve_item['configurations']
                        
                        for config in configurations:
                            for node in config.get('nodes', []):
                                if 'cpeMatch' in node:
                                    for cpe_match in node['cpeMatch']:
                                        if cpe_match.get('vulnerable', False):
                                            cpe_string = cpe_match.get('criteria', '')
                                            if cpe_string:
                                                cpe_list.append(cpe_string)
                                                cve_list.append(cve_id)
                                                vendor_list.append(self.extract_cpe_vendor(cpe_string))
                                                product_list.append(self.extract_cpe_product(cpe_string))
                                                type_list.append(self.extract_cpe_type(cpe_string))
                    
                    except Exception as e:
                        continue
        
        except Exception as e:
            print(f"    ❌ Error processing NVD file for current year: {e}")
            return None
        
        if not self.quiet:
            print(f"    ✅ Processed {len(cpe_list):,} CPE entries from {len(set(cve_list)):,} CVEs for {self.current_year}")
        
        return {
            'cpe_list': cpe_list,
            'vendor_list': vendor_list,
            'product_list': product_list,
            'type_list': type_list,
            'cve_list': cve_list
        }
    
    def _generate_minimal_cpe_analysis(self):
        """Generate minimal CPE analysis when no data is available"""
        return {
            'generated_at': datetime.now().isoformat(),
            'total_unique_cpes': 0,
            'total_cpe_entries': 0,
            'total_cves_with_cpes': 0,
            'total_unique_vendors': 0,
            'total_unique_products': 0,
            'top_cpes': [],
            'top_vendors': [],
            'top_products': [],
            'cpe_type_distribution': [],
            'cves_with_most_cpes': [],
            'average_cpes_per_cve': 0
        }
