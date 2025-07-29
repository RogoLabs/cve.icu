#!/usr/bin/env python3
"""
Vendor Analysis Module
Handles all vendor/CPE (Common Platform Enumeration) related data processing and analysis
"""

import json
from pathlib import Path
from datetime import datetime


class VendorAnalyzer:
    """Handles vendor/CPE-specific analysis and data processing"""
    
    def __init__(self, base_dir, cache_dir, data_dir):
        self.base_dir = Path(base_dir)
        self.cache_dir = Path(cache_dir)
        self.data_dir = Path(data_dir)
        self.current_year = datetime.now().year
    
    def generate_vendor_analysis(self, all_year_data):
        """Generate CPE vendor analysis across all years"""
        print(f"  🏢 Generating vendor/CPE analysis...")
        
        # Aggregate vendor data from all years
        combined_vendors = {}
        total_cves_with_vendors = 0
        
        for year_data in all_year_data:
            if 'vendors' in year_data and 'cpe_vendors' in year_data['vendors']:
                total_cves_with_vendors += year_data['vendors'].get('total_cves_with_vendors', 0)
                
                # Aggregate vendor counts
                for vendor_entry in year_data['vendors']['cpe_vendors']:
                    vendor_name = vendor_entry['name']
                    count = vendor_entry['count']
                    
                    if vendor_name not in combined_vendors:
                        combined_vendors[vendor_name] = {
                            'name': vendor_name,
                            'count': 0
                        }
                    
                    combined_vendors[vendor_name]['count'] += count
        
        # Sort by count and get top vendors
        top_vendors = sorted(combined_vendors.values(), key=lambda x: x['count'], reverse=True)
        
        vendor_analysis = {
            'generated_at': datetime.now().isoformat(),
            'total_cves_with_vendors': total_cves_with_vendors,
            'total_unique_vendors': len(combined_vendors),
            'top_vendors': top_vendors[:100],  # Top 100 vendors
            'top_vendors_limited': top_vendors[:20]  # Top 20 for charts
        }
        
        # Save to file
        output_file = self.data_dir / 'vendor_analysis.json'
        with open(output_file, 'w') as f:
            json.dump(vendor_analysis, f, indent=2)
        
        print(f"  ✅ Generated vendor analysis with {len(combined_vendors):,} unique vendors")
        return vendor_analysis
    
    def generate_current_year_vendor_analysis(self, current_year_data):
        """Generate current year vendor analysis"""
        print(f"    🏢 Generating current year vendor analysis...")
        
        # Extract vendor data from current year
        vendor_data = current_year_data.get('vendors', {})
        
        if not vendor_data or 'cpe_vendors' not in vendor_data:
            print(f"    ⚠️  No vendor data found for {self.current_year}")
            return {}
        
        # Get current year vendors
        current_year_vendors = vendor_data['cpe_vendors']
        
        current_year_vendor_analysis = {
            'generated_at': datetime.now().isoformat(),
            'year': self.current_year,
            'total_cves_with_vendors': vendor_data.get('total_cves_with_vendors', 0),
            'total_unique_vendors': len(current_year_vendors),
            'top_vendors': current_year_vendors[:100],  # Top 100 vendors
            'top_vendors_limited': current_year_vendors[:20]  # Top 20 for charts
        }
        
        # Save current year analysis
        current_year_file = self.data_dir / 'vendor_analysis_current_year.json'
        with open(current_year_file, 'w') as f:
            json.dump(current_year_vendor_analysis, f, indent=2)
        
        print(f"    ✅ Generated current year vendor analysis with {len(current_year_vendors)} vendors")
        return current_year_vendor_analysis
