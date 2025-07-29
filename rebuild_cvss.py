#!/usr/bin/env python3
"""
CVSS Analysis Rebuild Script
Quick rebuild script for CVSS analysis only - much faster than full site rebuild
"""

import sys
from pathlib import Path
import json
from datetime import datetime

# Add data folder to path for imports
sys.path.append('data')

from cvss_analysis import CVSSAnalyzer


def load_all_year_data(data_dir):
    """Load all existing year data files"""
    all_year_data = []
    current_year = datetime.now().year
    
    for year in range(1999, current_year + 1):
        year_file = data_dir / f'cve_{year}.json'
        if year_file.exists():
            try:
                with open(year_file, 'r') as f:
                    year_data = json.load(f)
                all_year_data.append(year_data)
            except Exception as e:
                print(f"  ⚠️  Error loading {year_file}: {e}")
    
    return all_year_data


def main():
    """Rebuild CVSS analysis only"""
    print("📊 CVE.ICU CVSS Analysis Quick Rebuild")
    print("=" * 40)
    
    # Set up paths
    base_dir = Path(__file__).parent
    cache_dir = base_dir / 'data' / 'cache'
    data_dir = base_dir / 'web' / 'data'
    
    # Ensure data directory exists
    data_dir.mkdir(parents=True, exist_ok=True)
    
    # Initialize CVSS analyzer
    cvss_analyzer = CVSSAnalyzer(base_dir, cache_dir, data_dir)
    
    try:
        # Load existing year data
        print("📂 Loading existing year data...")
        all_year_data = load_all_year_data(data_dir)
        print(f"✅ Loaded {len(all_year_data)} year data files")
        
        if not all_year_data:
            print("❌ No year data found. Run full build first.")
            return False
        
        # Generate comprehensive CVSS analysis
        print("\n🔄 Generating comprehensive CVSS analysis...")
        cvss_analysis = cvss_analyzer.generate_cvss_analysis(all_year_data)
        
        # Generate current year CVSS analysis
        current_year = datetime.now().year
        current_year_data = next((year for year in all_year_data if year['year'] == current_year), {})
        
        if current_year_data:
            print(f"\n🗓️  Generating {current_year} CVSS analysis...")
            current_cvss_analysis = cvss_analyzer.generate_current_year_cvss_analysis(current_year_data)
        else:
            print(f"⚠️  No {current_year} data found for current year analysis")
            current_cvss_analysis = {}
        
        print("\n" + "=" * 40)
        print("✅ CVSS analysis rebuild completed!")
        print(f"📊 Total CVEs with CVSS: {cvss_analysis.get('total_cves_with_cvss', 0):,}")
        print(f"📊 CVSS v2.0: {cvss_analysis.get('total_by_version', {}).get('v2.0', 0):,}")
        print(f"📊 CVSS v3.0: {cvss_analysis.get('total_by_version', {}).get('v3.0', 0):,}")
        print(f"📊 CVSS v3.1: {cvss_analysis.get('total_by_version', {}).get('v3.1', 0):,}")
        print(f"📊 CVSS v4.0: {cvss_analysis.get('total_by_version', {}).get('v4.0', 0):,}")
        print(f"📁 Files updated:")
        print(f"   - web/data/cvss_analysis.json")
        if current_cvss_analysis:
            print(f"   - web/data/cvss_analysis_current_year.json")
        
        return True
        
    except Exception as e:
        print(f"\n❌ CVSS analysis rebuild failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
