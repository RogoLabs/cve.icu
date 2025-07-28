#!/usr/bin/env python3
"""
CWE Analysis Rebuild Script
Quick rebuild script for CWE analysis only - much faster than full site rebuild
"""

import sys
from pathlib import Path
import json
from datetime import datetime

# Add data folder to path for imports
sys.path.append('data')

from cwe_analysis import CWEAnalyzer


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
    """Rebuild CWE analysis only"""
    print("🔍 CVE.ICU CWE Analysis Quick Rebuild")
    print("=" * 40)
    
    # Set up paths
    base_dir = Path(__file__).parent
    cache_dir = base_dir / 'data' / 'cache'
    data_dir = base_dir / 'web' / 'data'
    
    # Ensure data directory exists
    data_dir.mkdir(parents=True, exist_ok=True)
    
    # Initialize CWE analyzer
    cwe_analyzer = CWEAnalyzer(base_dir, cache_dir, data_dir)
    
    try:
        # Load existing year data
        print("📂 Loading existing year data...")
        all_year_data = load_all_year_data(data_dir)
        print(f"✅ Loaded {len(all_year_data)} year data files")
        
        if not all_year_data:
            print("❌ No year data found. Run full build first.")
            return False
        
        # Generate comprehensive CWE analysis
        print("\n🔄 Generating comprehensive CWE analysis...")
        cwe_analysis = cwe_analyzer.generate_cwe_analysis(all_year_data)
        
        # Generate current year CWE analysis
        current_year = datetime.now().year
        current_year_data = next((year for year in all_year_data if year['year'] == current_year), {})
        
        if current_year_data:
            print(f"\n🗓️  Generating {current_year} CWE analysis...")
            current_cwe_analysis = cwe_analyzer.generate_current_year_cwe_analysis(current_year_data)
        else:
            print(f"⚠️  No {current_year} data found for current year analysis")
            current_cwe_analysis = {}
        
        print("\n" + "=" * 40)
        print("✅ CWE analysis rebuild completed!")
        print(f"📊 Total CVEs with CWE: {cwe_analysis.get('total_cves_with_cwe', 0):,}")
        print(f"📊 Unique CWEs: {cwe_analysis.get('total_unique_cwes', 0):,}")
        print(f"📊 Top CWEs available: {len(cwe_analysis.get('top_cwes', []))}")
        print(f"📁 Files updated:")
        print(f"   - web/data/cwe_analysis.json")
        if current_cwe_analysis:
            print(f"   - web/data/cwe_analysis_current_year.json")
        
        return True
        
    except Exception as e:
        print(f"\n❌ CWE analysis rebuild failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
