#!/usr/bin/env python3
"""
CNA Analysis Rebuild Script
Quick rebuild script for CNA analysis only - much faster than full site rebuild
"""

import sys
from pathlib import Path

from cve_v5_processor import CVEV5Processor
import json
from datetime import datetime


def main():
    """Rebuild CNA analysis only"""
    print("🏢 CVE.ICU CNA Analysis Quick Rebuild")
    print("=" * 40)
    
    # Set up paths
    base_dir = Path(__file__).parent.parent
    cache_dir = base_dir / 'data' / 'cache'
    data_dir = base_dir / 'web' / 'data'
    
    # Ensure data directory exists
    data_dir.mkdir(parents=True, exist_ok=True)
    
    # Initialize CVE V5 processor
    v5_processor = CVEV5Processor(base_dir, cache_dir, data_dir)
    
    try:
        # Generate comprehensive CNA analysis using CVE V5 data
        print("\n🔄 Generating comprehensive CNA analysis (CVE V5 authoritative)...")
        cna_analysis = v5_processor.generate_comprehensive_cna_analysis()
        
        # Generate current year CNA analysis with new publication date logic
        print(f"\n🗓️  Generating {v5_processor.current_year} CNA analysis (by publication date)...")
        current_cna_analysis = v5_processor.generate_current_year_analysis()
        
        print("\n" + "=" * 40)
        print("✅ CNA analysis rebuild completed!")
        print(f"📊 Total CNAs: {cna_analysis.get('total_cnas', 0)}")
        print(f"📊 Active CNAs: {cna_analysis.get('active_cnas', 0)}")
        print(f"📊 Current year CNAs: {current_cna_analysis.get('total_cnas', 0)}")
        print(f"📁 Files updated:")
        print(f"   - web/data/cna_analysis.json")
        print(f"   - web/data/cna_analysis_current_year.json")
        
        return True
        
    except Exception as e:
        print(f"\n❌ CNA analysis rebuild failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
