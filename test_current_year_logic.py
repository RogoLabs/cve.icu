#!/usr/bin/env python3
"""
Test script to verify the new current year analysis logic
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'data'))

from cve_v5_processor import CVEV5Processor
from pathlib import Path

def test_current_year_logic():
    """Test the new current year analysis logic"""
    print("🧪 Testing new current year analysis logic...")
    
    base_dir = Path(__file__).parent
    cache_dir = base_dir / 'data' / 'cache'
    data_dir = base_dir / 'web' / 'data'
    
    # Initialize processor
    processor = CVEV5Processor(base_dir, cache_dir, data_dir)
    
    print(f"📅 Testing for year: {processor.current_year}")
    print(f"📂 CVE V5 cache dir: {processor.v5_cache_dir}")
    
    # Check if CVE V5 data exists
    if not processor.v5_cache_dir.exists():
        print("❌ CVE V5 cache directory not found!")
        return
    
    cves_dir = processor.v5_cache_dir / 'cves'
    if not cves_dir.exists():
        print("❌ CVEs directory not found!")
        return
    
    print(f"✅ Found CVEs directory with {len(list(cves_dir.iterdir()))} year folders")
    
    # Test the new logic
    print("\n🔍 Testing new publication date filtering logic...")
    current_year_data = processor.process_current_year_by_publication_date()
    
    print(f"\n📊 Results:")
    print(f"  📈 CNAs found: {len(current_year_data)}")
    print(f"  📅 Year tested: {processor.current_year}")
    
    if current_year_data:
        # Show top 5 CNAs
        sorted_cnas = sorted(current_year_data.items(), key=lambda x: x[1]['count'], reverse=True)
        print(f"\n🏆 Top 5 CNAs by {processor.current_year} publications:")
        for i, (org_id, stats) in enumerate(sorted_cnas[:5]):
            print(f"  {i+1}. {stats['assigner_short_name'] or org_id}: {stats['count']} CVEs")
    
    return current_year_data

if __name__ == "__main__":
    test_current_year_logic()
