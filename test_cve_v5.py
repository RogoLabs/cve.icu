#!/usr/bin/env python3
"""
Quick test script for CVE V5 processor to validate implementation
"""

import sys
from pathlib import Path

# Add data folder to path for imports
sys.path.append('data')

from cve_v5_processor import CVEV5Processor
from datetime import datetime

def test_cve_v5_integration():
    """Test the CVE V5 processor implementation"""
    print("🧪 Testing CVE V5 Integration")
    print("=" * 50)
    
    # Initialize processor
    base_dir = Path(__file__).parent
    cache_dir = base_dir / 'data' / 'cache'
    data_dir = base_dir / 'web' / 'data'
    
    processor = CVEV5Processor(base_dir, cache_dir, data_dir)
    
    # Test 1: Repository setup
    print("\n📦 Test 1: CVE V5 Repository Setup")
    success = processor.clone_or_update_cve_v5_repo()
    if success:
        print("✅ Repository setup successful")
        
        # Get repository statistics
        stats = processor.get_repo_stats()
        if stats:
            print(f"📊 Repository contains {stats['total_cves']} CVEs across {stats['total_years']} years")
            print(f"📅 Years available: {min(stats['years_available'])}-{max(stats['years_available'])}")
        else:
            print("⚠️ Could not get repository statistics")
    else:
        print("❌ Repository setup failed")
        return False
    
    # Test 2: Current year processing (quick test)
    print(f"\n📅 Test 2: Current Year ({datetime.now().year}) Processing")
    try:
        current_year_data = processor.generate_current_year_analysis()
        if current_year_data:
            print(f"✅ Current year analysis successful")
            print(f"📊 Found {current_year_data['total_cnas']} CNAs for {datetime.now().year}")
            print(f"🏢 Official CNAs: {current_year_data['official_cnas']}")
            print(f"❌ Unofficial CNAs: {current_year_data['unofficial_cnas']}")
            
            # Show top 5 CNAs
            top_cnas = current_year_data['cna_list'][:5]
            print(f"\n🏆 Top 5 CNAs for {datetime.now().year}:")
            for i, cna in enumerate(top_cnas, 1):
                print(f"  {i}. {cna['name']} - {cna['count']} CVEs")
        else:
            print("❌ Current year analysis failed")
    except Exception as e:
        print(f"❌ Current year processing failed: {e}")
        import traceback
        traceback.print_exc()
    
    # Test 3: Sample CVE record parsing
    print(f"\n🔍 Test 3: Sample CVE Record Parsing")
    try:
        v5_cache_dir = processor.v5_cache_dir
        current_year = datetime.now().year
        year_dir = v5_cache_dir / 'cves' / str(current_year)
        
        if year_dir.exists():
            # Find a sample CVE file
            cve_files = list(year_dir.glob('CVE-*.json'))[:3]  # Test first 3 files
            
            for cve_file in cve_files:
                record = processor.parse_cve_v5_record(cve_file)
                if record:
                    print(f"  📄 {record['cve_id']}")
                    print(f"    CNA Org ID: {record['assigner_org_id']}")
                    print(f"    CNA Name: {record['assigner_short_name']}")
                    print(f"    Published: {record['publication_date']}")
                else:
                    print(f"  ❌ Failed to parse {cve_file.name}")
        else:
            print(f"  ⚠️ No data directory found for {current_year}")
            
    except Exception as e:
        print(f"❌ Sample parsing failed: {e}")
    
    print("\n" + "=" * 50)
    print("🧪 CVE V5 Integration Test Complete")
    
    return True

if __name__ == '__main__':
    test_cve_v5_integration()
