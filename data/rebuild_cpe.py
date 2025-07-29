#!/usr/bin/env python3
"""
CPE Analysis Rebuild Script
Quick rebuild script for CPE analysis only - much faster than full site rebuild
"""

import sys
from pathlib import Path
import json
from datetime import datetime



from cpe_analysis import CPEAnalyzer

def main():
    """Main rebuild function"""
    print("🔍 CPE Analysis Quick Rebuild")
    print("=" * 50)
    
    # Setup paths
    base_dir = Path(__file__).parent.parent
    cache_dir = base_dir / 'data' / 'cache'
    data_dir = base_dir / 'web' / 'data'
    
    # Ensure data directory exists
    data_dir.mkdir(parents=True, exist_ok=True)
    
    # Initialize CPE analyzer
    print("📊 Initializing CPE analyzer...")
    cpe_analyzer = CPEAnalyzer(base_dir, cache_dir, data_dir)
    
    # Load existing year data for context (if available)
    print("📂 Loading existing year data...")
    all_year_data = []
    
    try:
        # Try to load existing year data files
        for year in range(1999, datetime.now().year + 1):
            year_file = data_dir / f'cve_{year}.json'
            if year_file.exists():
                with open(year_file, 'r') as f:
                    year_data = json.load(f)
                    all_year_data.append(year_data)
        
        if all_year_data:
            print(f"  ✅ Loaded {len(all_year_data)} existing year data files")
        else:
            print("  ⚠️  No existing year data found - CPE analysis will use raw data only")
    
    except Exception as e:
        print(f"  ⚠️  Error loading year data: {e}")
        print("  📝 Proceeding with raw data analysis...")
    
    # Generate comprehensive CPE analysis
    print("\n🔍 Generating comprehensive CPE analysis...")
    try:
        cpe_analysis = cpe_analyzer.generate_cpe_analysis(all_year_data)
        
        if cpe_analysis and cpe_analysis.get('total_unique_cpes', 0) > 0:
            print(f"  ✅ Generated comprehensive CPE analysis with {cpe_analysis['total_unique_cpes']:,} unique CPEs")
            print(f"  📊 Covers {cpe_analysis['total_cves_with_cpes']:,} CVEs with CPE data")
            print(f"  🏢 Includes {cpe_analysis['total_unique_vendors']:,} unique vendors")
        else:
            print("  ❌ CPE analysis failed or returned no data")
            return 1
    
    except Exception as e:
        print(f"  ❌ Error generating comprehensive CPE analysis: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    # Generate current year CPE analysis
    print("\n📅 Generating current year CPE analysis...")
    try:
        current_year = datetime.now().year
        current_year_data = next((data for data in all_year_data if data.get('year') == current_year), {})
        
        current_cpe_analysis = cpe_analyzer.generate_current_year_cpe_analysis(current_year_data)
        
        if current_cpe_analysis and current_cpe_analysis.get('total_unique_cpes', 0) > 0:
            print(f"  ✅ Generated current year CPE analysis with {current_cpe_analysis['total_unique_cpes']:,} unique CPEs")
            print(f"  📊 Covers {current_cpe_analysis['total_cves_with_cpes']:,} CVEs for {current_year}")
        else:
            print(f"  ⚠️  Current year CPE analysis returned minimal data for {current_year}")
    
    except Exception as e:
        print(f"  ❌ Error generating current year CPE analysis: {e}")
        import traceback
        traceback.print_exc()
        print("  ⚠️  Current year analysis will be missing")
    
    # Generate CPE page HTML
    print("\n🌐 Generating CPE page HTML...")
    try:
        from jinja2 import Environment, FileSystemLoader
        
        # Setup Jinja2 environment
        template_dir = base_dir / 'templates'
        env = Environment(loader=FileSystemLoader(template_dir))
        
        # Load CPE template
        template = env.get_template('cpe.html')
        
        # Render CPE page
        html_content = template.render(
            title="CPE Analysis - CVE.ICU",
            current_year=datetime.now().year
        )
        
        # Save CPE page
        output_file = base_dir / 'web' / 'cpe.html'
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"  ✅ Generated CPE page: {output_file}")
    
    except Exception as e:
        print(f"  ❌ Error generating CPE page HTML: {e}")
        import traceback
        traceback.print_exc()
        print("  ⚠️  CPE page HTML generation failed")
    
    print("\n" + "=" * 50)
    print("🎉 CPE Analysis Rebuild Complete!")
    print("\nFiles generated:")
    print(f"  📊 {data_dir}/cpe_analysis.json")
    print(f"  📅 {data_dir}/cpe_analysis_current_year.json")
    print(f"  🌐 {base_dir}/web/cpe.html")
    print("\nYou can now view the CPE analysis page in your browser.")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
