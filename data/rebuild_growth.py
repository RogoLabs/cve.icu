#!/usr/bin/env python3
"""
Growth Analysis Rebuild Script
Standalone script to rebuild growth analysis data and regenerate the Growth Intelligence Dashboard
"""

import sys
import os
from pathlib import Path



def main():
    """Main function to rebuild growth analysis"""
    print("🚀 Growth Analysis Rebuild Script")
    print("=" * 50)
    
    try:
        # Import required modules
        from yearly_analysis import YearlyAnalyzer
        
        # Initialize paths
        base_dir = Path(__file__).parent.parent
        cache_dir = base_dir / 'data' / 'cache'
        data_dir = base_dir / 'data'
        
        print(f"📁 Base directory: {base_dir}")
        print(f"💾 Cache directory: {cache_dir}")
        print(f"📊 Data directory: {data_dir}")
        
        # Initialize analyzer
        print("\n🔧 Initializing Growth Analyzer...")
        analyzer = YearlyAnalyzer(base_dir, cache_dir, data_dir)
        
        # Generate year data first (required for growth analysis)
        print("\n📅 Generating year data...")
        all_year_data = analyzer.generate_year_data_json()
        
        if not all_year_data:
            print("❌ No year data available for growth analysis")
            return False
        
        print(f"✅ Generated data for {len(all_year_data)} years")
        
        # Generate comprehensive growth analysis
        print("\n📈 Generating comprehensive growth analysis...")
        growth_analysis = analyzer.generate_growth_analysis(all_year_data)
        
        if growth_analysis:
            print("✅ Comprehensive growth analysis generated successfully")
            
            # Display key statistics
            growth_data = growth_analysis.get('growth_data', [])
            if growth_data:
                latest_year = growth_data[-1]
                print(f"📊 Latest year: {latest_year['year']} with {latest_year['cves']:,} CVEs")
                print(f"📈 Average annual growth: {growth_analysis.get('avg_annual_growth', 0)}%")
                
                highest_growth = growth_analysis.get('highest_growth_year')
                if highest_growth:
                    print(f"🚀 Peak growth: {highest_growth['year']} ({highest_growth['growth_rate']}%)")
        else:
            print("❌ Failed to generate comprehensive growth analysis")
            return False
        
        # Generate current year growth analysis
        print("\n📅 Generating current year growth analysis...")
        try:
            current_year = analyzer.current_year
            current_year_data = next((d for d in all_year_data if d.get('year') == current_year), None)
            
            if current_year_data:
                # Create simplified current year growth analysis
                current_year_growth = {
                    'generated_at': growth_analysis['generated_at'],
                    'year': current_year,
                    'growth_data': [d for d in growth_data if d['year'] == current_year],
                    'avg_annual_growth': 0,  # Not applicable for single year
                    'highest_growth_year': None,  # Not applicable for single year
                    'lowest_growth_year': None   # Not applicable for single year
                }
                
                # Save current year analysis
                import json
                from datetime import datetime
                
                current_year_file = data_dir / 'growth_analysis_current_year.json'
                with open(current_year_file, 'w') as f:
                    json.dump(current_year_growth, f, indent=2)
                
                print(f"✅ Current year ({current_year}) growth analysis generated")
            else:
                print(f"⚠️  No data found for current year {current_year}")
        
        except Exception as e:
            print(f"❌ Error generating current year growth analysis: {e}")
        
        print("\n🎉 Growth analysis rebuild completed successfully!")
        print(f"📄 Files generated:")
        print(f"  • growth_analysis.json (comprehensive)")
        print(f"  • growth_analysis_current_year.json (current year)")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("💡 Make sure all required modules are available")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
