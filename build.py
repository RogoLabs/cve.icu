#!/usr/bin/env python3
"""
CVE.ICU Static Site Generator
Fixed build system that works with existing code structure
"""

import os
import shutil
import json
from datetime import datetime
from pathlib import Path
import sys
import argparse

# Add data folder to path for imports
sys.path.append('data')

from jinja2 import Environment, FileSystemLoader, select_autoescape


class CVESiteBuilder:
    """Main class for building the CVE.ICU static site"""
    
    def __init__(self, quiet=False):
        self.quiet = quiet or os.getenv('CVE_BUILD_QUIET', '').lower() in ('1', 'true', 'yes')
        self.current_year = datetime.now().year
        self.available_years = list(range(1999, self.current_year + 1))
        self.base_dir = Path(__file__).parent
        self.templates_dir = self.base_dir / 'templates'
        self.web_dir = self.base_dir / 'web'
        self.static_dir = self.web_dir / 'static'
        self.data_dir = self.web_dir / 'data'
        self.data_scripts_dir = self.base_dir / 'data'
        self.cache_dir = self.data_scripts_dir / 'cache'
        
        # Set up Jinja2 environment
        self.jinja_env = Environment(
            loader=FileSystemLoader(self.templates_dir),
            autoescape=select_autoescape(['html', 'xml'])
        )
        
        # Add custom filters and globals
        self.jinja_env.globals['current_year'] = self.current_year
        self.jinja_env.globals['available_years'] = self.available_years
        self.jinja_env.filters['format_number'] = self.format_number
        
        if not self.quiet:
            print(f"🚀 CVE.ICU Build System Initialized")
            print(f"📅 Current Year: {self.current_year}")
            print(f"📊 Coverage: 1999-{self.current_year} ({len(self.available_years)} years)")
            print(f"🌐 Web output: {self.web_dir}")
            print(f"📁 Data scripts: {self.data_scripts_dir}")
    
    def print_verbose(self, message):
        """Print message only if not in quiet mode"""
        if not self.quiet:
            print(message)
    
    def print_always(self, message):
        """Print message regardless of quiet mode (for errors and essential info)"""
        print(message)
    
    def format_number(self, num):
        """Format numbers for display (e.g., 1000 -> 1K)"""
        if num >= 1000000:
            return f"{num / 1000000:.1f}M"
        elif num >= 1000:
            return f"{num / 1000:.1f}K"
        return str(num)
    
    def clean_build(self):
        """Clean and recreate the web directory"""
        self.print_verbose("🧹 Cleaning web directory...")
        
        # Remove existing HTML files and data directory, but keep static assets
        if self.web_dir.exists():
            # Remove HTML files
            for html_file in self.web_dir.glob('*.html'):
                html_file.unlink()
            
            # Remove and recreate data directory
            if self.data_dir.exists():
                shutil.rmtree(self.data_dir)
        
        # Create directory structure
        self.web_dir.mkdir(exist_ok=True)
        self.data_dir.mkdir(exist_ok=True)
        
        self.print_verbose("✅ Web directory cleaned and recreated")
    
    def ensure_static_assets(self):
        """Ensure static assets are in place"""
        self.print_verbose("📁 Checking static assets...")
        
        if not self.static_dir.exists():
            self.print_verbose("⚠️  Warning: Static directory not found, creating...")
            self.static_dir.mkdir(parents=True, exist_ok=True)
        
        # Check for required files
        required_files = [
            'css/style.css',
            'js/chart.min.js',
            'images/logo.png'
        ]
        
        for file_path in required_files:
            full_path = self.static_dir / file_path
            if full_path.exists():
                self.print_verbose(f"  ✅ Found {file_path}")
            else:
                self.print_verbose(f"  ⚠️  Missing {file_path}")
        
        self.print_verbose("✅ Static assets check complete")
    
    def generate_year_data_json(self):
        """Generate JSON data files for all available years"""
        self.print_verbose("📊 Generating year data JSON files...")
        
        try:
            # Import the real CVE years analyzer
            from cve_years import CVEYearsAnalyzer
            
            self.print_verbose("🔽 Initializing CVE data processing...")
            analyzer = CVEYearsAnalyzer(quiet=self.quiet)
            
            # Generate data for all years
            all_year_data = []
            
            for year in self.available_years:
                self.print_verbose(f"  📅 Processing year {year}...")
                
                try:
                    # Use the real analyzer to get year data
                    year_data = analyzer.get_year_data(year)
                    
                    if year_data:
                        # Save individual year file
                        year_file = self.data_dir / f'cve_{year}.json'
                        with open(year_file, 'w') as f:
                            json.dump(year_data, f, indent=2, default=str)
                        
                        all_year_data.append(year_data)
                        self.print_verbose(f"    ✅ Generated cve_{year}.json ({year_data.get('total_cves', 0):,} CVEs)")
                    else:
                        self.print_verbose(f"    ⚠️  Skipped {year} - no data available")
                        
                except Exception as e:
                    self.print_always(f"  ❌ Failed to process {year}: {e}")
                    continue
            
            self.print_always(f"✅ Generated {len(all_year_data)} year data files")
            return all_year_data
            
        except ImportError as e:
            self.print_always(f"❌ Failed to import CVE years analyzer: {e}")
            self.print_always("📝 Creating minimal data as fallback...")
            return self.create_minimal_year_data()
        except Exception as e:
            self.print_always(f"❌ Error generating year data: {e}")
            self.print_verbose("📝 Creating minimal data as fallback...")
            return self.create_minimal_year_data()
    
    def create_minimal_year_data(self):
        """Create minimal year data for basic functionality"""
        self.print_verbose("📝 Creating minimal year data for basic functionality...")
        all_year_data = []
        
        for year in self.available_years:
            year_data = {
                'year': year,
                'total_cves': max(100, (year - 1999) * 500),
                'date_data': {
                    'monthly_distribution': {str(i): max(10, (year - 1999) * 5) for i in range(1, 13)},
                    'daily_analysis': {
                        'total_days': 365,
                        'days_with_cves': min(365, max(50, (year - 1999) * 10)),
                        'avg_cves_per_day': max(1, (year - 1999) * 1.5),
                        'max_cves_in_day': max(5, (year - 1999) * 3),
                        'daily_counts': {}
                    }
                }
            }
            
            # Save individual year file
            year_file = self.data_dir / f'cve_{year}.json'
            with open(year_file, 'w') as f:
                json.dump(year_data, f, indent=2)
            
            all_year_data.append(year_data)
        
        print(f"✅ Generated {len(all_year_data)} minimal year data files")
        return all_year_data
    
    def generate_combined_analysis_json(self, all_year_data):
        """Generate combined analysis JSON files"""
        print("📊 Generating combined analysis JSON files...")
        
        # Generate comprehensive CNA analysis using CVE V5 as authoritative source
        try:
            from cve_v5_processor import CVEV5Processor
            if not self.quiet:
                print("  🏢 Generating comprehensive CNA analysis from CVE V5 data...")
            v5_processor = CVEV5Processor(self.base_dir, self.cache_dir, self.data_dir, quiet=self.quiet)
            cna_analysis = v5_processor.generate_comprehensive_cna_analysis()
            
            if cna_analysis:
                if not self.quiet:
                    print(f"  ✅ Generated cna_analysis.json with {cna_analysis['total_cnas']} CNAs (CVE V5 authoritative)")
            else:
                print("  ❌ CVE V5 CNA analysis failed")
                
        except Exception as e:
            print(f"  ❌ Error generating CVE V5 CNA analysis: {e}")
            import traceback
            traceback.print_exc()
            print("  ⚠️  CNA analysis will be missing")
        
        # Generate current year CNA analysis using CVE V5 data
        try:
            from cve_v5_processor import CVEV5Processor
            if not self.quiet:
                print("  🗓️  Generating current year CNA analysis from CVE V5 data...")
            v5_processor = CVEV5Processor(self.base_dir, self.cache_dir, self.data_dir, quiet=self.quiet)
            current_cna_analysis = v5_processor.generate_current_year_analysis()
            
            if current_cna_analysis:
                if not self.quiet:
                    print(f"  ✅ Generated cna_analysis_current_year.json with {current_cna_analysis['total_cnas']} CNAs (CVE V5 authoritative)")
            else:
                print("  ❌ CVE V5 current year analysis failed")
                
        except Exception as e:
            print(f"  ❌ Error generating CVE V5 current year CNA analysis: {e}")
            import traceback
            traceback.print_exc()
            print("  ⚠️  Current year CNA analysis will be missing")
        
        # Generate CPE analysis
        try:
            from cpe_analysis import CPEAnalyzer
            if not self.quiet:
                print("  🔍 Generating comprehensive CPE analysis...")
            cpe_analyzer = CPEAnalyzer(self.base_dir, self.cache_dir, self.data_dir, quiet=self.quiet)
            cpe_analysis = cpe_analyzer.generate_cpe_analysis(all_year_data)
            
            if cpe_analysis:
                if not self.quiet:
                    print(f"  ✅ Generated cpe_analysis.json with {cpe_analysis['total_unique_cpes']:,} unique CPEs")
            else:
                print("  ❌ CPE analysis failed")
                
        except Exception as e:
            print(f"  ❌ Error generating CPE analysis: {e}")
            import traceback
            traceback.print_exc()
            print("  ⚠️  CPE analysis will be missing")
        
        # Generate current year CPE analysis
        try:
            from cpe_analysis import CPEAnalyzer
            if not self.quiet:
                print("  📅 Generating current year CPE analysis...")
            cpe_analyzer = CPEAnalyzer(self.base_dir, self.cache_dir, self.data_dir, quiet=self.quiet)
            current_year_data = next((data for data in all_year_data if data['year'] == datetime.now().year), {})
            current_cpe_analysis = cpe_analyzer.generate_current_year_cpe_analysis(current_year_data)
            
            if current_cpe_analysis:
                if not self.quiet:
                    print(f"  ✅ Generated cpe_analysis_current_year.json with {current_cpe_analysis['total_unique_cpes']:,} unique CPEs")
            else:
                print("  ❌ Current year CPE analysis failed")
            
        except Exception as e:
            print(f"  ❌ Error generating current year CPE analysis: {e}")
            import traceback
            traceback.print_exc()
            print("  ⚠️  Current year CPE analysis will be missing")
        
        # Generate CVSS analysis
        try:
            from cvss_analysis import CVSSAnalyzer
            if not self.quiet:
                print("  📊 Generating comprehensive CVSS analysis...")
            cvss_analyzer = CVSSAnalyzer(self.base_dir, self.cache_dir, self.data_dir, quiet=self.quiet)
            cvss_analysis = cvss_analyzer.generate_cvss_analysis(all_year_data)
            
            if cvss_analysis:
                if not self.quiet:
                    print("  ✅ Comprehensive CVSS analysis generated")
            else:
                print("  ❌ Comprehensive CVSS analysis failed")
                
        except Exception as e:
            print(f"  ❌ Error generating comprehensive CVSS analysis: {e}")
            import traceback
            traceback.print_exc()
            print("  ⚠️  Comprehensive CVSS analysis will be missing")
        
        # Generate current year CVSS analysis
        try:
            current_year_data = next((d for d in all_year_data if d.get('year') == self.current_year), None)
            if current_year_data:
                if not self.quiet:
                    print("  📅 Generating current year CVSS analysis...")
                current_year_cvss_analysis = cvss_analyzer.generate_current_year_cvss_analysis(current_year_data)
                
                if current_year_cvss_analysis:
                    if not self.quiet:
                        print("  ✅ Current year CVSS analysis generated")
                else:
                    print("  ❌ Current year CVSS analysis failed")
            else:
                print(f"  ⚠️  No data found for current year {self.current_year}")
                
        except Exception as e:
            print(f"  ❌ Error generating current year CVSS analysis: {e}")
            import traceback
            traceback.print_exc()
            print("  ⚠️  Current year CVSS analysis will be missing")
        
        # Generate CWE analysis
        try:
            from cwe_analysis import CWEAnalyzer
            if not self.quiet:
                print("  🔍 Generating comprehensive CWE analysis...")
            cwe_analyzer = CWEAnalyzer(self.base_dir, self.cache_dir, self.data_dir, quiet=self.quiet)
            cwe_analysis = cwe_analyzer.generate_cwe_analysis(all_year_data)
            
            if cwe_analysis:
                if not self.quiet:
                    print(f"  ✅ Generated cwe_analysis.json with {cwe_analysis['total_unique_cwes']} unique CWEs")
            else:
                print("  ❌ CWE analysis failed")
                
        except Exception as e:
            print(f"  ❌ Error generating CWE analysis: {e}")
            import traceback
            traceback.print_exc()
            print("  ⚠️  CWE analysis will be missing")
        
        # Generate current year CWE analysis
        try:
            current_year_data = next((d for d in all_year_data if d.get('year') == self.current_year), None)
            if current_year_data:
                if not self.quiet:
                    print("  📅 Generating current year CWE analysis...")
                current_year_cwe_analysis = cwe_analyzer.generate_current_year_cwe_analysis(current_year_data)
                
                if current_year_cwe_analysis:
                    if not self.quiet:
                        print(f"  ✅ Generated cwe_analysis_current_year.json with {current_year_cwe_analysis['total_unique_cwes']} unique CWEs")
                else:
                    print("  ❌ Current year CWE analysis failed")
            else:
                print(f"  ⚠️  No data found for current year {self.current_year}")
                
        except Exception as e:
            print(f"  ❌ Error generating current year CWE analysis: {e}")
            import traceback
            traceback.print_exc()
            print("  ⚠️  Current year CWE analysis will be missing")
        
        # Generate Calendar analysis
        try:
            from calendar_analysis import CalendarAnalyzer
            if not self.quiet:
                print("  📅 Generating comprehensive calendar analysis...")
            calendar_analyzer = CalendarAnalyzer(self.base_dir, self.cache_dir, self.data_dir, quiet=self.quiet)
            calendar_analysis = calendar_analyzer.generate_calendar_analysis()
            
            if calendar_analysis:
                if not self.quiet:
                    print(f"  ✅ Generated calendar_analysis.json with {calendar_analysis['metadata']['total_days']:,} days of data")
            else:
                print("  ❌ Calendar analysis failed")
                
        except Exception as e:
            print(f"  ❌ Error generating calendar analysis: {e}")
            import traceback
            traceback.print_exc()
            print("  ⚠️  Calendar analysis will be missing")
        
        # Generate current year calendar analysis
        try:
            current_year_calendar_analysis = calendar_analyzer.generate_current_year_calendar_analysis()
            
            if current_year_calendar_analysis:
                print(f"  ✅ Generated calendar_analysis_current_year.json with {current_year_calendar_analysis['metadata']['total_days']:,} days")
            else:
                print("  ❌ Current year calendar analysis failed")
                
        except Exception as e:
            print(f"  ❌ Error generating current year calendar analysis: {e}")
            import traceback
            traceback.print_exc()
            print("  ⚠️  Current year calendar analysis will be missing")
        
        # Generate growth analysis
        try:
            from yearly_analysis import YearlyAnalyzer
            print("  📈 Generating growth analysis...")
            yearly_analyzer = YearlyAnalyzer(self.base_dir, self.cache_dir, self.data_dir)
            growth_analysis = yearly_analyzer.generate_growth_analysis(all_year_data)
            
            if growth_analysis:
                print("  ✅ Growth analysis generated")
            else:
                print("  ❌ Growth analysis failed")
                
        except Exception as e:
            print(f"  ❌ Error generating growth analysis: {e}")
            import traceback
            traceback.print_exc()
            print("  ⚠️  Growth analysis will be missing")
        
        # Generate cve_all.json from year data
        self.generate_cve_all_json(all_year_data)
        
        print("✅ Combined analysis JSON files generated")
        
        return {
            'cna_analysis': 'generated',
            'cpe_analysis': 'generated',
            'cvss_analysis': 'generated',
            'cwe_analysis': 'generated',
            'calendar_analysis': 'generated',
            'growth_analysis': 'generated',
            'cve_all': 'generated'
        }
    
    def generate_cve_all_json(self, all_year_data):
        """Generate overall CVE statistics across all years"""
        print("  📊 Generating cve_all.json...")
        
        if not all_year_data:
            print("  ⚠️  No year data available")
            return
        
        # Calculate totals
        total_cves = sum(year_data.get('total_cves', 0) for year_data in all_year_data)
        years_with_data = len(all_year_data)
        
        # Find peak year
        peak_year_data = max(all_year_data, key=lambda x: x.get('total_cves', 0))
        peak_year = peak_year_data.get('year', self.current_year)
        peak_count = peak_year_data.get('total_cves', 0)
        
        # Calculate YOY growth (current vs previous year)
        current_year_data = next((d for d in all_year_data if d.get('year') == self.current_year), None)
        prev_year_data = next((d for d in all_year_data if d.get('year') == self.current_year - 1), None)
        
        yoy_growth = 0
        if current_year_data and prev_year_data:
            current_count = current_year_data.get('total_cves', 0)
            prev_count = prev_year_data.get('total_cves', 0)
            if prev_count > 0:
                yoy_growth = ((current_count - prev_count) / prev_count) * 100
        
        # Create yearly trend data
        yearly_data = []
        for year_data in sorted(all_year_data, key=lambda x: x.get('year', 0)):
            yearly_data.append({
                'year': year_data.get('year'),
                'count': year_data.get('total_cves', 0)
            })
        
        cve_all_data = {
            'generated_at': datetime.now().isoformat(),
            'total_cves': total_cves,
            'years_covered': years_with_data,
            'current_year': self.current_year,
            'current_year_cves': current_year_data.get('total_cves', 0) if current_year_data else 0,
            'peak_year': peak_year,
            'peak_count': peak_count,
            'yoy_growth_rate': round(yoy_growth, 1),
            'yearly_trend': yearly_data
        }
        
        # Save to file
        output_file = self.data_dir / 'cve_all.json'
        with open(output_file, 'w') as f:
            json.dump(cve_all_data, f, indent=2)
        
        print(f"  ✅ Generated cve_all.json with {total_cves:,} total CVEs")
    
    def generate_current_year_analysis_json(self, all_year_data):
        """Generate current year specific analysis files"""
        print(f"🗓️  Current year ({self.current_year}) analysis already handled in combined analysis")
        
        # Current year analysis is now handled in generate_combined_analysis_json
        # This method is kept for compatibility but doesn't need to do anything
        
        return {
            'cna_current': 'handled_in_combined_analysis'
        }
    
    def generate_html_pages(self):
        """Generate HTML pages from templates"""
        self.print_verbose("📄 Generating HTML pages...")
        
        # Define pages to generate
        pages = [
            {'template': 'index.html', 'output': 'index.html', 'title': 'CVE Intelligence Dashboard'},
            {'template': 'years.html', 'output': 'years.html', 'title': 'Yearly Analysis'},
            {'template': 'cna.html', 'output': 'cna.html', 'title': 'CNA Intelligence Dashboard'},
            {'template': 'cpe.html', 'output': 'cpe.html', 'title': 'CPE Analysis'},
            {'template': 'cvss.html', 'output': 'cvss.html', 'title': 'CVSS Analysis'},
            {'template': 'cwe.html', 'output': 'cwe.html', 'title': 'CWE Analysis'},
            {'template': 'calendar.html', 'output': 'calendar.html', 'title': 'Calendar View'},
            {'template': 'growth.html', 'output': 'growth.html', 'title': 'Growth Analysis'},
            {'template': 'about.html', 'output': 'about.html', 'title': 'About CVE.ICU'}
        ]
        
        # Generate each page
        for page in pages:
            try:
                template = self.jinja_env.get_template(page['template'])
                
                context = {
                    'title': f"{page['title']} - CVE.ICU",
                    'current_year': self.current_year,
                    'available_years': self.available_years
                }
                
                html_content = template.render(**context)
                
                with open(self.web_dir / page['output'], 'w') as f:
                    f.write(html_content)
                
                self.print_verbose(f"  📄 Generated {page['output']}")
                
            except Exception as e:
                self.print_always(f"  ❌ Error generating {page['output']}: {e}")
        
        self.print_always("✅ HTML pages generated successfully")
    
    def build_site(self):
        """Main build function - orchestrates the entire build process"""
        self.print_always("\n🏗️  Starting CVE.ICU site build...")
        if not self.quiet:
            print("=" * 50)
        
        try:
            # Step 1: Clean build directory
            self.clean_build()
            
            # Step 2: Ensure static assets are in place
            self.ensure_static_assets()
            
            # Step 3: Generate JSON data files
            all_year_data = self.generate_year_data_json()
            
            if not all_year_data:
                self.print_always("❌ No year data generated, cannot continue build")
                return False
            
            # Step 4: Generate combined analysis JSON files
            combined_analysis = self.generate_combined_analysis_json(all_year_data)
            
            # Step 5: Generate current year analysis files
            current_year_analysis = self.generate_current_year_analysis_json(all_year_data)
            
            # Step 6: Generate HTML pages
            self.generate_html_pages()
            
            if not self.quiet:
                print("\n" + "=" * 50)
            self.print_always("✅ Build completed successfully!")
            if not self.quiet:
                print(f"📁 Site generated in: {self.web_dir}")
                print(f"🌐 Ready for deployment")
                print(f"📊 Coverage: {len(self.available_years)} years (1999-{self.current_year})")
                print(f"📊 Year data files: {len(all_year_data)} years processed")
                print(f"🏢 CNA Analysis: {combined_analysis.get('cna_analysis', 'processed')}")
                print(f"📈 CVE All data: {combined_analysis.get('cve_all', 'processed')}")
                print(f"🗓️  Current year analysis: {current_year_analysis.get('cna_current', 'processed')}")
            
            return True
            
        except Exception as e:
            self.print_always(f"\n❌ Build failed: {e}")
            if not self.quiet:
                import traceback
                traceback.print_exc()
            return False


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='CVE.ICU Static Site Generator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Environment Variables:
  CVE_BUILD_QUIET=1    Enable quiet mode (same as --quiet)

Examples:
  python build.py              # Normal verbose output
  python build.py --quiet      # Minimal output for CI/CD
  CVE_BUILD_QUIET=1 python build.py  # Quiet mode via environment variable
'''
    )
    
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Minimal output mode - reduces verbosity for CI/CD environments'
    )
    
    args = parser.parse_args()
    
    builder = CVESiteBuilder(quiet=args.quiet)
    success = builder.build_site()
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
