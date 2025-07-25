#!/usr/bin/env python3
"""
CVE.ICU Static Site Generator
Future-proof build system for generating static HTML pages from CVE data
Automatically handles years 1999-present with no manual updates needed
"""

import os
import shutil
import json
from datetime import datetime
from pathlib import Path
import sys

# Add data folder to path for imports
sys.path.append('data')

from jinja2 import Environment, FileSystemLoader, select_autoescape

class CVESiteBuilder:
    """Main class for building the CVE.ICU static site"""
    
    def __init__(self):
        self.current_year = datetime.now().year
        self.available_years = list(range(1999, self.current_year + 1))
        self.base_dir = Path(__file__).parent
        self.templates_dir = self.base_dir / 'templates'
        self.web_dir = self.base_dir / 'web'
        self.static_dir = self.web_dir / 'static'
        self.data_dir = self.web_dir / 'data'
        self.data_scripts_dir = self.base_dir / 'data'
        
        # Set up Jinja2 environment
        self.jinja_env = Environment(
            loader=FileSystemLoader(self.templates_dir),
            autoescape=select_autoescape(['html', 'xml'])
        )
        
        # Add custom filters and globals
        self.jinja_env.globals['current_year'] = self.current_year
        self.jinja_env.globals['available_years'] = self.available_years
        self.jinja_env.filters['format_number'] = self.format_number
        
        print(f"🚀 CVE.ICU Build System Initialized")
        print(f"📅 Current Year: {self.current_year}")
        print(f"📊 Coverage: 1999-{self.current_year} ({len(self.available_years)} years)")
        print(f"🌐 Web output: {self.web_dir}")
        print(f"📁 Data scripts: {self.data_scripts_dir}")
    
    def format_number(self, num):
        """Format numbers for display (e.g., 1000 -> 1K)"""
        if num >= 1000000:
            return f"{num / 1000000:.1f}M"
        elif num >= 1000:
            return f"{num / 1000:.1f}K"
        return str(num)
    
    def clean_build(self):
        """Clean and recreate the web directory"""
        print("🧹 Cleaning web directory...")
        
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
        
        print("✅ Web directory cleaned and recreated")
    
    def ensure_static_assets(self):
        """Ensure static assets are in place (they should already be in web/static)"""
        print("📁 Checking static assets...")
        
        if not self.static_dir.exists():
            print("⚠️  Warning: Static directory not found, creating...")
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
                print(f"  ✅ Found {file_path}")
            else:
                print(f"  ⚠️  Missing {file_path}")
        
        print("✅ Static assets check complete")
    
    def generate_year_data_json(self):
        """Generate JSON data files for all available years"""
        print("📊 Generating year data JSON files...")
        
        try:
            # Import the years analyzer
            from cve_years import CVEYearsAnalyzer
            
            print("🔽 Initializing CVE data processing...")
            analyzer = CVEYearsAnalyzer()
            
            # Generate JSON for each available year
            for year in self.available_years:
                print(f"  📅 Processing {year}...")
                
                try:
                    year_data = analyzer.get_year_data(year)
                    
                    # Save to JSON file
                    json_file = self.data_dir / f'cve_{year}.json'
                    with open(json_file, 'w') as f:
                        json.dump(year_data, f, indent=2, default=str)
                    
                    cve_count = year_data.get('total_cves', 0)
                    print(f"    ✅ Generated {json_file.name} ({cve_count:,} CVEs)")
                    
                except Exception as e:
                    print(f"    ⚠️  Warning: Could not process {year}: {e}")
                    # Create empty data structure for missing years
                    empty_data = {
                        'year': year,
                        'total_cves': 0,
                        'monthly_counts': [0] * 12,
                        'severity_distribution': {},
                        'top_vendors': [],
                        'top_cwes': [],
                        'error': str(e),
                        'processing_stats': {
                            'processed_at': datetime.now().isoformat(),
                            'status': 'failed'
                        }
                    }
                    
                    json_file = self.data_dir / f'cve_{year}.json'
                    with open(json_file, 'w') as f:
                        json.dump(empty_data, f, indent=2)
            
            # Generate summary statistics
            try:
                print("📊 Generating summary statistics...")
                summary_stats = analyzer.generate_summary_stats()
                summary_file = self.data_dir / 'summary_stats.json'
                with open(summary_file, 'w') as f:
                    json.dump(summary_stats, f, indent=2, default=str)
                print(f"    ✅ Generated {summary_file.name}")
            except Exception as e:
                print(f"    ⚠️  Warning: Could not generate summary: {e}")
            
            print("✅ Year data JSON generation complete")
            
        except ImportError as e:
            print(f"⚠️  Warning: Could not import cve_years module: {e}")
            print("🔧 Creating placeholder data for development...")
            self.create_placeholder_data()
    
    def generate_combined_analysis_json(self):
        """Generate combined analysis JSON files aggregating data across all years"""
        print("📊 Generating combined analysis JSON files...")
        
        try:
            # Load all year data
            all_year_data = {}
            for year in self.available_years:
                json_file = self.data_dir / f'cve_{year}.json'
                if json_file.exists():
                    with open(json_file, 'r') as f:
                        all_year_data[year] = json.load(f)
            
            print(f"  📊 Loaded data for {len(all_year_data)} years")
            
            # Generate each combined analysis file
            self.generate_cve_all_json(all_year_data)
            self.generate_cna_analysis_json(all_year_data)
            self.generate_cpe_analysis_json(all_year_data)
            self.generate_cvss_analysis_json(all_year_data)
            self.generate_cwe_analysis_json(all_year_data)
            self.generate_calendar_analysis_json(all_year_data)
            self.generate_growth_analysis_json(all_year_data)
            
            print("✅ Combined analysis JSON generation complete")
            
        except Exception as e:
            print(f"❌ Failed to generate combined analysis JSON: {e}")
            import traceback
            traceback.print_exc()
    
    def generate_cve_all_json(self, all_year_data):
        """Generate overall CVE statistics across all years"""
        total_cves = sum(data['total_cves'] for data in all_year_data.values())
        
        # Aggregate monthly data across all years
        monthly_totals = [0] * 12
        for year_data in all_year_data.values():
            monthly_dist = year_data.get('date_data', {}).get('monthly_distribution', {})
            for month, count in monthly_dist.items():
                monthly_totals[int(month) - 1] += count
        
        # Aggregate CVSS data across all years
        cvss_totals = {}
        for year_data in all_year_data.values():
            cvss_data = year_data.get('cvss', {})
            for version, version_data in cvss_data.items():
                if version not in cvss_totals:
                    cvss_totals[version] = {'total': 0, 'severity_distribution': {}}
                cvss_totals[version]['total'] += version_data.get('total', 0)
                
                for severity, count in version_data.get('severity_distribution', {}).items():
                    if severity not in cvss_totals[version]['severity_distribution']:
                        cvss_totals[version]['severity_distribution'][severity] = 0
                    cvss_totals[version]['severity_distribution'][severity] += count
        
        cve_all_data = {
            'total_cves': total_cves,
            'year_range': f"{min(all_year_data.keys())}-{max(all_year_data.keys())}",
            'years_covered': len(all_year_data),
            'monthly_totals': {str(i+1): monthly_totals[i] for i in range(12)},
            'cvss_totals': cvss_totals,
            'processing_stats': {
                'processed_at': datetime.now().isoformat(),
                'data_source': 'aggregated_from_yearly_data'
            }
        }
        
        with open(self.data_dir / 'cve_all.json', 'w') as f:
            json.dump(cve_all_data, f, indent=2)
        print("  📄 Generated cve_all.json")
    
    def generate_cna_analysis_json(self, all_year_data):
        """Generate CNA analysis across all years"""
        from collections import Counter
        
        all_cna_counts = Counter()
        yearly_cna_data = {}
        
        for year, year_data in all_year_data.items():
            cna_assigners = year_data.get('vendors', {}).get('cna_assigners', [])
            yearly_cna_data[year] = cna_assigners
            
            for cna in cna_assigners:
                all_cna_counts[cna['name']] += cna['count']
        
        cna_analysis_data = {
            'top_cna_assigners_all_time': [
                {'name': name, 'count': count}
                for name, count in all_cna_counts.most_common(50)
            ],
            'yearly_breakdown': yearly_cna_data,
            'total_unique_cnas': len(all_cna_counts),
            'processing_stats': {
                'processed_at': datetime.now().isoformat(),
                'data_source': 'aggregated_from_yearly_data'
            }
        }
        
        with open(self.data_dir / 'cna_analysis.json', 'w') as f:
            json.dump(cna_analysis_data, f, indent=2)
        print("  📄 Generated cna_analysis.json")
    
    def generate_cpe_analysis_json(self, all_year_data):
        """Generate CPE vendor analysis across all years"""
        from collections import Counter
        
        all_cpe_counts = Counter()
        yearly_cpe_data = {}
        
        for year, year_data in all_year_data.items():
            cpe_vendors = year_data.get('vendors', {}).get('cpe_vendors', [])
            yearly_cpe_data[year] = cpe_vendors
            
            for vendor in cpe_vendors:
                all_cpe_counts[vendor['name']] += vendor['count']
        
        cpe_analysis_data = {
            'top_cpe_vendors_all_time': [
                {'name': name, 'count': count}
                for name, count in all_cpe_counts.most_common(50)
            ],
            'yearly_breakdown': yearly_cpe_data,
            'total_unique_vendors': len(all_cpe_counts),
            'processing_stats': {
                'processed_at': datetime.now().isoformat(),
                'data_source': 'aggregated_from_yearly_data'
            }
        }
        
        with open(self.data_dir / 'cpe_analysis.json', 'w') as f:
            json.dump(cpe_analysis_data, f, indent=2)
        print("  📄 Generated cpe_analysis.json")
    
    def generate_cvss_analysis_json(self, all_year_data):
        """Generate CVSS analysis across all years"""
        cvss_evolution = {}
        cvss_totals = {}
        
        for year, year_data in all_year_data.items():
            cvss_data = year_data.get('cvss', {})
            cvss_evolution[year] = cvss_data
            
            for version, version_data in cvss_data.items():
                if version not in cvss_totals:
                    cvss_totals[version] = {'total': 0, 'severity_distribution': {}}
                cvss_totals[version]['total'] += version_data.get('total', 0)
                
                for severity, count in version_data.get('severity_distribution', {}).items():
                    if severity not in cvss_totals[version]['severity_distribution']:
                        cvss_totals[version]['severity_distribution'][severity] = 0
                    cvss_totals[version]['severity_distribution'][severity] += count
        
        cvss_analysis_data = {
            'cvss_evolution_by_year': cvss_evolution,
            'cvss_totals_all_time': cvss_totals,
            'processing_stats': {
                'processed_at': datetime.now().isoformat(),
                'data_source': 'aggregated_from_yearly_data'
            }
        }
        
        with open(self.data_dir / 'cvss_analysis.json', 'w') as f:
            json.dump(cvss_analysis_data, f, indent=2)
        print("  📄 Generated cvss_analysis.json")
    
    def generate_cwe_analysis_json(self, all_year_data):
        """Generate CWE analysis across all years"""
        from collections import Counter
        
        all_cwe_counts = Counter()
        yearly_cwe_data = {}
        
        for year, year_data in all_year_data.items():
            top_cwes = year_data.get('cwe', {}).get('top_cwes', [])
            yearly_cwe_data[year] = top_cwes
            
            for cwe in top_cwes:
                all_cwe_counts[cwe['cwe']] += cwe['count']
        
        cwe_analysis_data = {
            'top_cwes_all_time': [
                {'cwe': cwe, 'count': count}
                for cwe, count in all_cwe_counts.most_common(50)
            ],
            'yearly_breakdown': yearly_cwe_data,
            'total_unique_cwes': len(all_cwe_counts),
            'processing_stats': {
                'processed_at': datetime.now().isoformat(),
                'data_source': 'aggregated_from_yearly_data'
            }
        }
        
        with open(self.data_dir / 'cwe_analysis.json', 'w') as f:
            json.dump(cwe_analysis_data, f, indent=2)
        print("  📄 Generated cwe_analysis.json")
    
    def generate_calendar_analysis_json(self, all_year_data):
        """Generate calendar/temporal analysis across all years"""
        from collections import defaultdict
        
        # Aggregate daily data across all years
        all_daily_data = defaultdict(int)
        monthly_trends = defaultdict(list)
        
        for year, year_data in all_year_data.items():
            daily_analysis = year_data.get('date_data', {}).get('daily_analysis', {})
            daily_counts = daily_analysis.get('daily_counts', {})
            
            # Add to overall daily data
            for date_str, count in daily_counts.items():
                all_daily_data[date_str] += count
            
            # Track monthly trends
            monthly_dist = year_data.get('date_data', {}).get('monthly_distribution', {})
            for month, count in monthly_dist.items():
                monthly_trends[int(month)].append({'year': year, 'count': count})
        
        calendar_analysis_data = {
            'daily_data_all_years': dict(all_daily_data),
            'monthly_trends': {str(k): v for k, v in monthly_trends.items()},
            'processing_stats': {
                'processed_at': datetime.now().isoformat(),
                'data_source': 'aggregated_from_yearly_data'
            }
        }
        
        with open(self.data_dir / 'calendar_analysis.json', 'w') as f:
            json.dump(calendar_analysis_data, f, indent=2)
        print("  📄 Generated calendar_analysis.json")
    
    def generate_growth_analysis_json(self, all_year_data):
        """Generate growth trend analysis across all years"""
        yearly_totals = []
        cumulative_total = 0
        
        for year in sorted(all_year_data.keys()):
            year_data = all_year_data[year]
            year_total = year_data['total_cves']
            cumulative_total += year_total
            
            yearly_totals.append({
                'year': year,
                'cves': year_total,
                'cumulative': cumulative_total
            })
        
        # Calculate growth rates
        for i in range(1, len(yearly_totals)):
            prev_count = yearly_totals[i-1]['cves']
            curr_count = yearly_totals[i]['cves']
            if prev_count > 0:
                growth_rate = ((curr_count - prev_count) / prev_count) * 100
                yearly_totals[i]['growth_rate'] = round(growth_rate, 2)
            else:
                yearly_totals[i]['growth_rate'] = 0
        
        growth_analysis_data = {
            'yearly_growth': yearly_totals,
            'total_cves_all_time': cumulative_total,
            'processing_stats': {
                'processed_at': datetime.now().isoformat(),
                'data_source': 'aggregated_from_yearly_data'
            }
        }
        
        with open(self.data_dir / 'growth_analysis.json', 'w') as f:
            json.dump(growth_analysis_data, f, indent=2)
        print("  📄 Generated growth_analysis.json")
    
    def create_placeholder_data(self):
        """Create placeholder JSON data for development/testing"""
        print("🔧 Creating placeholder data for development...")
        
        for year in self.available_years:
            # Create realistic-looking placeholder data
            placeholder_data = {
                'year': year,
                'total_cves': max(100, (year - 1999) * 500 + 1000),  # Realistic growth
                'monthly_counts': [50 + i * 10 for i in range(12)],
                'severity_distribution': {
                    'CRITICAL': 15,
                    'HIGH': 35,
                    'MEDIUM': 35,
                    'LOW': 15
                },
                'top_vendors': [
                    {'vendor': 'Microsoft', 'count': 150},
                    {'vendor': 'Adobe', 'count': 120},
                    {'vendor': 'Google', 'count': 100},
                    {'vendor': 'Apple', 'count': 80},
                    {'vendor': 'Oracle', 'count': 75}
                ],
                'placeholder': True
            }
            
            json_file = self.data_dir / f'cve_{year}.json'
            with open(json_file, 'w') as f:
                json.dump(placeholder_data, f, indent=2)
        
        print("✅ Placeholder data created")
    
    def generate_html_pages(self):
        """Generate all HTML pages from templates"""
        print("📄 Generating HTML pages...")
        
        # Generate index page
        self.generate_index_page()
        
        # Generate years page
        self.generate_years_page()
        
        # Generate analysis pages (placeholders for now)
        analysis_pages = ['cna', 'cpe', 'cvss', 'cwe', 'calendar', 'growth']
        for page in analysis_pages:
            self.generate_analysis_page(page)
        
        print("✅ HTML pages generated successfully")
    
    def generate_index_page(self):
        """Generate the homepage"""
        try:
            template = self.jinja_env.get_template('index.html')
            
            # Calculate summary statistics
            context = {
                'title': 'CVE.ICU - CVE Analysis Dashboard',
                'current_year': self.current_year,
                'available_years': self.available_years
            }
            
            html_content = template.render(**context)
            
            with open(self.web_dir / 'index.html', 'w') as f:
                f.write(html_content)
            
            print("  📄 Generated index.html")
            
        except Exception as e:
            print(f"  ❌ Failed to generate index.html: {e}")
    
    def generate_years_page(self):
        """Generate the interactive years comparison page"""
        try:
            template = self.jinja_env.get_template('years.html')
            
            context = {
                'title': 'Year Analysis - CVE.ICU',
                'available_years': self.available_years,
                'current_year': self.current_year
            }
            
            html_content = template.render(**context)
            
            with open(self.web_dir / 'years.html', 'w') as f:
                f.write(html_content)
            
            print("  📄 Generated years.html")
            
        except Exception as e:
            print(f"  ❌ Failed to generate years.html: {e}")
    
    def generate_analysis_page(self, page_name):
        """Generate individual analysis pages"""
        try:
            # Try to load existing template
            try:
                template = self.jinja_env.get_template(f'{page_name}.html')
            except:
                # Create a basic template if it doesn't exist
                self.create_basic_analysis_template(page_name)
                template = self.jinja_env.get_template(f'{page_name}.html')
            
            context = {
                'title': f'{page_name.upper()} Analysis - CVE.ICU',
                'page_name': page_name,
                'current_year': self.current_year
            }
            
            html_content = template.render(**context)
            
            with open(self.web_dir / f'{page_name}.html', 'w') as f:
                f.write(html_content)
            
            print(f"  📄 Generated {page_name}.html")
            
        except Exception as e:
            print("  Failed to generate {}.html: {}".format(page_name, e))
    
    def create_basic_analysis_template(self, page_name):
        """Create a basic analysis template if none exists"""
        page_upper = page_name.upper()
        
        # Build template content using string formatting
        template_lines = [
            '{% extends "base.html" %}',
            '',
            '{% block title %}{{ title }}{% endblock %}',
            '',
            '{% block content %}',
            '<div class="page-header">',
            f'    <h1 class="page-title">{page_upper} Analysis</h1>',
            '    <p class="page-subtitle">',
            f'        Comprehensive {page_upper} analysis and visualization',
            '    </p>',
            '</div>',
            '',
            '<div class="main-content">',
            f'    <h2>{page_upper} Analysis</h2>',
            f'    <p>This page will contain detailed {page_upper} analysis once the data processing modules are implemented.</p>',
            '    ',
            '    <div class="chart-container">',
            f'        <h3>{page_upper} Overview</h3>',
            '        <div class="chart-wrapper">',
            f'            <canvas id="{page_name}Chart"></canvas>',
            '        </div>',
            '    </div>',
            '</div>',
            '{% endblock %}',
            '',
            '{% block scripts %}',
            '<script>',
            f'// {page_upper} analysis functionality will be implemented here',
            'document.addEventListener(\'DOMContentLoaded\', function() {',
            f'    console.log(\'{page_upper} analysis page loaded\');',
            '    // Chart initialization will go here',
            '});',
            '</script>',
            '{% endblock %}'
        ]
        
        template_content = '\n'.join(template_lines)
        
        with open(self.templates_dir / '{}.html'.format(page_name), 'w') as f:
            f.write(template_content)
    
    def build_site(self):
        """Main build function - orchestrates the entire build process"""
        print("\n🏗️  Starting CVE.ICU site build...")
        print("=" * 50)
        
        try:
            # Step 1: Clean build directory
            self.clean_build()
            
            # Step 2: Ensure static assets are in place
            self.ensure_static_assets()
            
            # Step 3: Generate JSON data files
            self.generate_year_data_json()
            
            # Step 4: Generate combined analysis JSON files
            self.generate_combined_analysis_json()
            
            # Step 5: Generate HTML pages
            self.generate_html_pages()
            
            print("\n" + "=" * 50)
            print("✅ Build completed successfully!")
            print(f"📁 Site generated in: {self.web_dir}")
            print(f"🌐 Ready for deployment to GitHub Pages")
            print(f"📊 Coverage: {len(self.available_years)} years (1999-{self.current_year})")
            
            return True
            
        except Exception as e:
            print(f"\n❌ Build failed: {e}")
            import traceback
            traceback.print_exc()
            return False

def main():
    """Main entry point"""
    builder = CVESiteBuilder()
    success = builder.build_site()
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()
