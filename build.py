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
            # Import the years module (will be created in next step)
            from cve_years import CVEYearsAnalyzer
            
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
                    
                    print(f"    ✅ Generated {json_file.name}")
                    
                except Exception as e:
                    print(f"    ⚠️  Warning: Could not process {year}: {e}")
                    # Create empty data structure for missing years
                    empty_data = {
                        'year': year,
                        'total_cves': 0,
                        'monthly_counts': [0] * 12,
                        'severity_distribution': {},
                        'top_vendors': [],
                        'error': str(e)
                    }
                    
                    json_file = self.data_dir / f'cve_{year}.json'
                    with open(json_file, 'w') as f:
                        json.dump(empty_data, f, indent=2)
            
            print("✅ Year data JSON generation complete")
            
        except ImportError:
            print("⚠️  Warning: cve_years module not found. Creating placeholder data...")
            self.create_placeholder_data()
    
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
