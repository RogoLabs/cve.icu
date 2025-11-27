#!/usr/bin/env python3
"""
CVE.ICU Quick Template Builder
Fast template-only rebuild for development - skips data processing
"""

import shutil
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

class CVEQuickBuilder:
    """Fast template-only builder for development"""
    
    def __init__(self):
        self.current_year = datetime.now().year
        self.available_years = list(range(1999, self.current_year + 1))
        # Go up two levels: scripts -> data -> project root
        self.project_root = Path(__file__).parent.parent.parent
        self.templates_dir = self.project_root / 'templates'
        self.web_dir = self.project_root / 'web'
        self.static_dir = self.web_dir / 'static'
        self.data_dir = self.web_dir / 'data'
        
        # Set up Jinja2 environment
        self.jinja_env = Environment(
            loader=FileSystemLoader(self.templates_dir),
            autoescape=select_autoescape(['html', 'xml'])
        )
        
        # Add custom filters and globals
        self.jinja_env.globals['current_year'] = self.current_year
        self.jinja_env.globals['available_years'] = self.available_years
        self.jinja_env.filters['format_number'] = self.format_number
        
        print(f"⚡ CVE.ICU Quick Template Builder")
        print(f"📅 Current Year: {self.current_year}")
        print(f"📂 Templates: {self.templates_dir}")
        print(f"🌐 Web output: {self.web_dir}")
    
    def format_number(self, num):
        """Format numbers with commas"""
        if isinstance(num, (int, float)):
            return f"{num:,}"
        return str(num)
    
    def copy_static_assets(self):
        """Copy static assets (CSS, JS, images) if they don't exist"""
        print("📁 Checking static assets...")
        
        # Only copy if static directory doesn't exist or is empty
        if not self.static_dir.exists() or not any(self.static_dir.iterdir()):
            print("  📁 Copying static assets...")
            
            # Copy from project root static if it exists
            template_static = self.project_root / 'static'
            if template_static.exists():
                if self.static_dir.exists():
                    shutil.rmtree(self.static_dir)
                shutil.copytree(template_static, self.static_dir)
                print("  ✅ Static assets copied")
            else:
                print("  ⚠️  No static assets found to copy")
        else:
            print("  ✅ Static assets already exist")
    
    def generate_html_pages(self):
        """Generate HTML pages from templates"""
        print("📄 Generating HTML pages...")
        
        # Define pages to generate
        pages = [
            ('index.html', 'CVE.ICU - Vulnerability Intelligence Platform'),
            ('years.html', 'Yearly Analysis - CVE.ICU'),
            ('cna-hub.html', 'CNA Intelligence Hub - CVE.ICU'),
            ('cna.html', 'CNA Analysis - CVE.ICU'),
            ('cpe.html', 'CPE Analysis - CVE.ICU'),
            ('cvss.html', 'CVSS Analysis - CVE.ICU'),
            ('cwe.html', 'CWE Analysis - CVE.ICU'),
            ('calendar.html', 'Calendar View - CVE.ICU'),
            ('growth.html', 'Growth Trends - CVE.ICU'),
            ('about.html', 'About CVE.ICU - Vulnerability Intelligence Platform'),
            ('scoring.html', 'Scoring Hub - CVE.ICU'),
            ('epss.html', 'EPSS Analysis - CVE.ICU'),
            ('kev.html', 'KEV Dashboard - CVE.ICU'),
            ('data-quality.html', 'CNA Name Matching - CVE.ICU'),
        ]
        
        for template_name, title in pages:
            try:
                template = self.jinja_env.get_template(template_name)
                
                # Basic context for all pages
                context = {
                    'title': title,
                    'current_year': self.current_year,
                    'available_years': self.available_years,
                }
                
                # Add page-specific context
                if template_name == 'cna.html':
                    context.update({
                        'cna_data': [],  # Empty for now - will be populated by JavaScript
                        'total_cna_cves': 0,
                        'active_cnas': 0,
                        'avg_cves_per_cna': 0,
                    })
                
                html_content = template.render(**context)
                
                output_path = self.web_dir / template_name
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                
                print(f"  📄 Generated {template_name}")
                
            except Exception as e:
                print(f"  ❌ Error generating {template_name}: {e}")
                continue
        
        print("✅ HTML pages generated successfully")
    
    def build(self):
        """Main build method - templates only"""
        print("\n🏗️  Starting quick template build...")
        print("=" * 50)
        
        # Ensure web directory exists
        self.web_dir.mkdir(exist_ok=True)
        
        # Copy static assets if needed
        self.copy_static_assets()
        
        # Generate HTML pages
        self.generate_html_pages()
        
        print("\n" + "=" * 50)
        print("✅ Quick build completed!")
        print(f"📁 Site ready in: {self.web_dir}")
        print("🌐 Templates updated - data files unchanged")
        print("⚡ Build time: ~1 second vs ~5 minutes")

def main():
    """Main entry point"""
    builder = CVEQuickBuilder()
    builder.build()

if __name__ == "__main__":
    main()
