#!/usr/bin/env python3
"""
Quick template rebuild script - regenerates HTML pages without reprocessing data
"""

import sys
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

# Add data directory to path
sys.path.insert(0, str(Path(__file__).parent / 'data'))

base_dir = Path(__file__).parent
template_dir = base_dir / 'templates'
web_dir = base_dir / 'web'

# Initialize Jinja2 environment
env = Environment(loader=FileSystemLoader(str(template_dir)))

# Get current year
from datetime import datetime
current_year = datetime.now().year

print("🔨 Rebuilding HTML templates...")

# Rebuild index.html
print("  📄 Rebuilding index.html...")
template = env.get_template('index.html')
output = template.render(
    current_year=current_year,
    available_years=list(range(1999, current_year + 1))
)
with open(web_dir / 'index.html', 'w') as f:
    f.write(output)

# Rebuild growth.html
print("  📄 Rebuilding growth.html...")
template = env.get_template('growth.html')
output = template.render(
    title='Growth Intelligence Dashboard',
    current_year=current_year
)
with open(web_dir / 'growth.html', 'w') as f:
    f.write(output)

print("✅ Templates rebuilt successfully!")
print("🌐 View at: file://" + str(web_dir / 'index.html'))
