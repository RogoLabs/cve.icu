#!/usr/bin/env python3
"""
Quick template rebuild script - regenerates HTML pages without reprocessing data
"""
from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

# Get project root (scripts -> data -> project root)
project_root = Path(__file__).parent.parent.parent
template_dir = project_root / 'templates'
web_dir = project_root / 'web'

# Logging setup
sys.path.insert(0, str(project_root / 'data'))
try:
    from data.logging_config import get_logger
except ImportError:
    from logging_config import get_logger

logger = get_logger(__name__)

# Initialize Jinja2 environment
env = Environment(loader=FileSystemLoader(str(template_dir)))

# Get current year
current_year = datetime.now().year

logger.info("Rebuilding HTML templates...")

# Rebuild index.html
logger.info("Rebuilding index.html...")
template = env.get_template('index.html')
output = template.render(
    current_year=current_year,
    available_years=list(range(1999, current_year + 1))
)
with open(web_dir / 'index.html', 'w') as f:
    f.write(output)

# Rebuild growth.html
logger.info("Rebuilding growth.html...")
template = env.get_template('growth.html')
output = template.render(
    title='Growth Intelligence Dashboard',
    current_year=current_year
)
with open(web_dir / 'growth.html', 'w') as f:
    f.write(output)

logger.info("Templates rebuilt successfully!")
logger.info(f"View at: file://{web_dir / 'index.html'}")
