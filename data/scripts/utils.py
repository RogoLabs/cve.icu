#!/usr/bin/env python3
"""
Shared utilities for rebuild scripts
"""

import json
import sys
from datetime import datetime
from pathlib import Path


def setup_paths():
    """
    Set up paths and ensure parent modules are importable.
    
    Returns:
        tuple: (project_root, cache_dir, data_dir)
    """
    # scripts/ -> data/ -> project root
    scripts_dir = Path(__file__).parent
    data_module_dir = scripts_dir.parent
    project_root = data_module_dir.parent
    
    # Add data/ to path for importing analysis modules
    if str(data_module_dir) not in sys.path:
        sys.path.insert(0, str(data_module_dir))
    
    cache_dir = data_module_dir / 'cache'
    web_data_dir = project_root / 'web' / 'data'
    
    # Ensure directories exist
    web_data_dir.mkdir(parents=True, exist_ok=True)
    
    return project_root, cache_dir, web_data_dir


def load_all_year_data(data_dir: Path) -> list:
    """
    Load all existing year data files.
    
    Args:
        data_dir: Path to web/data directory containing cve_YYYY.json files
        
    Returns:
        List of year data dictionaries
    """
    all_year_data = []
    current_year = datetime.now().year
    
    for year in range(1999, current_year + 1):
        year_file = data_dir / f'cve_{year}.json'
        if year_file.exists():
            try:
                with open(year_file, 'r') as f:
                    year_data = json.load(f)
                all_year_data.append(year_data)
            except Exception as e:
                print(f"  ⚠️  Error loading {year_file}: {e}")
    
    return all_year_data


def print_header(title: str, emoji: str = "🔄"):
    """Print a consistent header for rebuild scripts."""
    print(f"{emoji} CVE.ICU {title}")
    print("=" * 40)


def print_success(message: str):
    """Print a success message."""
    print(f"✅ {message}")


def print_error(message: str):
    """Print an error message."""
    print(f"❌ {message}")
