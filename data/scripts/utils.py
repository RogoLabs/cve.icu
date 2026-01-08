#!/usr/bin/env python3
"""
Shared utilities for rebuild scripts
"""
from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

# Logging setup
try:
    from data.logging_config import get_logger
except ImportError:
    try:
        from logging_config import get_logger
    except ImportError:
        # Fallback: scripts/ -> data/ path setup may not be done yet
        scripts_dir = Path(__file__).parent
        data_module_dir = scripts_dir.parent
        if str(data_module_dir) not in sys.path:
            sys.path.insert(0, str(data_module_dir))
        from logging_config import get_logger

logger = get_logger(__name__)


def setup_paths() -> tuple[Path, Path, Path]:
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


def load_all_year_data(data_dir: Path) -> list[dict]:
    """
    Load all existing year data files.
    
    Args:
        data_dir: Path to web/data directory containing cve_YYYY.json files
        
    Returns:
        List of year data dictionaries
    """
    all_year_data: list[dict] = []
    current_year = datetime.now().year
    
    for year in range(1999, current_year + 1):
        year_file = data_dir / f'cve_{year}.json'
        if year_file.exists():
            try:
                with open(year_file, 'r') as f:
                    year_data = json.load(f)
                all_year_data.append(year_data)
            except (FileNotFoundError, json.JSONDecodeError, OSError) as e:
                logger.warning(f"Error loading {year_file}: {e}")
    
    return all_year_data


def print_header(title: str, emoji: str = "🔄") -> None:
    """Print a consistent header for rebuild scripts."""
    logger.info(f"CVE.ICU {title}")
    logger.info("=" * 40)


def print_success(message: str) -> None:
    """Print a success message."""
    logger.info(message)


def print_error(message: str) -> None:
    """Print an error message."""
    logger.error(message)
