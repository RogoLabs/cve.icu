#!/usr/bin/env python3
"""
CVSS Analysis Rebuild Script
Quick rebuild script for CVSS analysis only - much faster than full site rebuild
"""
from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from cvss_analysis import CVSSAnalyzer
from scripts.utils import setup_paths, load_all_year_data, print_header

# Logging setup
try:
    from data.logging_config import get_logger
except ImportError:
    from logging_config import get_logger

logger = get_logger(__name__)


def main() -> bool:
    """Rebuild CVSS analysis only"""
    print_header("CVSS Analysis Quick Rebuild", "📊")
    
    # Set up paths
    project_root, cache_dir, data_dir = setup_paths()
    
    # Initialize CVSS analyzer
    cvss_analyzer = CVSSAnalyzer(project_root, cache_dir, data_dir)
    
    try:
        # Load existing year data
        logger.info("Loading existing year data...")
        all_year_data = load_all_year_data(data_dir)
        logger.info(f"Loaded {len(all_year_data)} year data files")
        
        if not all_year_data:
            logger.error("No year data found. Run full build first.")
            return False
        
        # Generate comprehensive CVSS analysis
        logger.info("Generating comprehensive CVSS analysis...")
        cvss_analysis = cvss_analyzer.generate_cvss_analysis(all_year_data)
        
        # Generate current year CVSS analysis
        current_year = datetime.now().year
        current_year_data = next((year for year in all_year_data if year['year'] == current_year), {})
        
        if current_year_data:
            logger.info(f"Generating {current_year} CVSS analysis...")
            current_cvss_analysis = cvss_analyzer.generate_current_year_cvss_analysis(current_year_data)
        else:
            logger.warning(f"No {current_year} data found for current year analysis")
            current_cvss_analysis = {}
        
        logger.info("=" * 40)
        logger.info("CVSS analysis rebuild completed!")
        logger.info(f"Total CVEs with CVSS: {cvss_analysis.get('total_cves_with_cvss', 0):,}")
        logger.info(f"CVSS v2.0: {cvss_analysis.get('total_by_version', {}).get('v2.0', 0):,}")
        logger.info(f"CVSS v3.0: {cvss_analysis.get('total_by_version', {}).get('v3.0', 0):,}")
        logger.info(f"CVSS v3.1: {cvss_analysis.get('total_by_version', {}).get('v3.1', 0):,}")
        logger.info(f"CVSS v4.0: {cvss_analysis.get('total_by_version', {}).get('v4.0', 0):,}")
        logger.info("Files updated:")
        logger.info("   - web/data/cvss_analysis.json")
        if current_cvss_analysis:
            logger.info("   - web/data/cvss_analysis_current_year.json")
        
        return True
        
    except (ImportError, json.JSONDecodeError, OSError) as e:
        logger.error(f"CVSS analysis rebuild failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
