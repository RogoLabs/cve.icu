#!/usr/bin/env python3
"""
CWE Analysis Rebuild Script
Quick rebuild script for CWE analysis only - much faster than full site rebuild
"""
from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from cwe_analysis import CWEAnalyzer
from scripts.utils import setup_paths, load_all_year_data, print_header

# Logging setup
try:
    from data.logging_config import get_logger
except ImportError:
    from logging_config import get_logger

logger = get_logger(__name__)


def main() -> bool:
    """Rebuild CWE analysis only"""
    print_header("CWE Analysis Quick Rebuild", "🔍")
    
    # Set up paths
    project_root, cache_dir, data_dir = setup_paths()
    
    # Initialize CWE analyzer
    cwe_analyzer = CWEAnalyzer(project_root, cache_dir, data_dir)
    
    try:
        # Load existing year data
        logger.info("Loading existing year data...")
        all_year_data = load_all_year_data(data_dir)
        logger.info(f"Loaded {len(all_year_data)} year data files")
        
        if not all_year_data:
            logger.error("No year data found. Run full build first.")
            return False
        
        # Generate comprehensive CWE analysis
        logger.info("Generating comprehensive CWE analysis...")
        cwe_analysis = cwe_analyzer.generate_cwe_analysis(all_year_data)
        
        # Generate current year CWE analysis
        current_year = datetime.now().year
        current_year_data = next((year for year in all_year_data if year['year'] == current_year), {})
        
        if current_year_data:
            logger.info(f"Generating {current_year} CWE analysis...")
            current_cwe_analysis = cwe_analyzer.generate_current_year_cwe_analysis(current_year_data)
        else:
            logger.warning(f"No {current_year} data found for current year analysis")
            current_cwe_analysis = {}
        
        logger.info("=" * 40)
        logger.info("CWE analysis rebuild completed!")
        logger.info(f"Total CVEs with CWE: {cwe_analysis.get('total_cves_with_cwe', 0):,}")
        logger.info(f"Unique CWEs: {cwe_analysis.get('total_unique_cwes', 0):,}")
        logger.info(f"Top CWEs available: {len(cwe_analysis.get('top_cwes', []))}")
        logger.info("Files updated:")
        logger.info("   - web/data/cwe_analysis.json")
        if current_cwe_analysis:
            logger.info("   - web/data/cwe_analysis_current_year.json")
        
        return True
        
    except (ImportError, json.JSONDecodeError, OSError) as e:
        logger.error(f"CWE analysis rebuild failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
