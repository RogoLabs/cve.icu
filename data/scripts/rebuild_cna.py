#!/usr/bin/env python3
"""
CNA Analysis Rebuild Script
Quick rebuild script for CNA analysis only - much faster than full site rebuild
"""
from __future__ import annotations

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from cve_v5_processor import CVEV5Processor
from scripts.utils import setup_paths, print_header

# Logging setup
try:
    from data.logging_config import get_logger
except ImportError:
    from logging_config import get_logger

logger = get_logger(__name__)


def main() -> bool:
    """Rebuild CNA analysis only"""
    print_header("CNA Analysis Quick Rebuild", "🏢")
    
    # Set up paths
    project_root, cache_dir, data_dir = setup_paths()
    
    # Initialize CVE V5 processor
    v5_processor = CVEV5Processor(project_root, cache_dir, data_dir)
    
    try:
        # Generate comprehensive CNA analysis using CVE V5 data
        logger.info("Generating comprehensive CNA analysis (CVE V5 authoritative)...")
        cna_analysis = v5_processor.generate_comprehensive_cna_analysis()
        
        # Generate current year CNA analysis with new publication date logic
        logger.info(f"Generating {v5_processor.current_year} CNA analysis (by publication date)...")
        current_cna_analysis = v5_processor.generate_current_year_analysis()
        
        logger.info("=" * 40)
        logger.info("CNA analysis rebuild completed!")
        logger.info(f"Total CNAs: {cna_analysis.get('total_cnas', 0)}")
        logger.info(f"Active CNAs: {cna_analysis.get('active_cnas', 0)}")
        logger.info(f"Current year CNAs: {current_cna_analysis.get('total_cnas', 0)}")
        logger.info("Files updated:")
        logger.info("   - web/data/cna_analysis.json")
        logger.info("   - web/data/cna_analysis_current_year.json")
        
        return True
        
    except (ImportError, json.JSONDecodeError, OSError) as e:
        logger.error(f"CNA analysis rebuild failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
