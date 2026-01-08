#!/usr/bin/env python3
"""
CPE Analysis Rebuild Script
Quick rebuild script for CPE analysis only - much faster than full site rebuild
"""
from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

import jinja2

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from cpe_analysis import CPEAnalyzer
from scripts.utils import setup_paths, load_all_year_data, print_header

# Logging setup
try:
    from data.logging_config import get_logger
except ImportError:
    from logging_config import get_logger

logger = get_logger(__name__)


def main() -> bool:
    """Main rebuild function"""
    print_header("CPE Analysis Quick Rebuild", "🔍")
    
    # Setup paths
    project_root, cache_dir, data_dir = setup_paths()
    
    # Initialize CPE analyzer
    logger.info("Initializing CPE analyzer...")
    cpe_analyzer = CPEAnalyzer(project_root, cache_dir, data_dir)
    
    # Load existing year data for context (if available)
    logger.info("Loading existing year data...")
    all_year_data = load_all_year_data(data_dir)
    
    if all_year_data:
        logger.info(f"Loaded {len(all_year_data)} existing year data files")
    else:
        logger.warning("No existing year data found - CPE analysis will use raw data only")
    
    # Generate comprehensive CPE analysis
    logger.info("Generating comprehensive CPE analysis...")
    try:
        cpe_analysis = cpe_analyzer.generate_cpe_analysis(all_year_data)
        
        if cpe_analysis and cpe_analysis.get('total_unique_cpes', 0) > 0:
            logger.info(f"Generated comprehensive CPE analysis with {cpe_analysis['total_unique_cpes']:,} unique CPEs")
            logger.info(f"Covers {cpe_analysis['total_cves_with_cpes']:,} CVEs with CPE data")
            logger.info(f"Includes {cpe_analysis['total_unique_vendors']:,} unique vendors")
        else:
            logger.error("CPE analysis failed or returned no data")
            return 1
    
    except (ImportError, json.JSONDecodeError, OSError) as e:
        logger.error(f"Error generating comprehensive CPE analysis: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    # Generate current year CPE analysis
    logger.info("Generating current year CPE analysis...")
    try:
        current_year = datetime.now().year
        current_year_data = next((data for data in all_year_data if data.get('year') == current_year), {})
        
        current_cpe_analysis = cpe_analyzer.generate_current_year_cpe_analysis(current_year_data)
        
        if current_cpe_analysis and current_cpe_analysis.get('total_unique_cpes', 0) > 0:
            logger.info(f"Generated current year CPE analysis with {current_cpe_analysis['total_unique_cpes']:,} unique CPEs")
            logger.info(f"Covers {current_cpe_analysis['total_cves_with_cpes']:,} CVEs for {current_year}")
        else:
            logger.warning(f"Current year CPE analysis returned minimal data for {current_year}")
    
    except (ImportError, json.JSONDecodeError, OSError, KeyError) as e:
        logger.error(f"Error generating current year CPE analysis: {e}")
        import traceback
        traceback.print_exc()
        logger.warning("Current year analysis will be missing")
    
    # Generate CPE page HTML
    logger.info("Generating CPE page HTML...")
    try:
        from jinja2 import Environment, FileSystemLoader
        
        # Setup Jinja2 environment
        template_dir = project_root / 'templates'
        env = Environment(loader=FileSystemLoader(template_dir))
        
        # Load CPE template
        template = env.get_template('cpe.html')
        
        # Render CPE page
        html_content = template.render(
            title="CPE Analysis - CVE.ICU",
            current_year=datetime.now().year
        )
        
        # Save CPE page
        output_file = project_root / 'web' / 'cpe.html'
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"Generated CPE page: {output_file}")
    
    except (ImportError, OSError, jinja2.TemplateError) as e:
        logger.error(f"Error generating CPE page HTML: {e}")
        import traceback
        traceback.print_exc()
        logger.warning("CPE page HTML generation failed")
    
    logger.info("=" * 50)
    logger.info("CPE Analysis Rebuild Complete!")
    logger.info("Files generated:")
    logger.info(f"  {data_dir}/cpe_analysis.json")
    logger.info(f"  {data_dir}/cpe_analysis_current_year.json")
    logger.info(f"  {project_root}/web/cpe.html")
    logger.info("You can now view the CPE analysis page in your browser.")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
