#!/usr/bin/env python3
"""
Growth Analysis Rebuild Script
Standalone script to rebuild growth analysis data and regenerate the Growth Intelligence Dashboard
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from yearly_analysis import YearlyAnalyzer
from scripts.utils import setup_paths, print_header

# Logging setup
try:
    from data.logging_config import get_logger
except ImportError:
    from logging_config import get_logger

logger = get_logger(__name__)


def main() -> bool:
    """Main function to rebuild growth analysis"""
    print_header("Growth Analysis Rebuild", "🚀")
    
    try:
        # Initialize paths
        project_root, cache_dir, _ = setup_paths()
        data_dir = project_root / 'data'  # Growth analysis uses data/ not web/data/
        
        logger.info(f"Base directory: {project_root}")
        logger.info(f"Cache directory: {cache_dir}")
        logger.info(f"Data directory: {data_dir}")
        
        # Initialize analyzer
        logger.info("Initializing Growth Analyzer...")
        analyzer = YearlyAnalyzer(project_root, cache_dir, data_dir)
        
        # Generate year data first (required for growth analysis)
        logger.info("Generating year data...")
        all_year_data = analyzer.generate_year_data_json()
        
        if not all_year_data:
            logger.error("No year data available for growth analysis")
            return False
        
        logger.info(f"Generated data for {len(all_year_data)} years")
        
        # Generate comprehensive growth analysis
        logger.info("Generating comprehensive growth analysis...")
        growth_analysis = analyzer.generate_growth_analysis(all_year_data)
        
        if growth_analysis:
            logger.info("Comprehensive growth analysis generated successfully")
            
            # Display key statistics
            growth_data = growth_analysis.get('growth_data', [])
            if growth_data:
                latest_year = growth_data[-1]
                logger.info(f"Latest year: {latest_year['year']} with {latest_year['cves']:,} CVEs")
                logger.info(f"Average annual growth: {growth_analysis.get('avg_annual_growth', 0)}%")
                
                highest_growth = growth_analysis.get('highest_growth_year')
                if highest_growth:
                    logger.info(f"Peak growth: {highest_growth['year']} ({highest_growth['growth_rate']}%)")
        else:
            logger.error("Failed to generate comprehensive growth analysis")
            return False
        
        # Generate current year growth analysis
        logger.info("Generating current year growth analysis...")
        try:
            current_year = analyzer.current_year
            current_year_data = next((d for d in all_year_data if d.get('year') == current_year), None)
            
            if current_year_data:
                # Create simplified current year growth analysis
                current_year_growth = {
                    'generated_at': growth_analysis['generated_at'],
                    'year': current_year,
                    'growth_data': [d for d in growth_data if d['year'] == current_year],
                    'avg_annual_growth': 0,  # Not applicable for single year
                    'highest_growth_year': None,  # Not applicable for single year
                    'lowest_growth_year': None   # Not applicable for single year
                }
                
                # Save current year analysis
                current_year_file = data_dir / 'growth_analysis_current_year.json'
                with open(current_year_file, 'w') as f:
                    json.dump(current_year_growth, f, indent=2)
                
                logger.info(f"Current year ({current_year}) growth analysis generated")
            else:
                logger.warning(f"No data found for current year {current_year}")
        
        except (KeyError, json.JSONDecodeError, OSError) as e:
            logger.error(f"Error generating current year growth analysis: {e}")
        
        logger.info("Growth analysis rebuild completed successfully!")
        logger.info("Files generated:")
        logger.info("  • growth_analysis.json (comprehensive)")
        logger.info("  • growth_analysis_current_year.json (current year)")
        
        return True
        
    except ImportError as e:
        logger.error(f"Import error: {e}")
        logger.info("Make sure all required modules are available")
        return False
    except (OSError, json.JSONDecodeError, KeyError) as e:
        logger.error(f"File or data error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
