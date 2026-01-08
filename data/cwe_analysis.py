#!/usr/bin/env python3
"""
CWE Analysis Module
Handles all CWE (Common Weakness Enumeration) related data processing and analysis
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    from data.logging_config import get_logger
except ImportError:
    from logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class CWEAnalyzer:
    """Handles CWE-specific analysis and data processing"""
    base_dir: Path
    cache_dir: Path
    data_dir: Path
    quiet: bool = False
    current_year: int = field(default_factory=lambda: datetime.now().year)
    
    def __post_init__(self) -> None:
        """Convert path arguments to Path objects if needed."""
        self.base_dir = Path(self.base_dir)
        self.cache_dir = Path(self.cache_dir)
        self.data_dir = Path(self.data_dir)
    
    def generate_cwe_analysis(self, all_year_data: list[dict[str, Any]]) -> dict[str, Any]:
        """Generate CWE analysis across all years"""
        if not self.quiet:
            logger.info(f"  🔍 Generating CWE analysis...")
        
        # Aggregate CWE data from all years
        combined_cwe = {}
        
        for year_data in all_year_data:
            if 'cwe' in year_data and 'top_cwes' in year_data['cwe']:
                # Aggregate CWE counts
                for cwe_entry in year_data['cwe']['top_cwes']:
                    cwe_full = cwe_entry['cwe']  # e.g., "CWE-79"
                    cwe_id = cwe_full.replace('CWE-', '') if cwe_full.startswith('CWE-') else cwe_full
                    count = cwe_entry['count']
                    
                    if cwe_id not in combined_cwe:
                        combined_cwe[cwe_id] = {
                            'id': cwe_id,
                            'name': cwe_entry.get('name', f'CWE-{cwe_id}'),
                            'count': 0
                        }
                    
                    combined_cwe[cwe_id]['count'] += count
        
        # Sort by count and get top CWEs
        top_cwes = sorted(combined_cwe.values(), key=lambda x: x['count'], reverse=True)
        
        # Calculate total CVEs with CWE from aggregated counts
        total_cves_with_cwe = sum(cwe['count'] for cwe in combined_cwe.values())
        
        # Add common CWE descriptions for better understanding
        cwe_descriptions = {
            '79': 'Cross-site Scripting (XSS)',
            '89': 'SQL Injection',
            '20': 'Improper Input Validation',
            '22': 'Path Traversal',
            '352': 'Cross-Site Request Forgery (CSRF)',
            '78': 'OS Command Injection',
            '190': 'Integer Overflow',
            '476': 'NULL Pointer Dereference',
            '94': 'Code Injection',
            '119': 'Buffer Overflow',
            '125': 'Out-of-bounds Read',
            '787': 'Out-of-bounds Write',
            '416': 'Use After Free',
            '200': 'Information Exposure',
            '434': 'Unrestricted Upload of File',
            '862': 'Missing Authorization',
            '863': 'Incorrect Authorization',
            '269': 'Improper Privilege Management',
            '287': 'Improper Authentication',
            '295': 'Improper Certificate Validation'
        }
        
        # Enhance CWE entries with descriptions
        for cwe in top_cwes:
            cwe_id = cwe['id']
            if cwe_id in cwe_descriptions:
                cwe['description'] = cwe_descriptions[cwe_id]
                cwe['name'] = f"CWE-{cwe_id}: {cwe_descriptions[cwe_id]}"
            else:
                cwe['description'] = f"CWE-{cwe_id}"
        
        cwe_analysis = {
            'generated_at': datetime.now().isoformat(),
            'total_cves_with_cwe': total_cves_with_cwe,
            'total_unique_cwes': len(combined_cwe),
            'top_cwes': top_cwes,  # All CWEs
            'top_cwes_limited': top_cwes[:20]  # Top 20 for charts
        }
        
        # Save to file
        output_file = self.data_dir / 'cwe_analysis.json'
        with open(output_file, 'w') as f:
            json.dump(cwe_analysis, f, indent=2)
        
        if not self.quiet:
            logger.info(f"  ✅ Generated CWE analysis with {len(combined_cwe):,} unique CWEs")
        return cwe_analysis
    
    def generate_current_year_cwe_analysis(self, current_year_data: dict[str, Any]) -> dict[str, Any]:
        """Generate current year CWE analysis"""
        if not self.quiet:
            logger.info(f"    🔍 Generating current year CWE analysis...")
        
        # Extract CWE data from current year
        cwe_data = current_year_data.get('cwe', {})
        
        if not cwe_data or 'top_cwes' not in cwe_data:
            logger.warning(f"    ⚠️  No CWE data found for {self.current_year}")
            return {}
        
        # Get current year CWEs
        current_year_cwes = cwe_data['top_cwes']
        
        # Add descriptions to current year CWEs
        cwe_descriptions = {
            '79': 'Cross-site Scripting (XSS)',
            '89': 'SQL Injection',
            '20': 'Improper Input Validation',
            '22': 'Path Traversal',
            '352': 'Cross-Site Request Forgery (CSRF)',
            '78': 'OS Command Injection',
            '190': 'Integer Overflow',
            '476': 'NULL Pointer Dereference',
            '94': 'Code Injection',
            '119': 'Buffer Overflow',
            '125': 'Out-of-bounds Read',
            '787': 'Out-of-bounds Write',
            '416': 'Use After Free',
            '200': 'Information Exposure',
            '434': 'Unrestricted Upload of File',
            '862': 'Missing Authorization',
            '863': 'Incorrect Authorization',
            '269': 'Improper Privilege Management',
            '287': 'Improper Authentication',
            '295': 'Improper Certificate Validation'
        }
        
        # Enhance CWE entries with descriptions
        enhanced_cwes = []
        for cwe in current_year_cwes:
            cwe_full = cwe['cwe']  # e.g., "CWE-79"
            cwe_id = cwe_full.replace('CWE-', '') if cwe_full.startswith('CWE-') else cwe_full
            enhanced_cwe = cwe.copy()
            enhanced_cwe['id'] = cwe_id  # Add id field for consistency
            
            if cwe_id in cwe_descriptions:
                enhanced_cwe['description'] = cwe_descriptions[cwe_id]
                enhanced_cwe['name'] = f"CWE-{cwe_id}: {cwe_descriptions[cwe_id]}"
            else:
                enhanced_cwe['description'] = f"CWE-{cwe_id}"
                enhanced_cwe['name'] = f"CWE-{cwe_id}"
            
            enhanced_cwes.append(enhanced_cwe)
        
        # Calculate total CVEs with CWE from individual counts
        total_cves_with_cwe = sum(cwe['count'] for cwe in current_year_cwes)
        
        current_year_cwe_analysis = {
            'generated_at': datetime.now().isoformat(),
            'year': self.current_year,
            'total_cves_with_cwe': total_cves_with_cwe,
            'total_unique_cwes': len(current_year_cwes),
            'top_cwes': enhanced_cwes,  # All CWEs
            'top_cwes_limited': enhanced_cwes[:20]  # Top 20 for charts
        }
        
        # Save current year analysis
        current_year_file = self.data_dir / 'cwe_analysis_current_year.json'
        with open(current_year_file, 'w') as f:
            json.dump(current_year_cwe_analysis, f, indent=2)
        
        if not self.quiet:
            logger.info(f"    ✅ Generated current year CWE analysis with {len(current_year_cwes)} CWEs")
        return current_year_cwe_analysis
