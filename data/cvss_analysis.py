#!/usr/bin/env python3
"""
CVSS Analysis Module
Handles all CVSS (Common Vulnerability Scoring System) related data processing and analysis
"""

import json
from pathlib import Path
from datetime import datetime


class CVSSAnalyzer:
    """Handles CVSS-specific analysis and data processing"""
    
    def __init__(self, base_dir, cache_dir, data_dir):
        self.base_dir = Path(base_dir)
        self.cache_dir = Path(cache_dir)
        self.data_dir = Path(data_dir)
        self.current_year = datetime.now().year
    
    def generate_cvss_analysis(self, all_year_data):
        """Generate CVSS analysis across all years with score distributions"""
        print(f"  📊 Generating CVSS analysis...")
        
        # Aggregate CVSS data from all years
        combined_cvss = {
            'v2.0': {'severity': {}, 'scores': {}},
            'v3.0': {'severity': {}, 'scores': {}},
            'v3.1': {'severity': {}, 'scores': {}},
            'v4.0': {'severity': {}, 'scores': {}}
        }
        
        total_cves_with_cvss = 0
        
        for year_data in all_year_data:
            if 'cvss' in year_data:
                cvss_data = year_data['cvss']
                total_cves_with_cvss += cvss_data.get('total_cves_with_cvss', 0)
                
                # Aggregate severity distributions
                for version in ['v2.0', 'v3.0', 'v3.1', 'v4.0']:
                    if version in cvss_data:
                        version_data = cvss_data[version]
                        
                        # Aggregate severity counts
                        if 'severity' in version_data:
                            for severity, count in version_data['severity'].items():
                                if severity not in combined_cvss[version]['severity']:
                                    combined_cvss[version]['severity'][severity] = 0
                                combined_cvss[version]['severity'][severity] += count
                        
                        # Aggregate score distributions
                        if 'scores' in version_data:
                            for score, count in version_data['scores'].items():
                                if score not in combined_cvss[version]['scores']:
                                    combined_cvss[version]['scores'][score] = 0
                                combined_cvss[version]['scores'][score] += count
        
        # Create binned score distributions (0-0.99, 1-1.99, etc.)
        binned_scores = {}
        for version in ['v2.0', 'v3.0', 'v3.1', 'v4.0']:
            binned_scores[version] = {}
            
            # Initialize bins
            for i in range(10):
                bin_key = f"{i}-{i}.99"
                binned_scores[version][bin_key] = 0
            binned_scores[version]["10.0"] = 0  # Special case for perfect 10.0
            
            # Aggregate scores into bins
            for score_str, count in combined_cvss[version]['scores'].items():
                try:
                    score = float(score_str)
                    if score == 10.0:
                        binned_scores[version]["10.0"] += count
                    else:
                        bin_index = int(score)  # This will floor the score
                        bin_key = f"{bin_index}-{bin_index}.99"
                        if bin_key in binned_scores[version]:
                            binned_scores[version][bin_key] += count
                except (ValueError, KeyError):
                    continue
        
        # Remove empty bins
        for version in binned_scores:
            binned_scores[version] = {k: v for k, v in binned_scores[version].items() if v > 0}
        
        # Calculate overall statistics
        total_by_version = {}
        for version in ['v2.0', 'v3.0', 'v3.1', 'v4.0']:
            total_by_version[version] = sum(combined_cvss[version]['severity'].values())
        
        cvss_analysis = {
            'generated_at': datetime.now().isoformat(),
            'total_cves_with_cvss': total_cves_with_cvss,
            'total_by_version': total_by_version,
            'severity_distribution': {version: data['severity'] for version, data in combined_cvss.items()},
            'score_distribution': {version: data['scores'] for version, data in combined_cvss.items()},
            'binned_score_distribution': binned_scores
        }
        
        # Save to file
        output_file = self.data_dir / 'cvss_analysis.json'
        with open(output_file, 'w') as f:
            json.dump(cvss_analysis, f, indent=2)
        
        print(f"  ✅ Generated CVSS analysis with {total_cves_with_cvss:,} CVEs across all versions")
        return cvss_analysis
    
    def generate_current_year_cvss_analysis(self, current_year_data):
        """Generate current year CVSS analysis"""
        print(f"    📊 Generating current year CVSS analysis...")
        
        # Extract CVSS data from current year
        cvss_data = current_year_data.get('cvss', {})
        
        if not cvss_data:
            print(f"    ⚠️  No CVSS data found for {self.current_year}")
            return {}
        
        # Create binned score distributions for current year
        binned_scores = {}
        for version in ['v2.0', 'v3.0', 'v3.1', 'v4.0']:
            if version in cvss_data and 'scores' in cvss_data[version]:
                binned_scores[version] = {}
                
                # Initialize bins
                for i in range(10):
                    bin_key = f"{i}-{i}.99"
                    binned_scores[version][bin_key] = 0
                binned_scores[version]["10.0"] = 0
                
                # Aggregate scores into bins
                for score_str, count in cvss_data[version]['scores'].items():
                    try:
                        score = float(score_str)
                        if score == 10.0:
                            binned_scores[version]["10.0"] += count
                        else:
                            bin_index = int(score)
                            bin_key = f"{bin_index}-{bin_index}.99"
                            if bin_key in binned_scores[version]:
                                binned_scores[version][bin_key] += count
                    except (ValueError, KeyError):
                        continue
                
                # Remove empty bins
                binned_scores[version] = {k: v for k, v in binned_scores[version].items() if v > 0}
        
        # Calculate totals by version
        total_by_version = {}
        for version in ['v2.0', 'v3.0', 'v3.1', 'v4.0']:
            if version in cvss_data and 'severity' in cvss_data[version]:
                total_by_version[version] = sum(cvss_data[version]['severity'].values())
            else:
                total_by_version[version] = 0
        
        current_year_cvss_analysis = {
            'generated_at': datetime.now().isoformat(),
            'year': self.current_year,
            'total_cves_with_cvss': cvss_data.get('total_cves_with_cvss', 0),
            'total_by_version': total_by_version,
            'severity_distribution': {version: cvss_data.get(version, {}).get('severity', {}) for version in ['v2.0', 'v3.0', 'v3.1', 'v4.0']},
            'score_distribution': {version: cvss_data.get(version, {}).get('scores', {}) for version in ['v2.0', 'v3.0', 'v3.1', 'v4.0']},
            'binned_score_distribution': binned_scores
        }
        
        # Save current year analysis
        current_year_file = self.data_dir / 'cvss_analysis_current_year.json'
        with open(current_year_file, 'w') as f:
            json.dump(current_year_cvss_analysis, f, indent=2)
        
        print(f"    ✅ Generated current year CVSS analysis")
        return current_year_cvss_analysis
