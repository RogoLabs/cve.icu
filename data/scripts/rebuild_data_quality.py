#!/usr/bin/env python3
"""
Rebuild data quality JSON with CNAScorecard-style name matching.

This script implements sophisticated name matching to identify:
1. Truly unmatched CNAs (not in official registry)
2. Unofficial CNAs (matched but using non-standard names)
3. Official CNAs (properly matched)

Matching strategies (in order):
1. Exact match
2. Case-insensitive match
3. Normalized match (remove spaces, hyphens, underscores)
4. Partial match (substring containment)
"""

import json
import sys
from pathlib import Path

# Get the data directory
SCRIPT_DIR = Path(__file__).parent
DATA_DIR = SCRIPT_DIR.parent
WEB_DATA_DIR = DATA_DIR.parent / "web" / "data"
CACHE_DIR = DATA_DIR / "cache"


def load_json(filepath):
    """Load JSON file."""
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_json(filepath, data):
    """Save JSON file."""
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)


def normalize_name(name):
    """Normalize a name by removing spaces, hyphens, underscores and lowercasing."""
    if not name:
        return ""
    return name.lower().replace(' ', '').replace('-', '').replace('_', '').replace('.', '')


def build_official_cna_lookups(cna_list):
    """
    Build lookup dictionaries for official CNAs.
    
    Returns:
        - short_name_map: shortName -> official entry
        - org_name_map: organizationName -> official entry  
        - all_official_names: set of all names (short + org)
        - normalized_map: normalized_name -> official entry
    """
    short_name_map = {}
    org_name_map = {}
    all_official_names = set()
    normalized_map = {}
    
    for cna in cna_list:
        short_name = cna.get('shortName', '')
        org_name = cna.get('organizationName', '')
        
        if short_name:
            short_name_map[short_name] = cna
            short_name_map[short_name.lower()] = cna  # Also store lowercase
            all_official_names.add(short_name)
            all_official_names.add(short_name.lower())
            
            # Normalized version
            norm = normalize_name(short_name)
            if norm:
                normalized_map[norm] = cna
        
        if org_name:
            org_name_map[org_name] = cna
            org_name_map[org_name.lower()] = cna
            all_official_names.add(org_name)
            all_official_names.add(org_name.lower())
            
            # Normalized version
            norm = normalize_name(org_name)
            if norm:
                normalized_map[norm] = cna
    
    return short_name_map, org_name_map, all_official_names, normalized_map


def map_cve_name_to_official(cve_name, short_name_map, org_name_map, normalized_map, cna_list):
    """
    Attempt to match a CVE CNA name to an official CNA entry.
    
    Matching strategies (in order of preference):
    1. Exact match on shortName
    2. Case-insensitive match on shortName
    3. Exact match on organizationName
    4. Case-insensitive match on organizationName
    5. Normalized match (remove spaces, hyphens, underscores)
    6. Partial match (substring containment with min length)
    
    Returns:
        tuple: (matched_official_entry or None, match_type, confidence)
        match_type: 'exact_short', 'case_short', 'exact_org', 'case_org', 'normalized', 'partial', None
        confidence: 'high', 'medium', 'low', None
    """
    if not cve_name:
        return None, None, None
    
    # 1. Exact match on shortName
    if cve_name in short_name_map:
        return short_name_map[cve_name], 'exact_short', 'high'
    
    # 2. Case-insensitive match on shortName
    cve_lower = cve_name.lower()
    if cve_lower in short_name_map:
        return short_name_map[cve_lower], 'case_short', 'high'
    
    # 3. Exact match on organizationName
    if cve_name in org_name_map:
        return org_name_map[cve_name], 'exact_org', 'high'
    
    # 4. Case-insensitive match on organizationName
    if cve_lower in org_name_map:
        return org_name_map[cve_lower], 'case_org', 'high'
    
    # 5. Normalized match
    normalized_cve = normalize_name(cve_name)
    if normalized_cve and normalized_cve in normalized_map:
        return normalized_map[normalized_cve], 'normalized', 'medium'
    
    # 6. Partial matching (substring containment)
    # Only for names with reasonable length to avoid false positives
    if len(cve_name) > 3:
        for cna in cna_list:
            short = cna.get('shortName', '').lower()
            org = cna.get('organizationName', '').lower()
            
            # Check if CVE name contains official name or vice versa
            if short and len(short) > 3:
                if cve_lower in short or short in cve_lower:
                    return cna, 'partial', 'low'
            
            if org and len(org) > 5:
                if cve_lower in org or org in cve_lower:
                    return cna, 'partial', 'low'
    
    return None, None, None


def analyze_cna_names(cna_analysis, official_cna_list):
    """
    Analyze all CNA names from our analysis against the official registry.
    
    Returns categorized results with match information.
    """
    # Build lookup structures
    short_name_map, org_name_map, all_official_names, normalized_map = build_official_cna_lookups(official_cna_list)
    
    # Results
    exact_matches = []      # Exact shortName match - official and correct
    case_matches = []       # Case mismatch - should standardize
    org_matches = []        # Matched via organizationName - should use shortName
    normalized_matches = [] # Matched via normalization - naming inconsistency
    partial_matches = []    # Partial match - likely the same but different naming
    unmatched = []          # No match found - potentially not a registered CNA
    
    # Also track the match details
    match_details = {}
    
    for cna_name, cna_data in cna_analysis.items():
        official, match_type, confidence = map_cve_name_to_official(
            cna_name, short_name_map, org_name_map, normalized_map, official_cna_list
        )
        
        result = {
            'cna_name': cna_name,
            'cve_count': cna_data.get('count', 0),
            'kev_count': cna_data.get('kev_count', 0),
            'epss_high_count': cna_data.get('epss_high_count', 0),
        }
        
        if official:
            result['official_short_name'] = official.get('shortName', '')
            result['official_org_name'] = official.get('organizationName', '')
            result['official_id'] = official.get('cnaID', '')
            result['match_type'] = match_type
            result['confidence'] = confidence
            
            if match_type == 'exact_short':
                exact_matches.append(result)
            elif match_type == 'case_short':
                case_matches.append(result)
            elif match_type in ('exact_org', 'case_org'):
                org_matches.append(result)
            elif match_type == 'normalized':
                normalized_matches.append(result)
            elif match_type == 'partial':
                partial_matches.append(result)
        else:
            result['match_type'] = None
            result['confidence'] = None
            unmatched.append(result)
        
        match_details[cna_name] = result
    
    # Sort by CVE count descending
    for lst in [exact_matches, case_matches, org_matches, normalized_matches, partial_matches, unmatched]:
        lst.sort(key=lambda x: x['cve_count'], reverse=True)
    
    return {
        'exact_matches': exact_matches,
        'case_matches': case_matches,
        'org_matches': org_matches,
        'normalized_matches': normalized_matches,
        'partial_matches': partial_matches,
        'unmatched': unmatched,
        'match_details': match_details
    }


def main():
    """Main entry point."""
    print("Rebuilding data quality analysis with CNAScorecard-style name matching...")
    
    # Load official CNA list
    cna_list_path = CACHE_DIR / "cna_list.json"
    if not cna_list_path.exists():
        print(f"ERROR: Official CNA list not found at {cna_list_path}")
        sys.exit(1)
    
    official_cna_list = load_json(cna_list_path)
    print(f"Loaded {len(official_cna_list)} official CNAs from registry")
    
    # Load our CNA analysis
    cna_analysis_path = WEB_DATA_DIR / "cna_analysis.json"
    if not cna_analysis_path.exists():
        print(f"ERROR: CNA analysis not found at {cna_analysis_path}")
        sys.exit(1)
    
    cna_analysis = load_json(cna_analysis_path)
    # Convert cna_list array to dict keyed by name for analysis
    cna_list_data = cna_analysis.get('cna_list', [])
    cna_data = {item['name']: item for item in cna_list_data if 'name' in item}
    print(f"Loaded {len(cna_data)} CNAs from analysis")
    
    # Analyze names
    results = analyze_cna_names(cna_data, official_cna_list)
    
    # Calculate statistics
    stats = {
        'total_cnas_in_analysis': len(cna_data),
        'official_cna_registry_count': len(official_cna_list),
        'exact_matches': len(results['exact_matches']),
        'case_mismatches': len(results['case_matches']),
        'org_name_matches': len(results['org_matches']),
        'normalized_matches': len(results['normalized_matches']),
        'partial_matches': len(results['partial_matches']),
        'unmatched': len(results['unmatched']),
    }
    
    # Total CVEs in each category
    stats['exact_match_cves'] = sum(x['cve_count'] for x in results['exact_matches'])
    stats['case_mismatch_cves'] = sum(x['cve_count'] for x in results['case_matches'])
    stats['org_name_match_cves'] = sum(x['cve_count'] for x in results['org_matches'])
    stats['normalized_match_cves'] = sum(x['cve_count'] for x in results['normalized_matches'])
    stats['partial_match_cves'] = sum(x['cve_count'] for x in results['partial_matches'])
    stats['unmatched_cves'] = sum(x['cve_count'] for x in results['unmatched'])
    
    # Calculate percentages
    total_cves = sum([
        stats['exact_match_cves'], stats['case_mismatch_cves'], 
        stats['org_name_match_cves'], stats['normalized_match_cves'],
        stats['partial_match_cves'], stats['unmatched_cves']
    ])
    
    if total_cves > 0:
        stats['exact_match_pct'] = round(stats['exact_match_cves'] / total_cves * 100, 2)
        stats['issues_pct'] = round((total_cves - stats['exact_match_cves']) / total_cves * 100, 2)
    
    print(f"\n=== Data Quality Summary ===")
    print(f"Total CNAs analyzed: {stats['total_cnas_in_analysis']}")
    print(f"Official registry size: {stats['official_cna_registry_count']}")
    print(f"\nMatching Results:")
    print(f"  Exact matches: {stats['exact_matches']} CNAs ({stats['exact_match_cves']:,} CVEs)")
    print(f"  Case mismatches: {stats['case_mismatches']} CNAs ({stats['case_mismatch_cves']:,} CVEs)")
    print(f"  Org name matches: {stats['org_name_matches']} CNAs ({stats['org_name_match_cves']:,} CVEs)")
    print(f"  Normalized matches: {stats['normalized_matches']} CNAs ({stats['normalized_match_cves']:,} CVEs)")
    print(f"  Partial matches: {stats['partial_matches']} CNAs ({stats['partial_match_cves']:,} CVEs)")
    print(f"  Unmatched: {stats['unmatched']} CNAs ({stats['unmatched_cves']:,} CVEs)")
    
    # Build output
    output = {
        'stats': stats,
        'exact_matches': results['exact_matches'][:50],  # Top 50 only
        'case_mismatches': results['case_matches'],
        'org_name_matches': results['org_matches'],
        'normalized_matches': results['normalized_matches'],
        'partial_matches': results['partial_matches'],
        'unmatched': results['unmatched'],
    }
    
    # Save to web data directory
    output_path = WEB_DATA_DIR / "data_quality.json"
    save_json(output_path, output)
    print(f"\nSaved data quality analysis to {output_path}")
    
    # Also print top unmatched for review
    if results['unmatched']:
        print(f"\n=== Top 10 Unmatched CNAs ===")
        for item in results['unmatched'][:10]:
            print(f"  {item['cna_name']}: {item['cve_count']:,} CVEs")


if __name__ == '__main__':
    main()
