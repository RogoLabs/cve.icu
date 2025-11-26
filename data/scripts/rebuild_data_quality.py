#!/usr/bin/env python3
"""
Generate data_quality.json for the CVE.ICU data quality dashboard.

Combines:
- unmatched_cnas_analysis.json (CNAs found in CVEs but not in official list)
- unofficial_cna_analysis.json (CNAs that may be official under different names)
- Additional quality metrics from the main CNA analysis
"""

import json
from pathlib import Path
from datetime import datetime

def main():
    scripts_dir = Path(__file__).parent
    data_dir = scripts_dir.parent
    web_data_dir = data_dir.parent / 'web' / 'data'
    
    print("📊 Generating data_quality.json...")
    
    # Load source files
    unmatched_path = scripts_dir / 'unmatched_cnas_analysis.json'
    unofficial_path = scripts_dir / 'unofficial_cna_analysis.json'
    cna_analysis_path = web_data_dir / 'cna_analysis.json'
    
    unmatched_cnas = []
    unofficial_cnas = {}
    cna_analysis = {}
    
    if unmatched_path.exists():
        with open(unmatched_path, 'r') as f:
            unmatched_cnas = json.load(f)
        print(f"  ✓ Loaded {len(unmatched_cnas)} unmatched CNAs")
    else:
        print(f"  ⚠ {unmatched_path} not found")
    
    if unofficial_path.exists():
        with open(unofficial_path, 'r') as f:
            unofficial_cnas = json.load(f)
        print(f"  ✓ Loaded unofficial CNA analysis")
    else:
        print(f"  ⚠ {unofficial_path} not found")
    
    if cna_analysis_path.exists():
        with open(cna_analysis_path, 'r') as f:
            cna_analysis = json.load(f)
        print(f"  ✓ Loaded CNA analysis")
    else:
        print(f"  ⚠ {cna_analysis_path} not found")
    
    # Build data quality summary
    data_quality = {
        "generated_at": datetime.now().isoformat(),
        "summary": {
            "total_official_cnas": cna_analysis.get('total_cnas', 0),
            "active_cnas": cna_analysis.get('active_cnas', 0),
            "inactive_cnas": cna_analysis.get('inactive_cnas', 0),
            "unmatched_cna_count": len(unmatched_cnas),
            "unofficial_total": unofficial_cnas.get('summary', {}).get('total_unofficial', 0),
            "likely_official": unofficial_cnas.get('summary', {}).get('likely_official', 0),
            "truly_unofficial": unofficial_cnas.get('summary', {}).get('truly_unofficial', 0),
        },
        "unmatched_cnas": [],
        "unofficial_cnas": [],
        "anomalies": []
    }
    
    # Process unmatched CNAs - categorize them
    unmatched_by_category = {}
    total_unmatched_cves = 0
    
    for cna in unmatched_cnas:
        category = cna.get('category', 'unknown')
        if category not in unmatched_by_category:
            unmatched_by_category[category] = []
        
        unmatched_by_category[category].append({
            "name": cna.get('name', 'Unknown'),
            "cve_count": cna.get('cve_count', 0),
            "category": category,
            "reason": cna.get('reason', ''),
            "closest_matches": [m.get('name') for m in cna.get('closest_matches', [])[:3]],
            "recommendations": cna.get('recommendations', [])
        })
        total_unmatched_cves += cna.get('cve_count', 0)
    
    data_quality['summary']['unmatched_cve_total'] = total_unmatched_cves
    data_quality['summary']['unmatched_by_category'] = {
        k: len(v) for k, v in unmatched_by_category.items()
    }
    
    # Add top unmatched CNAs (by CVE count)
    sorted_unmatched = sorted(unmatched_cnas, key=lambda x: x.get('cve_count', 0), reverse=True)
    data_quality['unmatched_cnas'] = [
        {
            "name": cna.get('name', 'Unknown'),
            "cve_count": cna.get('cve_count', 0),
            "category": cna.get('category', 'unknown'),
            "reason": cna.get('reason', ''),
            "closest_matches": [m.get('name') for m in cna.get('closest_matches', [])[:3]]
        }
        for cna in sorted_unmatched[:50]  # Top 50
    ]
    
    # Process unofficial CNAs
    detailed_results = unofficial_cnas.get('detailed_results', [])
    
    # Separate likely official from truly unofficial
    likely_official = []
    truly_unofficial = []
    
    for result in detailed_results:
        entry = {
            "name": result.get('cna_name', 'Unknown'),
            "cve_count": result.get('cve_count', 0),
            "years_active": result.get('years_active', 0),
            "confidence": result.get('confidence', 'Unknown'),
            "reasoning": result.get('reasoning', []),
            "is_likely_official": result.get('is_likely_official', False)
        }
        
        if result.get('is_likely_official'):
            likely_official.append(entry)
        else:
            truly_unofficial.append(entry)
    
    # Sort by CVE count
    data_quality['unofficial_cnas'] = sorted(
        truly_unofficial, 
        key=lambda x: x.get('cve_count', 0), 
        reverse=True
    )[:50]
    
    data_quality['likely_official_cnas'] = sorted(
        likely_official,
        key=lambda x: x.get('cve_count', 0),
        reverse=True
    )
    
    # Detect anomalies
    anomalies = []
    
    # Anomaly: CNAs with very high CVE counts but inactive
    if cna_analysis.get('cna_list'):
        for cna in cna_analysis['cna_list']:
            if cna.get('activity_status') == 'Inactive' and cna.get('count', 0) > 500:
                anomalies.append({
                    "type": "high_volume_inactive",
                    "cna_name": cna.get('name'),
                    "cve_count": cna.get('count'),
                    "last_cve_year": cna.get('last_cve_year'),
                    "description": f"High-volume CNA ({cna.get('count')} CVEs) has been inactive since {cna.get('last_cve_year')}"
                })
    
    # Anomaly: Samsung not matching (known issue)
    samsung_entry = next((c for c in unmatched_cnas if 'Samsung' in c.get('name', '')), None)
    if samsung_entry:
        anomalies.append({
            "type": "major_vendor_unmatched",
            "cna_name": samsung_entry.get('name'),
            "cve_count": samsung_entry.get('cve_count', 0),
            "description": "Major vendor appears unmatched from official CNA list - likely name variation issue"
        })
    
    data_quality['anomalies'] = anomalies[:20]  # Top 20 anomalies
    
    # Write output
    output_path = web_data_dir / 'data_quality.json'
    with open(output_path, 'w') as f:
        json.dump(data_quality, f, indent=2)
    
    print(f"\n✅ Generated {output_path}")
    print(f"   - {data_quality['summary']['unmatched_cna_count']} unmatched CNAs")
    print(f"   - {data_quality['summary']['truly_unofficial']} truly unofficial CNAs")
    print(f"   - {len(anomalies)} anomalies detected")

if __name__ == '__main__':
    main()
