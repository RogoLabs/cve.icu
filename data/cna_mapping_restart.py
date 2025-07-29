#!/usr/bin/env python3
"""
CNA Mapping Restart Script

Maps every CVE to either an official or unofficial CNA using:
1. UUID/official CNA mapping (cna_name_map.json)
2. Reporting email/domain mapping (cna_list.json contact emails)
3. Fallback to edge-case/unknown (creates 'Unofficial CNA' if needed)

- 100% of CVEs will be mapped
- Official status uses UUID first, then fuzzy name match
- Years active is calculated from cnaID, not CVE publication
"""

import json
import re
from pathlib import Path
from collections import defaultdict

# Utility: Normalize CNA names for fuzzy matching

def normalize_name(name):
    if not name:
        return ''
    return (
        name.lower()
        .replace(',', '')
        .replace('.', '')
        .replace('incorporated', 'inc')
        .replace('corporation', 'corp')
        .replace('limited', 'ltd')
        .replace('llc', '')
        .replace('inc', '')
        .replace('corp', '')
        .replace('ltd', '')
        .replace('the ', '')
        .replace('&', 'and')
        .replace('  ', ' ')
        .strip()
    )

def extract_designation_year(cna_id):
    match = re.match(r"CNA-(\d{4})-", cna_id or "")
    return int(match.group(1)) if match else None

# Load all reference data
cache_dir = Path(__file__).parent / 'cache'
with open(cache_dir / 'nvd.jsonl', 'r') as f:
    cve_data = [json.loads(line) for line in f if line.strip()]
with open(cache_dir / 'cna_name_map.json', 'r') as f:
    uuid_map = json.load(f)  # uuid: org_name
with open(cache_dir / 'cna_list.json', 'r') as f:
    cna_list_raw = json.load(f)
    cna_list = cna_list_raw['data'] if isinstance(cna_list_raw, dict) and 'data' in cna_list_raw else cna_list_raw

# Build official CNA lookup by UUID and normalized name
uuid_to_name = {uuid: name for uuid, name in uuid_map.items()}
official_names = {normalize_name(name): uuid for uuid, name in uuid_map.items()}
# Build contact email and domain lookup from cna_list.json
email_to_cna = {}
domain_to_cna = {}
cnaid_to_year = {}
for cna in cna_list:
    org_name = cna.get('organizationName', '')
    cna_id = cna.get('cnaID', '')
    if cna_id:
        cnaid_to_year[org_name] = extract_designation_year(cna_id)
    # Contact emails
    for contact in cna.get('contact', []):
        for email in contact.get('email', []):
            email_addr = email.get('emailAddr', '').lower()
            if email_addr:
                email_to_cna[email_addr] = org_name
                domain = email_addr.split('@')[-1]
                if domain:
                    domain_to_cna[domain] = org_name

# Main mapping pass
cna_stats = defaultdict(lambda: {'count': 0, 'cve_ids': [], 'first_cve_year': None, 'last_cve_year': None, 'designation_year': None, 'official': False, 'source': set()})
unknown_cnas = set()
for cve in cve_data:
    # 1. Try UUID/official CNA mapping
    cna_uuid = cve.get('cna', '')
    cna_name = uuid_to_name.get(cna_uuid, '')
    if cna_name:
        mapped_name = cna_name
        official = True
        designation_year = cnaid_to_year.get(cna_name)
        source = 'uuid'
    else:
        # 2. Try reporting email(s)
        emails = set()
        # NVD v2: sourceIdentifier or assigner field, and any emails in references
        assigner = cve.get('assigner', '')
        if assigner and '@' in assigner:
            emails.add(assigner.lower())
        # Try references
        for ref in cve.get('references', []):
            url = ref.get('url', '')
            if '@' in url:
                emails.add(url.lower())
        # Try description for emails
        desc = cve.get('description', '')
        for match in re.findall(r'[\w\.-]+@[\w\.-]+', desc):
            emails.add(match.lower())
        mapped_name = ''
        official = False
        designation_year = None
        source = ''
        for email in emails:
            # Direct email match
            if email in email_to_cna:
                mapped_name = email_to_cna[email]
                official = normalize_name(mapped_name) in official_names
                designation_year = cnaid_to_year.get(mapped_name)
                source = 'email'
                break
            # Domain match
            domain = email.split('@')[-1]
            if domain in domain_to_cna:
                mapped_name = domain_to_cna[domain]
                official = normalize_name(mapped_name) in official_names
                designation_year = cnaid_to_year.get(mapped_name)
                source = 'domain'
                break
        # 3. Fallback: fuzzy name from assigner
        if not mapped_name and assigner:
            normalized = normalize_name(assigner)
            if normalized in official_names:
                mapped_name = uuid_to_name[official_names[normalized]]
                official = True
                designation_year = cnaid_to_year.get(mapped_name)
                source = 'fuzzy-assigner'
        # 4. Edge: fallback to email or domain as "Unofficial CNA"
        if not mapped_name and emails:
            mapped_name = sorted(emails)[0]  # Use first email as CNA name
            official = False
            designation_year = None
            source = 'unofficial-email'
        if not mapped_name:
            mapped_name = 'Unknown CNA'
            official = False
            designation_year = None
            source = 'unknown'
    # Update stats
    cna_stats[mapped_name]['count'] += 1
    cna_stats[mapped_name]['cve_ids'].append(cve.get('id', ''))
    year = int(cve.get('published', '1970')[:4]) if 'published' in cve else None
    if year:
        if not cna_stats[mapped_name]['first_cve_year'] or year < cna_stats[mapped_name]['first_cve_year']:
            cna_stats[mapped_name]['first_cve_year'] = year
        if not cna_stats[mapped_name]['last_cve_year'] or year > cna_stats[mapped_name]['last_cve_year']:
            cna_stats[mapped_name]['last_cve_year'] = year
    if designation_year:
        cna_stats[mapped_name]['designation_year'] = designation_year
    cna_stats[mapped_name]['official'] = official
    cna_stats[mapped_name]['source'].add(source)

# Output summary
summary = []
for name, stats in cna_stats.items():
    years_active = None
    if stats['designation_year']:
        years_active = 2025 - stats['designation_year']
    summary.append({
        'name': name,
        'count': stats['count'],
        'official': stats['official'],
        'years_active': years_active,
        'first_cve_year': stats['first_cve_year'],
        'last_cve_year': stats['last_cve_year'],
        'sources': sorted(stats['source']),
    })
summary.sort(key=lambda x: x['count'], reverse=True)

with open('../web/data/cna_analysis_restart.json', 'w') as f:
    json.dump(summary, f, indent=2)

print(f"✅ CNA mapping complete. {len(summary)} CNAs found. Output: web/data/cna_analysis_restart.json")
