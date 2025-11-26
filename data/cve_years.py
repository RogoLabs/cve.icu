#!/usr/bin/env python3
"""
CVE Years Analyzer
Processes CVE data from JSONL file and generates yearly analysis data
Handles historical data (1999-2016) and individual years (2017-present)
"""

import json
import re
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict, Counter
from urllib.parse import urlparse
from download_cve_data import CVEDataDownloader

class CVEYearsAnalyzer:
    """Analyzes CVE data by year and generates structured data for visualization"""
    
    def __init__(self, quiet=False):
        self.quiet = quiet
        self.base_dir = Path(__file__).parent
        self.downloader = CVEDataDownloader(quiet=quiet)
        self.data_file = None
        self.year_data_cache = {}
        
        # CNA mapping data for proper name resolution
        self.cna_list = {}
        self.cna_name_map = {}
        
        if not self.quiet:
            print(f"📊 CVE Years Analyzer Initialized")
            print(f"📅 Target coverage: 1999-{datetime.now().year}")

    def extract_severity_info(self, cve_data):
        """Extract normalized CVSS severity and score from a CVE record.

        This is intentionally conservative and mirrors the original notebook
        logic: prefer v3.1, then v3.0, then v2.0, and fall back to
        "UNKNOWN"/0.0 when nothing is available.
        """

        def _normalize(severity):
            if not severity:
                return "UNKNOWN"
            sev = str(severity).strip().upper()
            # Common variants across NVD data
            if sev in {"CRITICAL", "CRIT"}:
                return "CRITICAL"
            if sev in {"HIGH", "H"}:
                return "HIGH"
            if sev in {"MEDIUM", "MED"}:
                return "MEDIUM"
            if sev in {"LOW", "L"}:
                return "LOW"
            if sev in {"NONE", "N"}:
                return "NONE"
            return sev or "UNKNOWN"

        # NVD 1.1+ style: metrics are under cve.metrics
        metrics = cve_data.get("cve", {}).get("metrics", {})

        # Helper to extract from a metrics list by key
        def _from_metrics(key, version_label):
            entries = metrics.get(key) or []
            if not entries:
                return None
            # Take the first entry as representative
            metric = entries[0].get("cvssData") or {}
            score = metric.get("baseScore")
            severity = metric.get("baseSeverity")
            try:
                score_val = float(score)
            except Exception:
                score_val = 0.0
            return {
                "version": version_label,
                "severity": _normalize(severity),
                "score": score_val,
            }

        # Preference order: v4.0 (if present), then v3.1, v3.0, v2.0
        for key, label in (
            ("cvssMetricV40", "v4.0"),
            ("cvssMetricV31", "v3.1"),
            ("cvssMetricV30", "v3.0"),
            ("cvssMetricV2", "v2.0"),
        ):
            info = _from_metrics(key, label)
            if info is not None:
                return info

        # Fallback: some legacy records may expose a flatter shape; be lenient
        try:
            base_metric = (
                cve_data.get("impact", {})
                .get("baseMetricV3", {})
                .get("cvssV3", {})
            )
            if base_metric:
                score = base_metric.get("baseScore", 0.0)
                severity = base_metric.get("baseSeverity", "UNKNOWN")
                return {
                    "version": "v3.0",
                    "severity": _normalize(severity),
                    "score": float(score) if score is not None else 0.0,
                }
        except Exception:
            pass

        # Ultimate fallback
        return {"version": "unknown", "severity": "UNKNOWN", "score": 0.0}

    def parse_cve_date(self, cve_data):
        """Extract a publication date for a CVE record.

        Tries multiple known NVD-style shapes and falls back to lastModified or
        the year embedded in the CVE ID if necessary.
        """

        # Prioritize cve['published'] and similar keys (NVD JSONL structure)
        for key in ("published", "publishedDate", "publishDate"):
            date_str = cve_data.get("cve", {}).get(key)
            if not date_str:
                date_str = cve_data.get(key)
            if date_str:
                try:
                    # Handle ISO8601 with or without fractional seconds
                    return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                except Exception:
                    pass

        # Try lastModified style keys as a fallback
        for key in ("lastModified", "lastModifiedDate"):
            date_str = cve_data.get(key)
            if not date_str:
                date_str = cve_data.get("cve", {}).get(key)
            if date_str:
                try:
                    return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                except Exception:
                    pass

        # Legacy / alternative layouts: sometimes dates are nested under cve
        # metadata or configurations – keep this best-effort and very defensive.
        try:
            meta = cve_data.get("cve", {}).get("CVE_data_meta", {})
            # Some feeds include date in a "DATE_PUBLIC"-style field; rarely used.
            for key in ("DATE_PUBLIC", "date_public", "date"):
                date_str = meta.get(key)
                if date_str:
                    try:
                        return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                    except Exception:
                        pass
        except Exception:
            pass

        # As a last resort, derive a year from the CVE ID itself; this at least
        # lets us bucket by year when no explicit published date is available.
        try:
            cve_id = cve_data.get("cve", {}).get("id") or \
                     cve_data.get("cve", {}).get("CVE_data_meta", {}).get("ID", "")
            if isinstance(cve_id, str) and cve_id.startswith("CVE-"):
                parts = cve_id.split("-")
                if len(parts) >= 3:
                    year = int(parts[1])
                    # Use January 1st of that year as a synthetic publication date
                    return datetime(year, 1, 1)
        except Exception:
            pass

        # If everything fails, return None so callers can skip this CVE
        return None
    
    def ensure_data_loaded(self):
        """Ensure CVE data is downloaded and available"""
        if self.data_file is None:
            if not self.quiet:
                print("🔽 Loading CVE data...")
            self.data_file = self.downloader.ensure_data_available()
            if not self.quiet:
                print(f"✅ Data loaded from: {self.data_file}")

    def process_year_data(self, year):
        """Process CVE data for a specific year"""
        if year in self.year_data_cache:
            return self.year_data_cache[year]

        self.ensure_data_loaded()

        if not self.quiet:
            print(f"📊 Processing CVE data for {year}...")

        # Initialize counters
        monthly_counts = [0] * 12
        daily_counts = {}
        cvss_data = {
            'v2.0': {'severity_counts': Counter(), 'score_distribution': Counter(), 'total': 0},
            'v3.0': {'severity_counts': Counter(), 'score_distribution': Counter(), 'total': 0},
            'v3.1': {'severity_counts': Counter(), 'score_distribution': Counter(), 'total': 0},
            'v4.0': {'severity_counts': Counter(), 'score_distribution': Counter(), 'total': 0},
            'unknown': {'severity_counts': Counter(), 'score_distribution': Counter(), 'total': 0}
        }
        vendor_counts = Counter()
        cwe_counts = Counter()
        status_counts = Counter()
        tag_counts = Counter()
        reference_tag_counts = Counter()
        cpe_vendor_counts = Counter()

        if not self.quiet:
            print("🔽 Loading CVE data...")

        if not self.quiet:
            print("  📊 Reading JSON array format...")
        with open(self.data_file, 'r', encoding='utf-8') as f:
            try:
                all_cves = json.load(f)
                if not self.quiet:
                    print(f"  📊 Loaded {len(all_cves)} CVE records")
            except json.JSONDecodeError as e:
                print(f"  ❌ Failed to parse JSON: {e}")
                return self.create_empty_year_data(year)

        # EPSS summary buckets for this year (using precomputed mapping)
        epss_buckets = {
            'epss_gt_0_1': 0,
            'epss_gt_0_5': 0,
            'epss_gt_0_9': 0,
        }

        # KEV summary for this year: just a simple count of KEV CVEs
        kev_summary = {
            'kev_count': 0,
        }

        # Lazy-load EPSS mapping once per analyzer instance (best-effort)
        if not hasattr(self, 'epss_mapping'):
            try:
                epss_json = self.downloader.epss_parsed_file
                if not epss_json.exists():
                    epss_json = self.downloader.parse_epss_csv()
                if epss_json and Path(epss_json).exists():
                    with open(epss_json, 'r', encoding='utf-8') as ef:
                        self.epss_mapping = json.load(ef)
                else:
                    self.epss_mapping = {}
            except Exception:
                self.epss_mapping = {}

            # Lazy-load KEV mapping once per analyzer instance (best-effort)
            if not hasattr(self, 'kev_mapping'):
                try:
                    kev_json = self.downloader.kev_parsed_file
                    if not kev_json.exists():
                        kev_json = self.downloader.parse_kev_json()
                    if kev_json and Path(kev_json).exists():
                        with open(kev_json, 'r', encoding='utf-8') as kf:
                            raw = json.load(kf)
                            # Stored as {"CVE-...": true, ...}
                            self.kev_mapping = {k: bool(v) for k, v in raw.items()}
                    else:
                        self.kev_mapping = {}
                except Exception:
                    self.kev_mapping = {}

        # Process each CVE record
        total_cves = 0
        for cve_idx, cve_data in enumerate(all_cves):
            if cve_idx % 10000 == 0 and cve_idx > 0 and not self.quiet:
                print(f"  📊 Processed {cve_idx:,} CVEs...")

            try:
                cve_id = cve_data.get('cve', {}).get('id', '')
                if not cve_id.startswith('CVE-'):
                    continue

                vuln_status = cve_data.get('cve', {}).get('vulnStatus', '')
                if 'Rejected' in vuln_status:
                    continue

                pub_date = self.parse_cve_date(cve_data)
                if not pub_date:
                    continue

                actual_year = pub_date.year
                if actual_year != year:
                    continue

                total_cves += 1

                month_idx = pub_date.month - 1
                monthly_counts[month_idx] += 1

                date_str = pub_date.strftime('%Y-%m-%d')
                daily_counts[date_str] = daily_counts.get(date_str, 0) + 1

                severity_info = self.extract_severity_info(cve_data)
                cvss_version = severity_info['version']
                severity = severity_info['severity']
                score = severity_info['score']

                if cvss_version in cvss_data:
                    cvss_data[cvss_version]['severity_counts'][severity] += 1
                    score_key = round(float(score), 1) if score > 0 else 0.0
                    cvss_data[cvss_version]['score_distribution'][score_key] += 1
                    cvss_data[cvss_version]['total'] += 1
                else:
                    cvss_data['unknown']['severity_counts'][severity] += 1
                    score_key = round(float(score), 1) if score > 0 else 0.0
                    cvss_data['unknown']['score_distribution'][score_key] += 1
                    cvss_data['unknown']['total'] += 1

                # EPSS aggregation
                try:
                    if getattr(self, 'epss_mapping', None):
                        epss = self.epss_mapping.get(cve_id)
                        if epss:
                            epss_score = float(epss.get('epss_score') or 0.0)
                            if epss_score > 0.1:
                                epss_buckets['epss_gt_0_1'] += 1
                            if epss_score > 0.5:
                                epss_buckets['epss_gt_0_5'] += 1
                            if epss_score > 0.9:
                                epss_buckets['epss_gt_0_9'] += 1
                except Exception:
                    pass

                # KEV aggregation (simple count per year)
                try:
                    if getattr(self, 'kev_mapping', None):
                        if self.kev_mapping.get(cve_id):
                            kev_summary['kev_count'] += 1
                except Exception:
                    pass

                # Additional fields
                status_counts[vuln_status] += 1

                cve_tags = cve_data.get('cve', {}).get('cveTags', [])
                for tag in cve_tags:
                    if isinstance(tag, str):
                        tag_counts[tag] += 1
                    elif isinstance(tag, dict) and 'tag' in tag:
                        tag_counts[tag['tag']] += 1

                references = cve_data.get('cve', {}).get('references', [])
                for ref in references:
                    ref_tags = ref.get('tags', [])
                    for tag in ref_tags:
                        reference_tag_counts[tag] += 1

                cpe_vendors = self.extract_cpe_vendor_info(cve_data)
                for vendor in cpe_vendors:
                    cpe_vendor_counts[vendor] += 1

                vendors = self.extract_vendor_info(cve_data)
                for vendor in vendors:
                    vendor_counts[vendor] += 1

                cwes = self.extract_cwe_info(cve_data)
                for cwe in cwes:
                    cwe_counts[cwe] += 1

            except (json.JSONDecodeError, KeyError, ValueError, IndexError) as e:
                if cve_idx <= 10:
                    print(f"  ⚠️  Error processing CVE {cve_idx}: {e}")
                continue

        # Prepare daily publication analysis
        complete_daily_counts = self.create_complete_daily_array(daily_counts, year)

        if complete_daily_counts:
            non_zero_days = {k: v for k, v in complete_daily_counts.items() if v > 0}
            if non_zero_days:
                daily_values = list(non_zero_days.values())
                daily_analysis = {
                    'total_days': len(non_zero_days),
                    'avg_per_day': round(sum(daily_values) / len(daily_values), 2),
                    'highest_day': {
                        'date': max(non_zero_days, key=non_zero_days.get),
                        'count': max(daily_values)
                    },
                    'lowest_day': {
                        'date': min(non_zero_days, key=non_zero_days.get),
                        'count': min(daily_values)
                    },
                    'daily_counts': complete_daily_counts
                }
            else:
                daily_analysis = {
                    'total_days': 0,
                    'avg_per_day': 0,
                    'highest_day': {'date': '', 'count': 0},
                    'lowest_day': {'date': '', 'count': 0},
                    'daily_counts': complete_daily_counts
                }
        else:
            daily_analysis = {
                'total_days': 0,
                'avg_per_day': 0,
                'highest_day': {'date': '', 'count': 0},
                'lowest_day': {'date': '', 'count': 0},
                'daily_counts': {}
            }

        year_data = {
            'year': year,
            'total_cves': total_cves,
            'date_data': {
                'monthly_distribution': {
                    str(i + 1): monthly_counts[i] for i in range(12)
                },
                'daily_analysis': daily_analysis
            },
            'cvss': {
                **{
                    version: {
                        'total': data['total'],
                        'severity_distribution': dict(data['severity_counts']),
                        'score_distribution': dict(data['score_distribution'])
                    }
                    for version, data in cvss_data.items()
                    if data['total'] > 0
                },
                'epss_summary': epss_buckets
            },
            'kev': kev_summary,
            'vendors': {
                'cna_assigners': [
                    {'name': vendor, 'count': count}
                    for vendor, count in vendor_counts.most_common(20)
                ],
                'cpe_vendors': [
                    {'name': vendor, 'count': count}
                    for vendor, count in cpe_vendor_counts.most_common(20)
                ]
            },
            'cwe': {
                'top_cwes': [
                    {'cwe': cwe, 'count': count}
                    for cwe, count in cwe_counts.most_common(20)
                ]
            },
            'metadata': {
                'vulnerability_status': [
                    {'status': status, 'count': count}
                    for status, count in status_counts.most_common(10)
                ],
                'cve_tags': [
                    {'tag': tag, 'count': count}
                    for tag, count in tag_counts.most_common(10)
                ],
                'reference_tags': [
                    {'tag': tag, 'count': count}
                    for tag, count in reference_tag_counts.most_common(20)
                ]
            },
            'processing_stats': {
                'processed_at': datetime.now().isoformat(),
                'data_source': 'data/cache/nvd.json'
            }
        }

        self.year_data_cache[year] = year_data

        if not self.quiet:
            print(f"  ✅ Found {total_cves} CVEs for {year}")
        return year_data

    def create_complete_daily_array(self, daily_counts, year):
        """Create complete daily array with zeros for missing dates to prevent UI issues"""
        try:
            # Create date range for the entire year
            start_date = datetime(year, 1, 1)
            if year == datetime.now().year:
                # For current year, only go up to today
                end_date = datetime.now().date()
            else:
                # For past years, include the entire year
                end_date = datetime(year, 12, 31).date()
            
            complete_daily_counts = {}
            current_date = start_date.date()
            
            while current_date <= end_date:
                date_str = current_date.strftime('%Y-%m-%d')
                complete_daily_counts[date_str] = daily_counts.get(date_str, 0)
                current_date += timedelta(days=1)
            
            return complete_daily_counts
            
        except Exception as e:
            print(f"⚠️  Warning: Could not create complete daily array: {e}")
            return daily_counts
    
    def extract_cwe_info(self, cve_data):
        """Extract CWE (Common Weakness Enumeration) information from CVE data"""
        cwes = []
        try:
            # Look for CWE information in the weaknesses section
            weaknesses = cve_data.get('cve', {}).get('weaknesses', [])
            
            for weakness in weaknesses:
                descriptions = weakness.get('description', [])
                for desc in descriptions:
                    if desc.get('lang') == 'en':  # English descriptions only
                        cwe_value = desc.get('value', '')
                        if cwe_value and cwe_value.startswith('CWE-'):
                            # Filter out "Missing" CWEs as per original notebook
                            if 'Missing_' not in cwe_value:
                                cwes.append(cwe_value)
            
            return cwes
            
        except Exception:
            return []
    
    def extract_identifier_info(self, cve_data):
        """Extract CVE identifiers and references information (secure hostname check)"""
        identifiers = []
        try:
            # Extract references/identifiers from the CVE data
            references = cve_data.get('cve', {}).get('references', [])
            for ref in references:
                url = ref.get('url', '')
                if url:
                    try:
                        parsed = urlparse(url)
                        hostname = parsed.hostname or ''
                        if hostname == 'github.com' or hostname.endswith('.github.com'):
                            identifiers.append('GitHub')
                        elif hostname == 'nvd.nist.gov':
                            identifiers.append('NVD')
                        elif hostname == 'cve.mitre.org':
                            identifiers.append('MITRE')
                        elif hostname == 'security-tracker.debian.org':
                            identifiers.append('Debian')
                        elif hostname == 'access.redhat.com':
                            identifiers.append('Red Hat')
                        elif hostname == 'ubuntu.com' or hostname.endswith('.ubuntu.com'):
                            identifiers.append('Ubuntu')
                        elif 'bugzilla' in hostname:
                            identifiers.append('Bugzilla')
                        elif hostname == 'exploit-db.com' or hostname == 'www.exploit-db.com':
                            identifiers.append('Exploit-DB')
                        else:
                            if hostname:
                                identifiers.append(hostname)
                    except Exception:
                        pass
            return identifiers
        except Exception:
            return []
    
    def extract_cpe_vendor_info(self, cve_data):
        """Extract vendor information from CPE (Common Platform Enumeration) data"""
        vendors = []
        try:
            # Look in cve.configurations for CPE data (it's a list, not dict with nodes)
            configurations = cve_data.get('cve', {}).get('configurations', [])
            
            # configurations is a list of configuration objects
            for config in configurations:
                # Each config has nodes
                nodes = config.get('nodes', [])
                for node in nodes:
                    cpe_matches = node.get('cpeMatch', [])
                    for cpe in cpe_matches:
                        # The CPE URI is in 'criteria' field, not 'cpe23Uri'
                        cpe_uri = cpe.get('criteria', '')
                        if not cpe_uri:
                            # Fallback to cpe23Uri if criteria is empty
                            cpe_uri = cpe.get('cpe23Uri', '')
                        
                        if cpe_uri and cpe_uri.startswith('cpe:2.3:'):
                            # Parse CPE format: cpe:2.3:part:vendor:product:version:...
                            parts = cpe_uri.split(':')
                            if len(parts) > 3:
                                vendor = parts[3].replace('_', ' ').title()
                                if vendor and vendor.lower() not in ['*', 'n/a', 'unknown', '-', '']:
                                    vendors.append(vendor)
            
            return list(set(vendors))  # Remove duplicates
            
        except Exception:
            return []

    def extract_vendor_info(self, cve_data):
        """Extract vendor / CNA information for this CVE.

        This focuses on the CNA/container metadata and assigner fields, and
        lightly supplements with CPE vendors so that yearly aggregates have a
        reasonable view of who is associated with the CVE.
        """
        vendors = set()

        try:
            cve = cve_data.get("cve", {})

            # Preferred: CNA/container shortName or name
            cna_container = cve.get("cnaContainer", {})
            provider = cna_container.get("providerMetadata", {})
            for key in ("shortName", "name"):
                name = provider.get(key)
                if isinstance(name, str) and name.strip():
                    vendors.add(name.strip())

            # Legacy / alternate fields
            for key in ("assignerShortName", "assigner"):
                name = cve.get(key)
                if isinstance(name, str) and name.strip():
                    vendors.add(name.strip())

            # As a supplement, fold in CPE vendors (already normalized)
            for v in self.extract_cpe_vendor_info(cve_data):
                vendors.add(v)

        except Exception:
            # Best-effort only
            pass

        return list(vendors)
    
    def get_year_data(self, year):
        """Main method to get processed data for a specific year"""
        current_year = datetime.now().year
        
        if year < 1999 or year > current_year:
            raise ValueError(f"Year {year} is outside valid range (1999-{current_year})")
        
        return self.process_year_data(year)
    
    def get_all_years_data(self):
        """Get data for all available years"""
        current_year = datetime.now().year
        all_data = {}
        
        print(f"📊 Processing all years (1999-{current_year})...")
        
        for year in range(1999, current_year + 1):
            try:
                all_data[year] = self.get_year_data(year)
            except Exception as e:
                print(f"⚠️  Failed to process {year}: {e}")
                # Create empty data structure for failed years
                all_data[year] = {
                    'year': year,
                    'total_cves': 0,
                    'monthly_counts': [0] * 12,
                    'severity_distribution': {},
                    'top_vendors': [],
                    'top_cwes': [],
                    'error': str(e)
                }
        
        return all_data
    
    def generate_summary_stats(self):
        """Generate overall summary statistics"""
        self.ensure_data_loaded()
        
        print("📊 Generating summary statistics...")
        
        total_cves = 0
        year_counts = Counter()
        severity_counts = Counter()
        
        with open(self.data_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                try:
                    cve_data = json.loads(line)
                    cve_id = cve_data.get('cve', {}).get('CVE_data_meta', {}).get('ID', '')
                    
                    if cve_id.startswith('CVE-'):
                        total_cves += 1
                        
                        # Count by year
                        pub_date = self.parse_cve_date(cve_data)
                        if pub_date:
                            year_counts[pub_date.year] += 1
                        else:
                            # Fallback to CVE ID year
                            year = int(cve_id.split('-')[1])
                            year_counts[year] += 1
                        
                        # Count by severity
                        severity_info = self.extract_severity_info(cve_data)
                        severity_counts[severity_info['severity']] += 1
                
                except (json.JSONDecodeError, KeyError, ValueError, IndexError):
                    continue
        
        return {
            'total_cves': total_cves,
            'year_range': (min(year_counts.keys()), max(year_counts.keys())),
            'years_covered': len(year_counts),
            'year_distribution': dict(sorted(year_counts.items())),
            'severity_distribution': dict(severity_counts.most_common()),
            'generated_at': datetime.now().isoformat()
        }

def main():
    """Main entry point for standalone testing"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Analyze CVE data by year")
    parser.add_argument('--year', type=int, help='Analyze specific year')
    parser.add_argument('--summary', action='store_true', help='Generate summary statistics')
    parser.add_argument('--all-years', action='store_true', help='Process all years')
    
    args = parser.parse_args()
    
    analyzer = CVEYearsAnalyzer()
    
    if args.summary:
        stats = analyzer.generate_summary_stats()
        print(json.dumps(stats, indent=2))
    elif args.year:
        year_data = analyzer.get_year_data(args.year)
        print(json.dumps(year_data, indent=2, default=str))
    elif args.all_years:
        all_data = analyzer.get_all_years_data()
        print(f"Processed {len(all_data)} years")
        for year, data in sorted(all_data.items()):
            print(f"  {year}: {data['total_cves']} CVEs")
    else:
        print("Please specify --year, --summary, or --all-years")

if __name__ == '__main__':
    main()
