#!/usr/bin/env python3
"""
Scoring Analysis Module for CVE.ICU
Generates analysis files for the Scoring Hub: EPSS, KEV, and Risk Matrix data
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from data.logging_config import get_logger
except ImportError:
    from logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class ScoringAnalyzer:
    """Generates scoring-related analysis files for the Scoring Hub"""
    base_dir: Path | None = None
    cache_dir: Path | None = None
    output_dir: Path | None = None
    epss_file: Path = field(init=False)
    kev_file: Path = field(init=False)
    nvd_file: Path = field(init=False)
    
    def __post_init__(self) -> None:
        """Set up paths with defaults if not provided."""
        if self.base_dir is None:
            self.base_dir = Path(__file__).parent.parent
        else:
            self.base_dir = Path(self.base_dir)
        
        if self.cache_dir is None:
            self.cache_dir = self.base_dir / 'data' / 'cache'
        else:
            self.cache_dir = Path(self.cache_dir)
        
        if self.output_dir is None:
            self.output_dir = self.base_dir / 'web' / 'data'
        else:
            self.output_dir = Path(self.output_dir)
        
        # Source files
        self.epss_file = self.cache_dir / 'epss_scores-current.json'
        self.kev_file = self.cache_dir / 'known_exploited_vulnerabilities.json'
        self.nvd_file = self.cache_dir / 'nvd.json'
        
    def load_epss_data(self) -> dict[str, dict[str, float]]:
        """Load EPSS scores from parsed JSON"""
        if not self.epss_file.exists():
            logger.warning(f"⚠️  EPSS file not found: {self.epss_file}")
            return {}
        
        with open(self.epss_file, 'r') as f:
            return json.load(f)
    
    def load_nvd_publication_dates(self) -> dict[str, str]:
        """Load CVE publication dates from NVD data.
        
        Returns a dict mapping CVE ID -> publication year (e.g., "2024")
        """
        if not self.nvd_file.exists():
            logger.warning(f"⚠️  NVD file not found: {self.nvd_file}")
            return {}
        
        logger.debug("  📂 Loading NVD publication dates...")
        pub_dates: dict[str, str] = {}
        
        try:
            with open(self.nvd_file, 'r') as f:
                nvd_data = json.load(f)
            
            # NVD data is a list of items with 'cve' key
            if isinstance(nvd_data, list):
                for item in nvd_data:
                    cve = item.get('cve', {})
                    cve_id = cve.get('id', '')
                    published = cve.get('published', '')
                    if cve_id and published:
                        # Extract year from ISO date like "2024-01-15T04:00:00.000"
                        try:
                            pub_year = published[:4]
                            if pub_year.isdigit():
                                pub_dates[cve_id] = pub_year
                        except (IndexError, ValueError):
                            pass
            
            logger.debug(f"  ✅ Loaded publication dates for {len(pub_dates):,} CVEs")
            return pub_dates
            
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"⚠️  Error loading NVD data: {e}")
            return {}
    
    def load_kev_data(self) -> dict[str, Any]:
        """Load KEV data from CISA JSON"""
        if not self.kev_file.exists():
            logger.warning(f"⚠️  KEV file not found: {self.kev_file}")
            return {'vulnerabilities': []}
        
        with open(self.kev_file, 'r') as f:
            return json.load(f)
    
    def load_cvss_data(self) -> dict[str, Any]:
        """Load CVSS data from existing analysis file or count from NVD"""
        cvss_file = self.output_dir / 'cvss_analysis.json'
        if cvss_file.exists():
            with open(cvss_file, 'r') as f:
                return json.load(f)
        
        # Fallback: count CVSS from NVD data directly
        logger.warning(f"⚠️  CVSS analysis file not found: {cvss_file}")
        logger.info(f"    📂 Counting CVSS from NVD data directly...")
        
        if not self.nvd_file.exists():
            return {'total_cves_with_cvss': 0}
        
        try:
            with open(self.nvd_file, 'r') as f:
                nvd_data = json.load(f)
            
            count = 0
            # NVD data is a list of items with 'cve' key
            if isinstance(nvd_data, list):
                for item in nvd_data:
                    cve = item.get('cve', {})
                    metrics = cve.get('metrics', {})
                    if metrics.get('cvssMetricV31') or metrics.get('cvssMetricV30') or metrics.get('cvssMetricV2'):
                        count += 1
            else:
                # Old format: dict keyed by CVE ID
                for cve_id, cve_data in nvd_data.items():
                    if cve_data.get('cvss_v3') or cve_data.get('cvss_v2'):
                        count += 1
            
            logger.info(f"    ✅ Found {count:,} CVEs with CVSS scores")
            return {'total_cves_with_cvss': count}
        except (FileNotFoundError, json.JSONDecodeError, KeyError, OSError) as e:
            logger.error(f"    ❌ Error loading NVD data: {e}")
            return {'total_cves_with_cvss': 0}
    
    def generate_epss_analysis(self) -> dict[str, Any] | None:
        """Generate EPSS-focused analysis JSON"""
        logger.info("📊 Generating EPSS analysis...")
        
        epss_data = self.load_epss_data()
        if not epss_data:
            logger.warning("  ⚠️  No EPSS data available")
            return None
        
        # Calculate distributions
        buckets = {
            'very_low': 0,      # 0 - 0.01
            'low': 0,           # 0.01 - 0.1
            'medium': 0,        # 0.1 - 0.3
            'high': 0,          # 0.3 - 0.5
            'very_high': 0,     # 0.5 - 0.7
            'critical': 0       # 0.7+
        }
        
        percentile_buckets = defaultdict(int)  # 0-10, 10-20, etc.
        year_coverage = defaultdict(lambda: {'total': 0, 'with_epss': 0})
        high_risk_cves = []  # EPSS > 0.5
        
        for cve_id, scores in epss_data.items():
            score = scores.get('epss_score', 0)
            percentile = scores.get('epss_percentile', 0)
            
            # Extract year from CVE ID
            try:
                year = cve_id.split('-')[1]
                year_coverage[year]['with_epss'] += 1
            except (IndexError, ValueError):
                pass
            
            # Score buckets using match/case with guard patterns
            match score:
                case s if s < 0.01:
                    buckets['very_low'] += 1
                case s if s < 0.1:
                    buckets['low'] += 1
                case s if s < 0.3:
                    buckets['medium'] += 1
                case s if s < 0.5:
                    buckets['high'] += 1
                case s if s < 0.7:
                    buckets['very_high'] += 1
                case _:
                    buckets['critical'] += 1
            
            # Percentile buckets (for histogram)
            bucket_idx = min(int(percentile * 10), 9)  # 0-9
            percentile_buckets[bucket_idx] += 1
            
            # High risk list (top by EPSS)
            if score >= 0.5:
                high_risk_cves.append({
                    'cve_id': cve_id,
                    'epss_score': score,
                    'epss_percentile': percentile
                })
        
        # Sort high risk by score descending, limit to top 100
        high_risk_cves.sort(key=lambda x: x['epss_score'], reverse=True)
        high_risk_cves = high_risk_cves[:100]
        
        # Calculate statistics
        all_scores = [s['epss_score'] for s in epss_data.values()]
        avg_score = sum(all_scores) / len(all_scores) if all_scores else 0
        
        # Threshold counts
        gt_01 = sum(1 for s in all_scores if s > 0.1)
        gt_03 = sum(1 for s in all_scores if s > 0.3)
        gt_05 = sum(1 for s in all_scores if s > 0.5)
        gt_07 = sum(1 for s in all_scores if s > 0.7)
        gt_09 = sum(1 for s in all_scores if s > 0.9)
        
        analysis = {
            'generated_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            'total_cves_with_epss': len(epss_data),
            'statistics': {
                'average_score': round(avg_score, 6),
                'gt_0_1': gt_01,
                'gt_0_3': gt_03,
                'gt_0_5': gt_05,
                'gt_0_7': gt_07,
                'gt_0_9': gt_09
            },
            'score_buckets': buckets,
            'percentile_distribution': dict(sorted(percentile_buckets.items())),
            'year_coverage': dict(sorted(year_coverage.items())),
            'high_risk_cves': high_risk_cves
        }
        
        output_file = self.output_dir / 'epss_analysis.json'
        with open(output_file, 'w') as f:
            json.dump(analysis, f, indent=2)
        
        logger.info(f"  ✅ Generated {output_file.name}")
        logger.info(f"     Total CVEs with EPSS: {len(epss_data):,}")
        logger.info(f"     High risk (>0.5): {gt_05:,}")
        
        return analysis
    
    def generate_kev_analysis(self) -> dict[str, Any] | None:
        """Generate KEV-focused analysis JSON"""
        logger.info("📊 Generating KEV analysis...")
        
        kev_data = self.load_kev_data()
        vulnerabilities = kev_data.get('vulnerabilities', [])
        
        if not vulnerabilities:
            logger.warning("  ⚠️  No KEV data available")
            return None
        
        # Load NVD publication dates for accurate published year
        nvd_pub_dates = self.load_nvd_publication_dates()
        
        # Aggregations
        by_year_added = defaultdict(int)
        by_year_cve = defaultdict(int)  # Year from CVE ID (CVE-YYYY-NNNN)
        by_year_published = defaultdict(int)  # Actual NVD publication year
        by_vendor = defaultdict(int)
        by_product = defaultdict(int)
        by_cwe = defaultdict(int)
        ransomware_count = 0
        
        recent_30_days = []
        recent_90_days = []
        now = datetime.now(timezone.utc)
        
        timeline = defaultdict(int)  # Monthly additions
        
        for vuln in vulnerabilities:
            cve_id = vuln.get('cveID', '')
            vendor = vuln.get('vendorProject', 'Unknown')
            product = vuln.get('product', 'Unknown')
            date_added = vuln.get('dateAdded', '')
            cwes = vuln.get('cwes', [])
            ransomware = vuln.get('knownRansomwareCampaignUse', 'Unknown')
            
            # Year from CVE ID (CVE-YYYY-NNNN) - not reliable for publication date
            try:
                cve_year = cve_id.split('-')[1]
                by_year_cve[cve_year] += 1
            except (IndexError, ValueError):
                pass
            
            # Actual publication year from NVD
            if cve_id in nvd_pub_dates:
                by_year_published[nvd_pub_dates[cve_id]] += 1
            
            # Year added to KEV
            if date_added:
                try:
                    added_date = datetime.strptime(date_added, '%Y-%m-%d').replace(tzinfo=timezone.utc)
                    by_year_added[str(added_date.year)] += 1
                    
                    # Monthly timeline
                    month_key = added_date.strftime('%Y-%m')
                    timeline[month_key] += 1
                    
                    # Recent additions
                    days_ago = (now - added_date).days
                    if days_ago <= 30:
                        recent_30_days.append({
                            'cve_id': cve_id,
                            'vendor': vendor,
                            'product': product,
                            'date_added': date_added,
                            'due_date': vuln.get('dueDate', ''),
                            'ransomware': ransomware
                        })
                    if days_ago <= 90:
                        recent_90_days.append({
                            'cve_id': cve_id,
                            'vendor': vendor,
                            'product': product,
                            'date_added': date_added
                        })
                except ValueError:
                    pass
            
            # Vendor and product
            by_vendor[vendor] += 1
            by_product[f"{vendor} - {product}"] += 1
            
            # CWEs
            for cwe in cwes:
                by_cwe[cwe] += 1
            
            # Ransomware
            if ransomware and ransomware.lower() not in ['unknown', 'no']:
                ransomware_count += 1
        
        # Sort and limit top lists
        top_vendors = sorted(by_vendor.items(), key=lambda x: x[1], reverse=True)[:20]
        top_products = sorted(by_product.items(), key=lambda x: x[1], reverse=True)[:20]
        top_cwes = sorted(by_cwe.items(), key=lambda x: x[1], reverse=True)[:20]
        
        # Sort recent by date
        recent_30_days.sort(key=lambda x: x['date_added'], reverse=True)
        recent_90_days.sort(key=lambda x: x['date_added'], reverse=True)
        
        analysis = {
            'generated_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            'catalog_version': kev_data.get('catalogVersion', ''),
            'total_kev_cves': len(vulnerabilities),
            'statistics': {
                'added_last_30_days': len(recent_30_days),
                'added_last_90_days': len(recent_90_days),
                'ransomware_associated': ransomware_count
            },
            'by_year_added': dict(sorted(by_year_added.items())),
            'by_year_cve': dict(sorted(by_year_cve.items())),
            'by_year_published': dict(sorted(by_year_published.items())),
            'timeline': dict(sorted(timeline.items())),
            'top_vendors': top_vendors,
            'top_products': top_products,
            'top_cwes': top_cwes,
            'recent_additions': recent_30_days[:20]  # Last 20 for display
        }
        
        output_file = self.output_dir / 'kev_analysis.json'
        with open(output_file, 'w') as f:
            json.dump(analysis, f, indent=2)
        
        logger.info(f"  ✅ Generated {output_file.name}")
        logger.info(f"     Total KEV CVEs: {len(vulnerabilities):,}")
        logger.info(f"     Added last 30 days: {len(recent_30_days)}")
        
        return analysis
    
    def generate_risk_matrix(self) -> dict[str, Any]:
        """Generate bucketed CVSS × EPSS risk matrix data"""
        logger.info("📊 Generating risk matrix...")
        
        epss_data = self.load_epss_data()
        self.load_cvss_data()
        kev_data = self.load_kev_data()
        
        # Build KEV set for quick lookup using set comprehension with walrus
        kev_set = {
            cve_id
            for vuln in kev_data.get('vulnerabilities', [])
            if (cve_id := vuln.get('cveID', ''))
        }
        
        # CVSS severity bands
        severity_bands = ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        
        # EPSS buckets
        epss_buckets = ['0-0.1', '0.1-0.3', '0.3-0.5', '0.5-0.7', '0.7+']
        
        def get_epss_bucket(score):
            match score:
                case s if s < 0.1:
                    return '0-0.1'
                case s if s < 0.3:
                    return '0.1-0.3'
                case s if s < 0.5:
                    return '0.3-0.5'
                case s if s < 0.7:
                    return '0.5-0.7'
                case _:
                    return '0.7+'
        
        def get_severity_from_score(score):
            match score:
                case 0:
                    return 'NONE'
                case s if s < 4.0:
                    return 'LOW'
                case s if s < 7.0:
                    return 'MEDIUM'
                case s if s < 9.0:
                    return 'HIGH'
                case _:
                    return 'CRITICAL'
        
        # Initialize matrix
        matrix = {}
        for severity in severity_bands:
            for epss_bucket in epss_buckets:
                key = f"{severity}_{epss_bucket}"
                matrix[key] = {
                    'severity': severity,
                    'epss_bucket': epss_bucket,
                    'count': 0,
                    'kev_count': 0
                }
        
        # We need to correlate EPSS with CVSS scores
        # Load yearly files to get CVSS scores per CVE
        # For now, use the severity distribution from cvss_analysis
        # This is a simplified approach - in production we'd scan nvd.json
        
        # For the matrix, we'll estimate based on overall distributions
        # and the EPSS data we have
        
        # Actually, let's load the NVD data to get proper CVSS scores
        if self.nvd_file.exists():
            logger.info("  📂 Loading NVD data for CVSS correlation...")
            with open(self.nvd_file, 'r') as f:
                nvd_data = json.load(f)
            
            for record in nvd_data:
                cve_info = record.get('cve', {})
                cve_id = cve_info.get('id', '')
                
                if cve_id not in epss_data:
                    continue
                
                epss_score = epss_data[cve_id].get('epss_score', 0)
                epss_bucket = get_epss_bucket(epss_score)
                
                # Get CVSS score - try v3.1, v3.0, v2.0, v4.0
                cvss_score = None
                metrics = cve_info.get('metrics', {})
                
                for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV40', 'cvssMetricV2']:
                    if version in metrics and metrics[version]:
                        metric = metrics[version][0]
                        cvss_data_inner = metric.get('cvssData', {})
                        if cvss_score := cvss_data_inner.get('baseScore'):
                            break
                
                if cvss_score is None:
                    continue
                
                severity = get_severity_from_score(cvss_score)
                key = f"{severity}_{epss_bucket}"
                
                matrix[key]['count'] += 1
                if cve_id in kev_set:
                    matrix[key]['kev_count'] += 1
        else:
            logger.warning("  ⚠️  NVD file not found, using estimated data")
        
        # Convert to list format for easier charting
        matrix_list = list(matrix.values())
        
        # Calculate totals
        total_in_matrix = sum(m['count'] for m in matrix_list)
        total_kev_in_matrix = sum(m['kev_count'] for m in matrix_list)
        
        analysis = {
            'generated_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            'severity_bands': severity_bands,
            'epss_buckets': epss_buckets,
            'matrix': matrix_list,
            'totals': {
                'cves_in_matrix': total_in_matrix,
                'kev_in_matrix': total_kev_in_matrix
            }
        }
        
        output_file = self.output_dir / 'risk_matrix.json'
        with open(output_file, 'w') as f:
            json.dump(analysis, f, indent=2)
        
        logger.info(f"  ✅ Generated {output_file.name}")
        logger.info(f"     CVEs in matrix: {total_in_matrix:,}")
        logger.info(f"     KEV in matrix: {total_kev_in_matrix:,}")
        
        return analysis
    
    def generate_scoring_comparison(self) -> dict[str, Any]:
        """Generate comparison data for the Scoring Hub landing page"""
        logger.info("📊 Generating scoring comparison...")
        
        epss_data = self.load_epss_data()
        kev_data = self.load_kev_data()
        cvss_data = self.load_cvss_data()
        
        kev_vulnerabilities = kev_data.get('vulnerabilities', [])
        kev_set = {v.get('cveID', '') for v in kev_vulnerabilities}
        
        # Count overlaps
        epss_and_kev = sum(1 for cve_id in epss_data if cve_id in kev_set)
        
        # High EPSS in KEV
        high_epss_in_kev = sum(
            1 for cve_id, scores in epss_data.items() 
            if cve_id in kev_set and scores.get('epss_score', 0) > 0.5
        )
        
        comparison = {
            'generated_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            'systems': {
                'cvss': {
                    'name': 'CVSS',
                    'full_name': 'Common Vulnerability Scoring System',
                    'description': 'Measures severity/impact of vulnerabilities',
                    'question': 'How bad is it?',
                    'total_scored': cvss_data.get('total_cves_with_cvss', 0),
                    'source': 'NVD / Vendors',
                    'update_frequency': 'Per CVE publication'
                },
                'epss': {
                    'name': 'EPSS',
                    'full_name': 'Exploit Prediction Scoring System',
                    'description': 'Predicts likelihood of exploitation in 30 days',
                    'question': 'Will it be exploited?',
                    'total_scored': len(epss_data),
                    'source': 'FIRST.org',
                    'update_frequency': 'Daily'
                },
                'kev': {
                    'name': 'KEV',
                    'full_name': 'Known Exploited Vulnerabilities',
                    'description': 'Confirmed actively exploited vulnerabilities',
                    'question': 'Is it being exploited?',
                    'total_scored': len(kev_vulnerabilities),
                    'source': 'CISA',
                    'update_frequency': 'As exploits are confirmed'
                }
            },
            'overlaps': {
                'epss_and_kev': epss_and_kev,
                'high_epss_in_kev': high_epss_in_kev,
                'kev_coverage_by_epss': round(epss_and_kev / len(kev_vulnerabilities) * 100, 1) if kev_vulnerabilities else 0
            },
            'insights': {
                'epss_gt_05_not_kev': sum(
                    1 for cve_id, scores in epss_data.items()
                    if scores.get('epss_score', 0) > 0.5 and cve_id not in kev_set
                ),
                'kev_with_low_epss': sum(
                    1 for cve_id in kev_set
                    if cve_id in epss_data and epss_data[cve_id].get('epss_score', 0) < 0.1
                )
            }
        }
        
        output_file = self.output_dir / 'scoring_comparison.json'
        with open(output_file, 'w') as f:
            json.dump(comparison, f, indent=2)
        
        logger.info(f"  ✅ Generated {output_file.name}")
        logger.info(f"     EPSS ∩ KEV: {epss_and_kev:,}")
        
        return comparison
    
    def generate_all(self) -> dict[str, Any]:
        """Generate all scoring analysis files"""
        logger.info("\n📊 Generating Scoring Hub Analysis Files")
        logger.info("=" * 50)
        
        results = {}
        results['epss'] = self.generate_epss_analysis()
        results['kev'] = self.generate_kev_analysis()
        results['risk_matrix'] = self.generate_risk_matrix()
        results['comparison'] = self.generate_scoring_comparison()
        
        logger.info("=" * 50)
        logger.info("✅ All scoring analysis files generated!")
        
        return results
    
    def generate_all_scoring_analysis(self) -> dict[str, Any]:
        """Alias for generate_all() - used by build.py"""
        return self.generate_all()


def main() -> None:
    """Main entry point"""
    analyzer = ScoringAnalyzer()
    analyzer.generate_all()


if __name__ == '__main__':
    main()
