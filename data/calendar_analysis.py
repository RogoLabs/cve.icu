#!/usr/bin/env python3
"""
Calendar Analysis Module for CVE.ICU
Generates daily CVE publication data for calendar heatmap visualization
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np

try:
    from data.logging_config import get_logger
except ImportError:
    from logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class CalendarAnalyzer:
    """Analyzer for generating calendar-based CVE publication data"""
    base_dir: Path
    cache_dir: Path
    data_dir: Path
    quiet: bool = False
    
    def __post_init__(self) -> None:
        """Convert path arguments to Path objects and set up derived attributes."""
        self.base_dir = Path(self.base_dir)
        self.cache_dir = Path(self.cache_dir)
        self.data_dir = Path(self.data_dir)
        self.nvd_file: Path = self.cache_dir / 'nvd.json'
        
    def load_nvd_data(self) -> list[dict[str, Any]]:
        """Load and parse NVD data from JSONL file"""
        if not self.quiet:
            logger.info("    📂 Loading NVD data for calendar analysis...")
        
        if not self.nvd_file.exists():
            logger.error(f"    ❌ NVD file not found: {self.nvd_file}")
            return []
        
        cve_records = []
        try:
            with open(self.nvd_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            if not self.quiet:
                logger.info(f"    📊 Processing {len(data):,} CVE records for calendar analysis...")
            
            for entry in data:
                try:
                    cve_id = entry.get('cve', {}).get('id', '')
                    published = entry.get('cve', {}).get('published', '')
                    
                    # Extract CVSS score (try v3.1 first, then v3.0, then v2.0)
                    cvss_score = None
                    metrics = entry.get('cve', {}).get('metrics', {})
                    
                    if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                        cvss_score = metrics['cvssMetricV31'][0].get('cvssData', {}).get('baseScore')
                    elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                        cvss_score = metrics['cvssMetricV30'][0].get('cvssData', {}).get('baseScore')
                    elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                        cvss_score = metrics['cvssMetricV2'][0].get('cvssData', {}).get('baseScore')
                    
                    # Skip rejected CVEs
                    status = entry.get('cve', {}).get('vulnStatus', '')
                    if 'Rejected' in status:
                        continue
                    
                    if cve_id and published:
                        cve_records.append({
                            'cve_id': cve_id,
                            'published': published,
                            'cvss_score': cvss_score
                        })
                        
                except (KeyError, TypeError, ValueError):
                    continue  # Skip malformed entries
                    
            if not self.quiet:
                logger.info(f"    ✅ Loaded {len(cve_records):,} valid CVE records")
            return cve_records
            
        except (FileNotFoundError, json.JSONDecodeError, OSError) as e:
            logger.error(f"    ❌ Error loading NVD data: {e}")
            return []
    
    def process_daily_data(self, cve_records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        """Process CVE records into daily publication counts"""
        if not self.quiet:
            logger.info("    📅 Processing daily CVE publication data...")
        
        daily_counts: dict[str, int] = defaultdict(int)
        daily_scores: dict[str, list[float]] = defaultdict(list)
        
        for record in cve_records:
            try:
                # Parse publication date
                pub_date = datetime.fromisoformat(record['published'].replace('Z', '+00:00'))
                date_key = pub_date.strftime('%Y-%m-%d')
                
                daily_counts[date_key] += 1
                
                if record['cvss_score'] is not None:
                    daily_scores[date_key].append(record['cvss_score'])
                    
            except (ValueError, KeyError, TypeError):
                continue  # Skip invalid dates
        
        # Calculate daily averages
        daily_data = {}
        for date_key, count in daily_counts.items():
            scores = daily_scores.get(date_key, [])

            entry: dict[str, Any] = {
                'date': date_key,
                'count': count,
            }
            # Only include CVSS fields when there is actual score data
            if scores:
                entry['avg_cvss_score'] = round(float(np.mean(scores)), 1)
                entry['cvss_count'] = len(scores)

            daily_data[date_key] = entry
        
        if not self.quiet:
            logger.info(f"    ✅ Processed {len(daily_data):,} days of CVE data")
        return daily_data
    
    def calculate_statistics(self, daily_data: dict[str, dict[str, Any]], cve_records: list[dict[str, Any]]) -> dict[str, Any]:
        """Calculate overall statistics for the calendar analysis"""
        if not self.quiet:
            logger.info("    📊 Calculating calendar statistics...")
        
        total_cves = len(cve_records)
        total_days = len(daily_data)
        
        # Calculate date range
        dates = [datetime.strptime(date_key, '%Y-%m-%d') for date_key in daily_data.keys()]
        start_date = min(dates) if dates else datetime.now()
        end_date = max(dates) if dates else datetime.now()
        
        # Calculate averages
        daily_counts = [data['count'] for data in daily_data.values()]
        avg_per_day = np.mean(daily_counts) if daily_counts else 0
        max_per_day = max(daily_counts) if daily_counts else 0
        min_per_day = min(daily_counts) if daily_counts else 0
        
        # Find peak day
        peak_day_data = max(daily_data.values(), key=lambda x: x['count']) if daily_data else None
        
        # Calculate CVSS statistics
        cvss_scores = [record['cvss_score'] for record in cve_records if record['cvss_score'] is not None]
        avg_cvss = np.mean(cvss_scores) if cvss_scores else None
        
        # Calculate current year statistics
        current_year = datetime.now().year
        current_year_data = {k: v for k, v in daily_data.items() if k.startswith(str(current_year))}
        current_year_cves = sum(data['count'] for data in current_year_data.values())
        
        statistics = {
            'total_cves': total_cves,
            'total_days_with_data': total_days,
            'date_range': {
                'start': start_date.strftime('%Y-%m-%d'),
                'end': end_date.strftime('%Y-%m-%d')
            },
            'daily_stats': {
                'average_per_day': round(avg_per_day, 2),
                'max_per_day': max_per_day,
                'min_per_day': min_per_day,
                'peak_day': {
                    'date': peak_day_data['date'] if peak_day_data else None,
                    'count': peak_day_data['count'] if peak_day_data else 0
                }
            },
            'cvss_stats': {
                'average_score': round(avg_cvss, 2) if avg_cvss else None,
                'total_with_scores': len(cvss_scores)
            },
            'current_year': {
                'year': current_year,
                'total_cves': current_year_cves,
                'days_with_data': len(current_year_data)
            }
        }
        
        return statistics
    
    def generate_calendar_analysis(self) -> dict[str, Any] | None:
        """Generate comprehensive calendar analysis"""
        logger.info("  📅 Generating calendar analysis...")
        
        # Load CVE data
        cve_records = self.load_nvd_data()
        if not cve_records:
            logger.error("  ❌ No CVE data available for calendar analysis")
            return None
        
        # Process daily data
        daily_data = self.process_daily_data(cve_records)
        if not daily_data:
            logger.error("  ❌ No daily data generated")
            return None
        
        # Calculate statistics
        statistics = self.calculate_statistics(daily_data, cve_records)
        
        # Prepare calendar data for frontend
        calendar_data = []
        for date_key, data in daily_data.items():
            entry: dict[str, Any] = {
                'date': date_key,
                'value': data['count'],
            }
            # Only include CVSS fields when score data exists (saves ~bytes per entry)
            if 'avg_cvss_score' in data:
                entry['avg_cvss'] = data['avg_cvss_score']
                entry['cvss_count'] = data['cvss_count']
            calendar_data.append(entry)
        
        # Sort by date
        calendar_data.sort(key=lambda x: x['date'])
        
        analysis_result = {
            'generated_at': datetime.now().isoformat(),
            'statistics': statistics,
            'daily_data': calendar_data,
            'metadata': {
                'total_records': len(cve_records),
                'total_days': len(daily_data),
                'data_source': 'NVD JSONL',
                'analysis_type': 'calendar_heatmap'
            }
        }
        
        # Save to file
        output_file = self.data_dir / 'calendar_analysis.json'
        with open(output_file, 'w') as f:
            json.dump(analysis_result, f, indent=2)
        
        if not self.quiet:
            logger.info(f"  ✅ Generated calendar analysis with {len(calendar_data):,} days of data")
        return analysis_result
    
    def generate_current_year_calendar_analysis(self) -> dict[str, Any] | None:
        """Generate current year specific calendar analysis"""
        logger.info("  📅 Generating current year calendar analysis...")
        
        # Load full analysis first
        full_analysis = self.generate_calendar_analysis()
        if not full_analysis:
            return None
        
        current_year = datetime.now().year
        
        # Filter for current year data
        current_year_daily = [
            data for data in full_analysis['daily_data'] 
            if data['date'].startswith(str(current_year))
        ]
        
        # Calculate current year statistics
        if current_year_daily:
            total_cves = sum(data['value'] for data in current_year_daily)
            avg_per_day = total_cves / len(current_year_daily) if current_year_daily else 0
            max_day = max(current_year_daily, key=lambda x: x['value']) if current_year_daily else None
            
            # Calculate CVSS average for current year
            cvss_scores = [data['avg_cvss'] for data in current_year_daily if data.get('avg_cvss') is not None]
            avg_cvss = np.mean(cvss_scores) if cvss_scores else None
            
            current_year_stats = {
                'year': current_year,
                'total_cves': total_cves,
                'total_days_with_data': len(current_year_daily),
                'average_per_day': round(avg_per_day, 2),
                'peak_day': {
                    'date': max_day['date'] if max_day else None,
                    'count': max_day['value'] if max_day else 0
                },
                'average_cvss': round(avg_cvss, 2) if avg_cvss else None
            }
        else:
            current_year_stats = {
                'year': current_year,
                'total_cves': 0,
                'total_days_with_data': 0,
                'average_per_day': 0,
                'peak_day': {'date': None, 'count': 0},
                'average_cvss': None
            }
        
        current_year_analysis = {
            'generated_at': datetime.now().isoformat(),
            'statistics': current_year_stats,
            'daily_data': current_year_daily,
            'metadata': {
                'year': current_year,
                'total_days': len(current_year_daily),
                'data_source': 'NVD JSONL',
                'analysis_type': 'current_year_calendar'
            }
        }
        
        # Save to file
        output_file = self.data_dir / 'calendar_analysis_current_year.json'
        with open(output_file, 'w') as f:
            json.dump(current_year_analysis, f, indent=2)
        
        if not self.quiet:
            logger.info(f"  ✅ Generated current year calendar analysis with {len(current_year_daily):,} days")
        return current_year_analysis


if __name__ == "__main__":
    # Test the analyzer
    base_dir = Path(__file__).parent.parent
    cache_dir = base_dir / 'data' / 'cache'
    data_dir = base_dir / 'web' / 'data'
    
    analyzer = CalendarAnalyzer(base_dir, cache_dir, data_dir)
    
    logger.info("🗓️  Testing Calendar Analysis...")
    comprehensive_analysis = analyzer.generate_calendar_analysis()
    current_year_analysis = analyzer.generate_current_year_calendar_analysis()
    
    if comprehensive_analysis and current_year_analysis:
        logger.info("✅ Calendar analysis test completed successfully!")
    else:
        logger.error("❌ Calendar analysis test failed!")
