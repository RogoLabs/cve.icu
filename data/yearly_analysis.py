#!/usr/bin/env python3
"""
Yearly Analysis Module
Handles year-by-year data processing and aggregation
"""

import json
from pathlib import Path
from datetime import datetime


class YearlyAnalyzer:
    """Handles yearly data processing and aggregation"""
    
    def __init__(self, base_dir, cache_dir, data_dir, quiet=False):
        self.quiet = quiet
        self.base_dir = Path(base_dir)
        self.cache_dir = Path(cache_dir)
        self.data_dir = Path(data_dir)
        self.current_year = datetime.now().year
        self.available_years = list(range(1999, self.current_year + 1))
    
    def generate_year_data_json(self):
        """Generate JSON data files for all available years"""
        if not self.quiet:
            print("📊 Generating year data JSON files...")
        
        try:
            # Import the years analyzer
            from cve_years import CVEYearsAnalyzer
            
            if not self.quiet:
                print("🔽 Initializing CVE data processing...")
            analyzer = CVEYearsAnalyzer(quiet=self.quiet)
            
            # Generate data for all years
            all_year_data = []
            
            for year in self.available_years:
                print(f"  📅 Processing {year}...")
                
                try:
                    year_data = analyzer.get_year_data(year)
                    
                    if year_data:
                        # Save individual year file
                        year_file = self.data_dir / f'cve_{year}.json'
                        with open(year_file, 'w') as f:
                            json.dump(year_data, f, indent=2)
                        
                        all_year_data.append(year_data)
                        print(f"  ✅ Generated cve_{year}.json ({year_data.get('total_cves', 0):,} CVEs)")
                    else:
                        print(f"  ⚠️  No data available for {year}")
                        
                except Exception as e:
                    print(f"  ❌ Failed to process {year}: {e}")
                    continue
            
            print(f"✅ Generated {len(all_year_data)} year data files")
            return all_year_data
            
        except ImportError as e:
            print(f"❌ Failed to import CVE years analyzer: {e}")
            print("📝 Creating placeholder data for development...")
            return self.create_placeholder_year_data()
        except Exception as e:
            print(f"❌ Error generating year data: {e}")
            return []
    
    def create_placeholder_year_data(self):
        """Create placeholder year data for development/testing"""
        print("📝 Creating placeholder year data...")
        
        all_year_data = []
        
        for year in self.available_years:
            # Create basic placeholder data structure
            year_data = {
                'year': year,
                'total_cves': max(100, (year - 1999) * 500),  # Increasing trend
                'date_data': {
                    'monthly_distribution': {str(i): max(10, (year - 1999) * 5) for i in range(1, 13)},
                    'daily_analysis': {
                        'total_days': 365,
                        'days_with_cves': min(365, max(50, (year - 1999) * 10)),
                        'avg_cves_per_day': max(1, (year - 1999) * 1.5),
                        'max_cves_in_day': max(5, (year - 1999) * 3),
                        'daily_counts': {}
                    }
                },
                'vendors': {
                    'total_cves_with_vendors': max(80, (year - 1999) * 400),
                    'cpe_vendors': [
                        {'name': 'Microsoft Corporation', 'count': max(20, (year - 1999) * 50)},
                        {'name': 'Adobe Inc.', 'count': max(15, (year - 1999) * 30)},
                        {'name': 'Oracle Corporation', 'count': max(10, (year - 1999) * 25)},
                        {'name': 'Google LLC', 'count': max(8, (year - 1999) * 20)},
                        {'name': 'Apple Inc.', 'count': max(5, (year - 1999) * 15)}
                    ],
                    'cna_assigners': [
                        {'name': 'MITRE Corporation', 'count': max(50, (year - 1999) * 100)},
                        {'name': 'Patchstack', 'count': max(20, (year - 1999) * 40)},
                        {'name': 'Microsoft Corporation', 'count': max(15, (year - 1999) * 30)},
                        {'name': 'Adobe Inc.', 'count': max(10, (year - 1999) * 25)},
                        {'name': 'Wordfence', 'count': max(8, (year - 1999) * 20)}
                    ]
                },
                'cvss': {
                    'total_cves_with_cvss': max(70, (year - 1999) * 350),
                    'v2.0': {
                        'severity': {'LOW': 10, 'MEDIUM': 30, 'HIGH': 20},
                        'scores': {'2.1': 5, '5.0': 15, '7.5': 10, '9.3': 8}
                    },
                    'v3.0': {
                        'severity': {'LOW': 15, 'MEDIUM': 40, 'HIGH': 25, 'CRITICAL': 10},
                        'scores': {'3.1': 8, '5.4': 20, '7.8': 15, '9.8': 12}
                    },
                    'v3.1': {
                        'severity': {'LOW': 20, 'MEDIUM': 50, 'HIGH': 30, 'CRITICAL': 15},
                        'scores': {'2.7': 10, '5.9': 25, '8.1': 18, '9.9': 15}
                    }
                },
                'cwe': {
                    'total_cves_with_cwe': max(60, (year - 1999) * 300),
                    'top_cwes': [
                        {'id': '79', 'name': 'Cross-site Scripting (XSS)', 'count': max(10, (year - 1999) * 20)},
                        {'id': '89', 'name': 'SQL Injection', 'count': max(8, (year - 1999) * 15)},
                        {'id': '20', 'name': 'Improper Input Validation', 'count': max(6, (year - 1999) * 12)},
                        {'id': '22', 'name': 'Path Traversal', 'count': max(5, (year - 1999) * 10)},
                        {'id': '352', 'name': 'Cross-Site Request Forgery (CSRF)', 'count': max(4, (year - 1999) * 8)}
                    ]
                }
            }
            
            # Save individual year file
            year_file = self.data_dir / f'cve_{year}.json'
            with open(year_file, 'w') as f:
                json.dump(year_data, f, indent=2)
            
            all_year_data.append(year_data)
            print(f"  📝 Created placeholder cve_{year}.json")
        
        print(f"✅ Created {len(all_year_data)} placeholder year files")
        return all_year_data
    
    def generate_cve_all_json(self, all_year_data):
        """Generate overall CVE statistics across all years"""
        print("  📊 Generating overall CVE statistics...")
        
        # Calculate totals and trends
        total_cves = sum(year['total_cves'] for year in all_year_data)
        years_with_data = len(all_year_data)
        
        # Find peak year
        peak_year_data = max(all_year_data, key=lambda x: x['total_cves'])
        peak_year = peak_year_data['year']
        peak_count = peak_year_data['total_cves']
        
        # Calculate current year stats
        current_year_data = next((year for year in all_year_data if year['year'] == self.current_year), None)
        current_year_count = current_year_data['total_cves'] if current_year_data else 0
        
        # Calculate YoY growth (current vs previous year)
        previous_year_data = next((year for year in all_year_data if year['year'] == self.current_year - 1), None)
        previous_year_count = previous_year_data['total_cves'] if previous_year_data else 0
        
        yoy_growth = 0
        if previous_year_count > 0:
            yoy_growth = ((current_year_count - previous_year_count) / previous_year_count) * 100
        
        # Calculate average CVEs per day for current year
        avg_cves_per_day = 0
        if current_year_data:
            days_elapsed = datetime.now().timetuple().tm_yday
            avg_cves_per_day = current_year_count / days_elapsed if days_elapsed > 0 else 0
        
        # Create yearly trend data for charts
        yearly_data = []
        for year_data in sorted(all_year_data, key=lambda x: x['year']):
            yearly_data.append({
                'year': year_data['year'],
                'count': year_data['total_cves']
            })
        
        cve_all_data = {
            'generated_at': datetime.now().isoformat(),
            'total_cves': total_cves,
            'years_covered': years_with_data,
            'current_year': self.current_year,
            'current_year_cves': current_year_count,
            'peak_year': peak_year,
            'peak_count': peak_count,
            'yoy_growth_rate': round(yoy_growth, 1),
            'avg_cves_per_day': round(avg_cves_per_day, 1),
            'yearly_trend': yearly_data
        }
        
        # Save to file
        output_file = self.data_dir / 'cve_all.json'
        with open(output_file, 'w') as f:
            json.dump(cve_all_data, f, indent=2)
        
        print(f"  ✅ Generated cve_all.json with {total_cves:,} total CVEs")
        return cve_all_data
    
    def generate_growth_analysis(self, all_year_data):
        """Generate growth trend analysis across all years"""
        print(f"  📈 Generating growth trend analysis...")
        
        # Get current date for year-to-date calculations
        current_date = datetime.now()
        current_year = current_date.year
        day_of_year = current_date.timetuple().tm_yday
        
        # Calculate year-over-year growth rates
        growth_data = []
        
        for i, year_data in enumerate(sorted(all_year_data, key=lambda x: x['year'])):
            if i == 0:
                # First year, no previous data for comparison
                growth_data.append({
                    'year': year_data['year'],
                    'cves': year_data['total_cves'],
                    'growth_rate': 0,
                    'growth_absolute': 0,
                    'is_ytd': year_data['year'] == current_year
                })
            else:
                prev_year_data = sorted(all_year_data, key=lambda x: x['year'])[i-1]
                prev_count = prev_year_data['total_cves']
                current_count = year_data['total_cves']
                
                # For current year, we need to calculate YTD comparison
                if year_data['year'] == current_year:
                    # Calculate proper YTD comparison: current YTD vs same period last year
                    # We need to get CVEs from previous year up to the same day of year
                    
                    # First, calculate projected full year for growth rate
                    days_in_year = 366 if current_year % 4 == 0 else 365
                    projected_full_year = (current_count / day_of_year) * days_in_year
                    
                    # Calculate growth rate based on projection vs previous full year
                    growth_rate = 0
                    if prev_count > 0:
                        growth_rate = ((projected_full_year - prev_count) / prev_count) * 100
                    
                    # For YTD comparison, we need to estimate previous year's YTD count
                    # Since we don't have daily data, we'll estimate based on year progress
                    prev_year_ytd_estimate = (prev_count / days_in_year) * day_of_year
                    
                    # Calculate true YTD comparison (current YTD vs previous year same period)
                    ytd_comparison = 0
                    if prev_year_ytd_estimate > 0:
                        ytd_comparison = ((current_count - prev_year_ytd_estimate) / prev_year_ytd_estimate) * 100
                    
                    growth_data.append({
                        'year': year_data['year'],
                        'cves': current_count,
                        'growth_rate': round(growth_rate, 1),
                        'growth_absolute': int(projected_full_year - prev_count),
                        'is_ytd': True,
                        'projected_full_year': int(projected_full_year),
                        'ytd_vs_prev_full': round(((current_count - prev_count) / prev_count) * 100, 1) if prev_count > 0 else 0,
                        'ytd_vs_prev_ytd': round(ytd_comparison, 1),
                        'prev_year_ytd_estimate': int(prev_year_ytd_estimate)
                    })
                else:
                    # Normal year-over-year calculation for completed years
                    growth_rate = 0
                    if prev_count > 0:
                        growth_rate = ((current_count - prev_count) / prev_count) * 100
                    
                    growth_data.append({
                        'year': year_data['year'],
                        'cves': current_count,
                        'growth_rate': round(growth_rate, 1),
                        'growth_absolute': current_count - prev_count,
                        'is_ytd': False
                    })
        
        # Calculate moving averages (exclude current year from averages since it's YTD)
        window_size = 3
        for i, entry in enumerate(growth_data):
            if entry.get('is_ytd', False):
                # For YTD data, don't calculate moving average
                entry['growth_rate_3yr_avg'] = entry['growth_rate']
            elif i >= window_size - 1:
                # Only include completed years in moving average
                window_rates = [growth_data[j]['growth_rate'] for j in range(i - window_size + 1, i + 1) 
                               if not growth_data[j].get('is_ytd', False)]
                if window_rates:
                    entry['growth_rate_3yr_avg'] = round(sum(window_rates) / len(window_rates), 1)
                else:
                    entry['growth_rate_3yr_avg'] = entry['growth_rate']
            else:
                entry['growth_rate_3yr_avg'] = entry['growth_rate']
        
        # Filter out YTD data for aggregate statistics since it's not comparable
        completed_years = [entry for entry in growth_data[1:] if not entry.get('is_ytd', False)]
        
        # Get current year data for YTD comparison
        current_year_data = next((entry for entry in growth_data if entry.get('is_ytd', False)), None)
        
        growth_analysis = {
            'generated_at': datetime.now().isoformat(),
            'growth_data': growth_data,
            'avg_annual_growth': round(sum(entry['growth_rate'] for entry in completed_years) / len(completed_years), 1) if completed_years else 0,
            'highest_growth_year': max(completed_years, key=lambda x: x['growth_rate']) if completed_years else None,
            'lowest_growth_year': min(completed_years, key=lambda x: x['growth_rate']) if completed_years else None,
            'current_year_ytd': current_year_data
        }
        
        # Save to file
        output_file = self.data_dir / 'growth_analysis.json'
        with open(output_file, 'w') as f:
            json.dump(growth_analysis, f, indent=2)
        
        if not self.quiet:
            print(f"  ✅ Generated growth analysis with {len(growth_data)} years of data")
        return growth_analysis
