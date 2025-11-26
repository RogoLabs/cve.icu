# CVE.ICU Data Directory

This directory contains all data processing modules, cache files, and utility scripts for CVE.ICU.

## Directory Structure

```
data/
├── cache/                          # Downloaded CVE data cache
├── scripts/                        # Utility and rebuild scripts
├── *.py                           # Core analysis modules
└── *.json                         # Generated data files
```

## Core Analysis Modules

These are the main data processing modules used by the build system:

- **`calendar_analysis.py`** - Daily CVE publication calendar analysis
- **`cna_analysis.py`** - CNA (CVE Numbering Authority) analysis
- **`cpe_analysis.py`** - CPE (Common Platform Enumeration) analysis
- **`cve_v5_processor.py`** - CVE V5 format processor (CVEProject/cvelistV5)
- **`cve_years.py`** - Year-by-year CVE data processor
- **`cvss_analysis.py`** - CVSS scoring analysis
- **`cwe_analysis.py`** - CWE (Common Weakness Enumeration) analysis
- **`download_cve_data.py`** - CVE data downloader from NVD
- **`vendor_analysis.py`** - Vendor and product analysis
- **`yearly_analysis.py`** - Yearly trends and growth analysis

## Utility Scripts

Located in `scripts/` subdirectory for development and maintenance:

- **`quick_build.py`** - Fast rebuild script for development
- **`rebuild_*.py`** - Individual module rebuild scripts (cna, cpe, cvss, cwe, growth, templates)
- **`generate_cna_analysis.py`** - Regenerate comprehensive CNA analysis
- **`cna_mapping_restart.py`** - CNA mapping utility

## Data Files

- **`*.json`** - Generated analysis data files (consumed by website)
- **`cache/`** - Cached CVE data from NVD (nvd.json, etc.)

### EPSS-Enriched CVE Records

Some generated JSON files now include additional fields per CVE where
Exploit Prediction Scoring System (EPSS) data is available:

- `epss_score` *(float, optional)* – Probability of exploitation.
- `epss_percentile` *(float, optional)* – Percentile rank of the EPSS score.

These fields are populated from the cached EPSS feed
(`epss_scores-current.csv.gz` → `epss_scores-current.json`) via
`download_cve_data.py` and are used by analysis modules for risk-focused
views.

## Usage

### Full Build
```bash
cd /path/to/cve.icu
python build.py
```

### Quick Rebuild (individual modules)
```bash
cd data/scripts
python rebuild_cna.py      # Rebuild CNA analysis only
python rebuild_cvss.py     # Rebuild CVSS analysis only
python rebuild_growth.py   # Rebuild growth analysis only
# etc...
```

### Module Development
Core modules are imported by `build.py` and can be used programmatically:

```python
from cna_analysis import CNAAnalyzer
from cvss_analysis import CVSSAnalyzer
from yearly_analysis import YearlyAnalyzer
```

## Notes

- Core modules should remain in `/data/` root for proper imports
- Utility scripts are organized in `/data/scripts/`
- All generated JSON files are output to `/web/data/`
- Cache directory stores downloaded CVE data to avoid repeated downloads
