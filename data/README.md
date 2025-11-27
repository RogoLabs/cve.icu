# CVE.ICU Data Directory

This directory contains all data processing modules, cache files, and utility scripts for CVE.ICU.

## Directory Structure

```
data/
├── cache/                          # Downloaded CVE data cache
│   ├── nvd.jsonl                   # NVD vulnerability data (~1.4GB)
│   ├── cvelistV5/                  # CVE V5 Git repository clone
│   ├── epss_scores-current.json    # EPSS scores
│   ├── known_exploited_*.json      # KEV catalog
│   ├── cna_list.json               # Official CNA registry
│   └── cna_name_map.json           # CNA UUID to name mappings
├── scripts/                        # Utility scripts
├── *_analysis.py                   # Analysis modules
├── download_cve_data.py            # Data download orchestrator
└── cve_v5_processor.py             # CVE V5 repository processor
```

## Core Analysis Modules

| Module | Purpose | Data Source |
|--------|---------|-------------|
| `yearly_analysis.py` | CVEs by year, trends | NVD |
| `cna_analysis.py` | CNA assignments, top CNAs | CVE V5 + NVD |
| `cvss_analysis.py` | CVSS scores, distributions | NVD |
| `cwe_analysis.py` | Weakness types | NVD |
| `cpe_analysis.py` | Affected products | NVD |
| `calendar_analysis.py` | Publication timing | NVD |
| `scoring_analysis.py` | EPSS, KEV integration | EPSS/KEV APIs |

## Data Flow

```
External APIs          Analysis Modules           Output
─────────────          ────────────────           ──────
NVD JSONL         ──>  yearly_analysis.py    ──>  cve_YYYY.json
CVE V5 Git Repo   ──>  cna_analysis.py       ──>  cna_analysis.json
EPSS API          ──>  cvss_analysis.py      ──>  cvss_analysis.json
KEV API           ──>  cwe_analysis.py       ──>  cwe_analysis.json
CNA Registry      ──>  scoring_analysis.py   ──>  scoring_analysis.json
```

## Cache Directory

The `cache/` directory stores downloaded external data:

- **nvd.jsonl**: NVD vulnerability database (JSONL format, ~1.4GB compressed)
- **cvelistV5/**: Git clone of the CVE List V5 repository
- **epss_scores-current.json**: Current EPSS probability scores
- **known_exploited_vulnerabilities.json**: CISA KEV catalog
- **cna_list.json**: Official CNA registry from CVE.org

Cache is populated by `download_cve_data.py` and can be refreshed with `--force`.

## Key Functions

### cve_v5_processor.py

Processes the CVE V5 Git repository for CNA analysis:

```python
def get_cve_files(repo_path)      # Yields all CVE JSON files
def parse_cve_v5_record(filepath) # Parses single CVE record (excludes REJECTED)
def load_cna_mappings()           # Loads CNA name/email mappings
def process_repository(repo_path) # Main entry point
```

### download_cve_data.py

Downloads and caches external data:

```python
def download_nvd_data(force=False)     # NVD vulnerability data
def clone_or_update_cvelistV5()        # CVE V5 Git repository
def download_epss_scores()             # EPSS probability scores
def download_kev_catalog()             # CISA KEV catalog
def download_cna_list()                # Official CNA registry
```

## Counting Methodology

All analysis modules consistently exclude REJECTED CVEs:

- **V5 Repository**: Filters by `cveMetadata.state == 'PUBLISHED'`
- **NVD Data**: Filters by `vulnStatus` not containing 'Rejected'

See [docs/COUNTING.md](../docs/COUNTING.md) for detailed counting methodology.

## Scripts Directory

Utility scripts for rebuilding specific analyses:

- `rebuild_cna.py` - Rebuild CNA analysis only
- `rebuild_cvss.py` - Rebuild CVSS analysis only
- `rebuild_cwe.py` - Rebuild CWE analysis only
- `rebuild_cpe.py` - Rebuild CPE analysis only
- `rebuild_growth.py` - Rebuild growth analysis only
- `rebuild_templates.py` - Rebuild HTML templates only
- `quick_build.py` - Fast development build

## Testing

Run data module tests:

```bash
pytest tests/test_*.py -v
```

Validate data consistency:

```bash
python build.py --validate
```
