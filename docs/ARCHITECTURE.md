# CVE.ICU Architecture

This document describes the high-level architecture of the CVE.ICU project.

## System Overview

CVE.ICU is a static site generator that processes CVE (Common Vulnerabilities and Exposures) data from multiple sources and produces interactive visualizations.

```
┌─────────────────────────────────────────────────────────────────────┐
│                          Data Sources                                │
├─────────────────────────────────────────────────────────────────────┤
│  NVD API    CVE V5 Repo    EPSS API    KEV API    CNA Registry      │
└──────┬─────────┬──────────────┬──────────┬──────────┬───────────────┘
       │         │              │          │          │
       ▼         ▼              ▼          ▼          ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        Download Layer                                │
│                    (download_cve_data.py)                           │
└─────────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                          Cache Layer                                 │
│                        (data/cache/)                                 │
│  nvd.jsonl  │  cvelistV5/  │  epss.json  │  kev.json  │  cna.json   │
└─────────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        Analysis Layer                                │
├─────────────────────────────────────────────────────────────────────┤
│  yearly_analysis.py    │  cna_analysis.py     │  cvss_analysis.py   │
│  cwe_analysis.py       │  cpe_analysis.py     │  calendar_analysis  │
│  scoring_analysis.py   │  cve_v5_processor    │  growth_analysis    │
└─────────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         Build Layer                                  │
│                         (build.py)                                   │
│  Template Rendering  │  JSON Generation  │  Data Validation         │
└─────────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         Output Layer                                 │
│                          (web/)                                      │
│  HTML Pages  │  JSON Data Files  │  Static Assets                   │
└─────────────────────────────────────────────────────────────────────┘
```

## Data Flow

### 1. Data Download Phase

`download_cve_data.py` fetches data from external sources:

- **NVD**: Downloads all CVE records via NVD 2.0 API into `nvd.jsonl`
- **CVE V5**: Clones/updates the CVEProject/cvelistV5 Git repository
- **EPSS**: Fetches current exploit probability scores
- **KEV**: Downloads CISA Known Exploited Vulnerabilities catalog
- **CNA Registry**: Fetches official CNA (CVE Numbering Authority) list

### 2. Analysis Phase

Each analysis module processes cached data for specific insights:

| Module | Input | Output | Purpose |
|--------|-------|--------|---------|
| `yearly_analysis.py` | NVD | `cve_YYYY.json` | CVEs per year, trends |
| `cna_analysis.py` | V5 + NVD | `cna_analysis.json` | CNA assignments |
| `cvss_analysis.py` | NVD | `cvss_analysis.json` | Score distributions |
| `cwe_analysis.py` | NVD | `cwe_analysis.json` | Weakness categories |
| `cpe_analysis.py` | NVD | `cpe_analysis.json` | Affected products |
| `calendar_analysis.py` | NVD | `calendar_analysis.json` | Publication timing |
| `scoring_analysis.py` | EPSS+KEV | `scoring_analysis.json` | Exploit scores |

### 3. Build Phase

`build.py` orchestrates the entire pipeline:

1. Downloads/updates cache (unless `--skip-download`)
2. Runs all analysis modules
3. Renders Jinja2 templates with analysis results
4. Copies static assets to output directory
5. Validates data consistency (with `--validate`)

### 4. Output Phase

Generated files in `web/`:

- HTML pages with embedded Chart.js visualizations
- JSON data files for client-side interactivity
- Static CSS/JS assets

## Module Responsibilities

### Core Modules

#### build.py
- Main entry point and orchestrator
- Command-line argument parsing
- Template rendering with Jinja2
- Data validation

#### download_cve_data.py
- External API integration
- Cache management
- Rate limiting and error handling

#### cve_v5_processor.py
- CVE V5 Git repository parsing
- CNA extraction and mapping
- REJECTED CVE filtering

### Analysis Modules

Each analysis module follows a consistent pattern:

```python
def analyze(nvd_data, current_year_only=False):
    """Main analysis function."""
    # Process data
    # Return analysis dict

def main():
    """Command-line entry point."""
    # Load cache
    # Run analysis
    # Save results
```

## Key Design Decisions

### 1. Static Site Generation
- No server-side processing required
- Can be hosted on GitHub Pages
- Fast page loads with pre-computed data

### 2. Dual Data Sources
- **NVD**: Official vulnerability details, CVSS scores
- **CVE V5**: Authoritative CNA assignments, faster updates

### 3. REJECTED CVE Exclusion
- All analyses consistently exclude REJECTED CVEs
- V5: `cveMetadata.state != 'PUBLISHED'`
- NVD: `vulnStatus` contains 'Rejected'

### 4. Current Year Variants
- Each analysis generates two variants:
  - Full dataset: `*_analysis.json`
  - Current year only: `*_analysis_current_year.json`
- Enables focused views without processing overhead

### 5. Incremental Updates
- Git-based V5 repository enables incremental updates
- NVD supports delta queries (not yet implemented)

## Directory Structure

```
cve.icu/
├── build.py                # Main build script
├── COUNTING.md             # Counting methodology
├── data/
│   ├── cache/              # Downloaded data (gitignored)
│   ├── scripts/            # Utility scripts
│   └── *_analysis.py       # Analysis modules
├── docs/
│   ├── ROADMAP.md          # Development roadmap
│   └── ARCHITECTURE.md     # This file
├── templates/              # Jinja2 HTML templates
├── tests/                  # pytest test suite
└── web/                    # Generated output
    ├── data/               # JSON data files
    └── static/             # CSS/JS/images
```

## Testing

Tests are organized by module:

```
tests/
├── test_build.py           # Build process tests
├── test_cna_analysis.py    # CNA analysis tests
├── test_cvss_analysis.py   # CVSS analysis tests
├── test_cwe_analysis.py    # CWE analysis tests
├── test_yearly_analysis.py # Yearly analysis tests
└── conftest.py             # Shared fixtures
```

Run with: `pytest tests/ -v`

## Validation

The `--validate` flag checks data consistency:

- CNA total ≈ cve_all total (within 1000)
- Year totals sum correctly
- No duplicate CVE IDs

## Performance Considerations

- NVD download: ~30 minutes (full), ~5 minutes (cached)
- V5 repository: ~10 minutes (full clone), ~1 minute (update)
- Analysis phase: ~2 minutes
- Build phase: ~10 seconds

Total build time with cache: ~3 minutes
Total build time from scratch: ~45 minutes
