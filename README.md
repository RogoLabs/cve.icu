# CVE.ICU 🛡️

> **Comprehensive CVE Analysis & Visualization Platform**

CVE.ICU is an automated platform that provides comprehensive analysis and visualization of Common Vulnerabilities and Exposures (CVE) data. Built with Python and deployed via GitHub Actions, it delivers fresh insights into the cybersecurity landscape through interactive web visualizations.

**🌐 Live Site:** [https://cve.icu](https://cve.icu)

[![Build and Deploy](https://github.com/RogoLabs/cve.icu/actions/workflows/deploy.yml/badge.svg)](https://github.com/RogoLabs/cve.icu/actions/workflows/deploy.yml)
[![Tests](https://github.com/RogoLabs/cve.icu/actions/workflows/ci.yml/badge.svg)](https://github.com/RogoLabs/cve.icu/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## ✨ Features

### 📊 Comprehensive CVE Analysis
- **Multi-Year Data** - Analyzes CVE data from 1999 to present (~303,000+ CVEs)
- **CVSS Scoring** - Severity analysis across CVSS v2, v3.0, v3.1, and v4.0
- **CWE Classification** - Common Weakness Enumeration categorization
- **CPE Analysis** - Vendor and product vulnerability insights
- **CNA Tracking** - CVE Numbering Authority statistics and activity

### 🎯 Scoring Intelligence Hub
- **CVSS Analysis** - Severity-based scoring distribution and trends
- **EPSS Integration** - Exploit Prediction Scoring System (probability of exploitation)
- **KEV Dashboard** - CISA Known Exploited Vulnerabilities catalog
- **Risk Matrix** - Interactive CVSS × EPSS visualization for risk prioritization

### �� Interactive Visualizations
- **Yearly Trends** - CVE publication patterns over time
- **Calendar Heatmaps** - Daily and monthly vulnerability disclosure patterns
- **Growth Metrics** - Year-over-year vulnerability growth analysis
- **Vendor Rankings** - Top affected vendors and products

### 🚀 Automated Infrastructure
- **GitHub Actions CI/CD** - Automated builds every 6 hours
- **Fresh Data** - Always up-to-date with latest NVD releases
- **GitHub Pages Deployment** - Automatic web deployment
- **39 Automated Tests** - Comprehensive test coverage

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          Data Sources                                │
├─────────────────────────────────────────────────────────────────────┤
│     NVD API    │   CVE V5 Repo   │   EPSS API   │   CISA KEV        │
└────────┬───────┴────────┬────────┴───────┬──────┴────────┬──────────┘
         │                │                │               │
         ▼                ▼                ▼               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     Download & Cache Layer                           │
│                   (download_cve_data.py)                            │
└─────────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       Analysis Layer                                 │
├─────────────────────────────────────────────────────────────────────┤
│  yearly    │   cna    │   cvss   │   cwe    │   cpe    │  scoring   │
│  analysis  │ analysis │ analysis │ analysis │ analysis │  analysis  │
└─────────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        Build Layer                                   │
│                       (build.py)                                     │
│    Template Rendering  │  JSON Generation  │  Data Validation       │
└─────────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       Output (web/)                                  │
│          HTML Pages  │  JSON Data  │  Static Assets                 │
└─────────────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Git

### Installation

```bash
# Clone the repository
git clone https://github.com/RogoLabs/cve.icu.git
cd cve.icu

# Install dependencies
pip install -r requirements.txt

# Run the build
python build.py
```

### Build Options

```bash
# Standard build (verbose output)
python build.py

# Quiet mode for CI/CD
python build.py --quiet

# Validate data consistency after build
python build.py --validate

# Environment variable for quiet mode
CVE_BUILD_QUIET=1 python build.py
```

### Serve Locally

```bash
cd web
python -m http.server 8000
# Open http://localhost:8000
```

## 📁 Project Structure

```
cve.icu/
├── build.py                 # Main build orchestrator
├── requirements.txt         # Python dependencies
├── data/
│   ├── cache/               # Downloaded data (gitignored)
│   │   ├── nvd.jsonl        # NVD vulnerability data
│   │   ├── cvelistV5/       # CVE V5 Git repository
│   │   └── *.json           # EPSS, KEV, CNA data
│   ├── *_analysis.py        # Analysis modules
│   ├── download_cve_data.py # Data downloader
│   ├── cve_v5_processor.py  # CVE V5 processor
│   └── scripts/             # Utility scripts
├── docs/
│   ├── ARCHITECTURE.md      # System architecture
│   ├── SCHEMAS.md           # JSON output schemas
│   ├── COUNTING.md          # CVE counting methodology
│   └── ROADMAP.md           # Development roadmap
├── templates/               # Jinja2 HTML templates
├── tests/                   # pytest test suite
└── web/                     # Generated output
    ├── *.html               # HTML pages
    ├── data/                # JSON data files
    └── static/              # CSS, JS, images
```

## 📊 Data Sources

| Source | Description | Update Frequency |
|--------|-------------|------------------|
| [NVD](https://nvd.nist.gov/) | National Vulnerability Database | Daily |
| [CVE List V5](https://github.com/CVEProject/cvelistV5) | Official CVE records | Real-time |
| [EPSS](https://www.first.org/epss/) | Exploit Prediction Scoring | Daily |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known Exploited Vulnerabilities | As needed |

## 🧪 Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=data --cov-report=html

# Validate data consistency
python build.py --validate
```

## 📈 Output Files

### Analysis JSON Files
| File | Description |
|------|-------------|
| `cve_YYYY.json` | Per-year CVE data |
| `cve_all.json` | Aggregated CVE summary |
| `yearly_summary.json` | Year-over-year statistics |
| `cna_analysis.json` | CNA assignment statistics |
| `cvss_analysis.json` | CVSS score distributions |
| `cwe_analysis.json` | CWE classification data |
| `cpe_analysis.json` | Vendor/product analysis |
| `calendar_analysis.json` | Publication timing patterns |
| `growth_analysis.json` | CVE growth trends |
| `scoring_analysis.json` | EPSS and KEV data |

### HTML Pages
| Page | Description |
|------|-------------|
| `index.html` | Dashboard overview |
| `years.html` | Year-by-year analysis |
| `cna.html` | CNA statistics |
| `cvss.html` | CVSS scoring analysis |
| `cwe.html` | CWE classification |
| `cpe.html` | Vendor/product analysis |
| `calendar.html` | Publication calendar |
| `growth.html` | Growth trends |
| `scoring.html` | EPSS/KEV/Risk Matrix |

## 🔄 CI/CD

The project uses GitHub Actions for automation:

- **Scheduled Builds**: Every 6 hours (0:00, 6:00, 12:00, 18:00 UTC)
- **On Push**: Builds triggered on commits to main branch
- **Deployment**: Automatic deployment to GitHub Pages

## 📖 Documentation

- [Architecture Guide](docs/ARCHITECTURE.md) - System design and data flow
- [JSON Schemas](docs/SCHEMAS.md) - Output file format specifications
- [Development Roadmap](docs/ROADMAP.md) - Project history and future plans
- [Counting Methodology](docs/COUNTING.md) - How CVEs are counted

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Run tests (`pytest tests/ -v`)
4. Commit changes (`git commit -m 'Add amazing feature'`)
5. Push to branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [NIST NVD](https://nvd.nist.gov/) for vulnerability data
- [CVE Program](https://www.cve.org/) for CVE identifiers
- [FIRST.org](https://www.first.org/) for EPSS scoring
- [CISA](https://www.cisa.gov/) for KEV catalog
- [Chart.js](https://www.chartjs.org/) for visualizations

---

<p align="center">
  <a href="https://rogolabs.net/"><img src="https://img.shields.io/badge/A_Project_From-RogoLabs-blue?style=for-the-badge" alt="RogoLabs"></a>
</p>

<p align="center">
  Built by <a href="https://github.com/jgamblin">Jerry Gamblin</a> at <a href="https://rogolabs.net/">RogoLabs</a>
</p>
