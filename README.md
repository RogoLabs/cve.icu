# CVE.ICU 🛡️

> **Comprehensive CVE Analysis & Visualization Platform**

CVE.ICU is a powerful, automated platform that provides comprehensive analysis and visualization of Common Vulnerabilities and Exposures (CVE) data. Built with Python and deployed via GitHub Actions, it delivers fresh insights into the cybersecurity landscape through interactive web visualizations.


## 🌟 Features

### 📊 Comprehensive CVE Analysis
- **Multi-Year Data Processing** - Analyzes CVE data from 1999 to present
- **CVSS Scoring Analysis** - Both v2, v3, and v4 vulnerability scoring metrics
- **CWE Classification** - Common Weakness Enumeration categorization
- **CPE Analysis** - Common Platform Enumeration vendor and product insights
- **CNA Tracking** - CVE Numbering Authority analysis and statistics

### 🎯 Scoring Intelligence Hub (NEW)
- **CVSS Analysis** - Severity-based scoring across all CVE versions
- **EPSS Integration** - Exploit Prediction Scoring System (probability of exploitation)
- **KEV Dashboard** - CISA Known Exploited Vulnerabilities catalog
- **Risk Matrix** - Interactive CVSS × EPSS visualization for risk prioritization

### 📈 Advanced Visualizations
- **Yearly Trends** - CVE publication patterns over time
- **Calendar Heatmaps** - Daily and monthly vulnerability disclosure patterns
- **Severity Distributions** - CVSS score breakdowns and trends
- **Vendor Analysis** - Top affected vendors and products
- **Growth Metrics** - Year-over-year vulnerability growth analysis

### 🚀 Automated Infrastructure
- **GitHub Actions CI/CD** - Automated builds every 6 hours
- **Fresh Data** - Always up-to-date with latest NVD releases
- **GitHub Pages Deployment** - Automatic web deployment
- **Quiet Mode** - Clean, professional build logs optimized for CI/CD

## 🛠️ Technical Architecture

### Core Components
- **`build.py`** - Main build orchestrator with quiet mode support
- **Data Analysis Modules** - Specialized analyzers for different CVE aspects
- **Web Generation** - Static site generation with interactive visualizations
- **Caching System** - Efficient data processing and storage

### Data Sources
- **NVD (National Vulnerability Database)** - Primary CVE data source
- **CVE List V5** - Modern CVE format support
- **Official CNA Registry** - CVE Numbering Authority information
- **FIRST.org EPSS** - Exploit Prediction Scoring System data (daily updates)
- **CISA KEV** - Known Exploited Vulnerabilities catalog

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- pip package manager
- Git

### Installation
```bash
# Clone the repository
git clone https://github.com/jgamblin/cve.icu.git
cd cve.icu

# Install dependencies
pip install -r requirements.txt

# Run the build (verbose mode)
python build.py

# Run the build (quiet mode - recommended for CI/CD)
python build.py --quiet
```

### Environment Variables
```bash
# Enable quiet mode via environment variable
export CVE_BUILD_QUIET=1
python build.py
```

## 📋 Build Modes

### Standard Mode
```bash
python build.py
```
- Full verbose output with detailed progress information
- Ideal for development and debugging
- Shows all processing steps and statistics

### Quiet Mode 🔇
```bash
python build.py --quiet
```
- Clean, minimal output optimized for CI/CD environments
- Suppresses verbose progress messages
- Shows only essential information (errors, completion status)
- **80%+ reduction** in log verbosity
- Perfect for GitHub Actions and automated builds

## 🏗️ Project Structure

```
cve.icu/
├── build.py                 # Main build orchestrator
├── data/                    # Data processing modules
│   ├── calendar_analysis.py # Calendar heatmap generation
│   ├── cna_analysis.py      # CNA statistics and tracking
│   ├── cpe_analysis.py      # CPE vendor/product analysis
│   ├── cvss_analysis.py     # CVSS scoring analysis
│   ├── cve_years.py         # Multi-year CVE processing
│   ├── cve_v5_processor.py  # CVE v5 format support
│   ├── cwe_analysis.py      # CWE classification analysis
│   ├── download_cve_data.py # NVD data fetching (+ EPSS, KEV)
│   ├── scoring_analysis.py  # EPSS/KEV/Risk Matrix analysis
│   ├── yearly_analysis.py   # Year-over-year trends
│   └── cache/               # Data caching directory
├── templates/               # Jinja2 HTML templates
├── web/                     # Generated website files
│   └── data/                # JSON data files for frontend
├── docs/                    # Documentation
│   └── ROADMAP.md           # Strategic development roadmap
├── .github/workflows/       # GitHub Actions CI/CD
└── requirements.txt         # Python dependencies
```

## 🤖 Automated Deployment

CVE.ICU uses GitHub Actions for fully automated builds and deployments:

- **Triggers**: Push to main, every 6 hours, manual dispatch
- **Fresh Data**: Downloads latest CVE data on each run
- **Quiet Builds**: Optimized logging for clean CI/CD output
- **GitHub Pages**: Automatic deployment to production
- **Data Commits**: Automated updates to data files

## 📊 Data Processing Pipeline

1. **Data Acquisition** - Fetch latest CVE data from NVD
2. **Multi-Format Support** - Process both legacy and CVE v5 formats
3. **Comprehensive Analysis** - Run all analysis modules in parallel
4. **Visualization Generation** - Create interactive charts and graphs
5. **Web Assembly** - Build complete static website
6. **Deployment** - Publish to GitHub Pages

## 🎯 Use Cases

### Security Researchers
- Track vulnerability trends and patterns
- Analyze vendor security postures
- Research CWE and CVSS distributions

### Security Teams
- Monitor emerging threats
- Assess organizational risk exposure
- Track vulnerability disclosure timelines

### Developers
- Understand common vulnerability patterns
- Learn from historical security data
- Integrate CVE insights into development processes

## 🔧 Configuration

### Quiet Mode Options
```bash
# Command line flag
python build.py --quiet

# Environment variable
CVE_BUILD_QUIET=1 python build.py

# GitHub Actions (automatic)
# Uses --quiet flag by default for clean logs
```

### Customization
- Modify analysis parameters in individual modules
- Adjust caching strategies in `download_cve_data.py`
- Customize web output in visualization modules

## 📈 Performance

### Build Optimization
- **Intelligent Caching** - Efficient data reuse
- **Parallel Processing** - Multi-threaded analysis where possible
- **Memory Management** - Optimized for large datasets
- **Clean Logging** - Quiet mode reduces output by 80%+

### Data Freshness
- **6-Hour Updates** - Automated refresh cycle
- **NVD Synchronization** - Always current with official data
- **Incremental Processing** - Efficient handling of updates

## 🤝 Contributing

We welcome contributions! Please see our contributing guidelines:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

### Development Setup
```bash
# Clone your fork
git clone https://github.com/yourusername/cve.icu.git

# Install development dependencies
pip install -r requirements.txt

# Run tests
python -m pytest tests/

# Test quiet mode
python build.py --quiet
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **National Vulnerability Database (NVD)** - Primary data source
- **MITRE Corporation** - CVE program and CWE classification
- **CVE Numbering Authorities** - Vulnerability discovery and disclosure
- **Open Source Community** - Tools and libraries that make this possible

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/jgamblin/cve.icu/issues)
- **Discussions**: [GitHub Discussions](https://github.com/jgamblin/cve.icu/discussions)
- **Website**: [https://cve.icu](https://cve.icu)

---

**Built with ❤️ for the cybersecurity community**

*CVE.ICU - Making vulnerability data accessible, understandable, and actionable.*

[![Build and Deploy](https://github.com/jgamblin/cve.icu/actions/workflows/deploy.yml/badge.svg)](https://github.com/jgamblin/cve.icu/actions/workflows/deploy.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
