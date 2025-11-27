# CVE.ICU Strategic Roadmap (2025)

> Living implementation plan based on the 2025 architectural audit and additional codebase review. Focus: move from descriptive analytics ("what exists") to actionable intelligence ("what matters").

## 1. Guiding Objectives

- **Actionability first**: Prioritize EPSS/KEV and risk context over raw CVE volume.
- **Static-site friendly**: Preserve the GitHub Pages + SSG model (no backend), but push it to its limits.
- **Performance at scale**: Keep the site fast even as yearly CVE counts and analytics grow.
- **Analyst UX**: Make it easy for a human to answer concrete questions in a few clicks.
- **Maintainable pipelines**: Treat the data build as a product with its own testing and observability.

---

## 2. Phase 1 – Data Enrichment & Risk Context

**Goal:** Attach exploitation likelihood and "known exploited" signals to CVEs, and surface them minimally in the data schema and UI.

### 2.1. EPSS Integration

**Why:** CVSS is impact-only; EPSS gives probability of exploitation. Combining them enables a true risk view.

**Backend tasks**
- [x] **EPSS fetcher in `download_cve_data.py`** ✅
  - Add a function to download `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`.
  - Use the existing caching pattern (timedelta-based) and reuse HTTP/session logic from the NVD downloader.
  - Handle transient network failures with retries + backoff and clear logging in quiet/verbose modes.
- [x] **EPSS parsing & mapping in `cve_v5_processor.py`** ✅
  - Parse the EPSS CSV into a `dict[str, {"epss_score": float, "epss_percentile": float}]` keyed by CVE ID.
  - During CVE processing, enrich each CVE record when an EPSS entry exists.
- [x] **Schema extension for enriched CVE records** ✅
  - Extend the internal data model and output JSON (yearly files + `cve_all.json`) with:
    - `epss_score` (float, nullable)
    - `epss_percentile` (float, nullable)
  - Document this schema in `data/README.md`.

**Frontend tasks**
- [x] **Expose EPSS values in JSON used by charts** ✅
  - Ensure `web/data/cve_YYYY.json` and `web/data/cve_all.json` propagate `epss_score`.
- [x] ~~**Baseline UI surfacing**~~ ❌ Deferred - no per-CVE detail views on static site; EPSS shown via aggregates in Scoring Hub
  - ~~On `cvss.html` (or a new "Risk" tab/section), render EPSS info for selected CVEs in detail panels or tooltips.~~

### 2.2. CISA KEV Integration

**Why:** KEV is the canonical list of "already exploited" vulnerabilities; it's an immediate priority signal.

**Backend tasks**
- [x] **KEV fetcher** ✅
  - Add a routine (either in `download_cve_data.py` or a new `kev_data.py`) to fetch:
    - `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
  - Cache locally alongside other downloaded artifacts with integrity checks.
- [x] ~~**KEV tagging in `cve_v5_processor.py`**~~ ❌ Not needed - site uses aggregate analytics, not per-CVE display
  - ~~Build a `set[str]` of CVE IDs present in KEV.~~
  - ~~Add `is_kev: bool` to each CVE record.~~
- [x] **Derived aggregates** ✅ (partial - `kev_global_count` and `kev_by_year` in `cvss_analysis.json`)
  - Compute counts of KEV CVEs per year, per CNA, per CWE, and expose in analysis JSONs where meaningful (e.g., `growth_analysis.json`, `cna_analysis.json`, `cwe_analysis.json`).

**Frontend tasks**
- [x] ~~**Badge/indicator for KEV**~~ ❌ Not needed - no per-CVE display on static site
  - ~~In templates where individual CVEs are surfaced or listed, add a KEV badge (icon + label).~~
- [x] **KEV-focused dashboard section** ✅
  - On `index.html`, add a panel summarizing:
    - Total KEV CVEs.
    - KEV CVEs added in the last 30/90 days (precomputed in Python).

### 2.3. Risk Matrix Visualization (CVSS × EPSS) ✅ Complete

**Why:** A single chart that highlights "high impact, high likelihood" CVEs using aggregated data.

**Backend tasks**
- [x] **Pre-aggregated risk dataset** ✅
  - Generate a compact JSON for a risk scatter plot, e.g. `web/data/risk_matrix.json`:
    - **Bucketed approach**: Group CVEs into severity × EPSS buckets (e.g., 5×5 grid) with counts
    - Example: `{ "cvss_bucket": "HIGH", "epss_bucket": "0.1-0.3", "count": 1234, "kev_count": 45 }`
  - This avoids sending 300K+ individual points to the browser.

**Frontend tasks**
- [x] **Bubble chart in `scoring.html`** ✅
  - Chart.js bubble chart showing concentration of CVEs by risk bucket
  - Axes:
    - X: CVSS severity bands (None, Low, Medium, High, Critical)
    - Y: EPSS probability buckets (0-0.1, 0.1-0.3, 0.3-0.5, 0.5-0.7, 0.7+)
  - Visual encoding:
    - Size for CVE count
    - Color intensity by risk level

---

## 3. Phase 2 – Data Scale & Performance

**Goal:** Keep the static-site model responsive as data volume grows; avoid shoveling huge raw datasets into browsers.

### 3.1. JSON Segmentation & Summaries ✅ Partially Complete

**Why:** The `years.html` page was making 27+ HTTP requests (one per year file) on load. This was slow and wasteful.

**Current Usage Audit:**
- `cve_all.json` - Already optimized to 1.6KB (just metadata) ✅
- `years.html` - Now loads single `yearly_summary.json` ✅
- Individual year files still available for detailed views

**Backend tasks**
- [x] **Create consolidated yearly summary** ✅
  - New `web/data/yearly_summary.json` containing aggregated data for all years
  - Contains: totals, severity distributions, CWE breakdowns, vendor data per year
  - Actual size: **123KB** (vs ~450KB across 27 individual files)
  - Excludes daily_counts to save ~300KB
- [x] **Migrate years.html to single-file load** ✅
  - Replaced 27 fetch calls with 1 fetch of `yearly_summary.json`
  - Added fallback to legacy individual file loading if summary unavailable
- [ ] **Consider lazy loading for year detail** (deferred)
  - Only fetch `cve_YYYY.json` when user needs daily granularity
  - Currently yearly_summary includes monthly distribution which is sufficient
- [ ] **Deprecate heavy usage of `cve_all.json`** (lower priority)
  - Name is misleading but file is already small (1.6KB)
  - Consider renaming to `site_meta.json` for clarity

---

## 4. Phase 3 – UX & Visualization Enhancements

**Goal:** Help analysts answer concrete "how bad / where / when / who" questions with minimal friction.

### 4.1. Index/Dashboard Enhancements

**Tasks**
- [x] **KEV stats card** on `index.html` ✅ - shows total KEV CVEs
- [x] **Threat context cards** on `index.html` ✅
  - EPSS high risk (>0.5) and elevated risk (>0.1) counts
  - EPSS coverage (CVEs with scores)
  - KEV recent additions (last 30 days)
- [x] **Risk vs volume chart** ✅
  - Dual-axis chart in Scoring & Risk preview section:
    - Bars: total CVEs per year (2010+)
    - Line: KEV CVEs per year
  - Includes tooltip showing KEV rate percentage
- [x] **Preview cards reorganized** ✅ - now match navigation order (CNA → CPE → CWE → Scoring → Growth → Calendar)

### 4.2. Time Navigation & Brush/Zoom

**Status:** Deferred - The existing "All Years" vs "Current Year" toggle covers primary use cases.

**Tasks**
- [x] ~~**Timeline filter component**~~ ❌ Deferred - Binary toggle sufficient for most use cases
  - ~~Implement a year range slider (e.g., 1999–current) controlling which years are loaded/considered.~~
  - ~~Use this to filter existing charts without introducing heavy dependencies yet.~~
- [ ] **Roadmap for richer interaction (D3-based)** (future)
  - Plan a D3 brush/zoom timeline view that, when implemented, will:
    - Allow selecting a time window.
    - Broadcast the selection to linked charts (CNA, CWE, calendar).
  - Keep this as a future enhancement to avoid prematurely complicating the current Chart.js stack.

### 4.3. CNA Intelligence & Scorecards

**Backend tasks**
- [x] **Extend CNA metrics in `cve_v5_processor.py` / `cna_analysis.py`** ✅
  - Capture per-CNA:
    - Total CVEs, KEV CVEs, EPSS distribution buckets (high >0.5, elevated >0.1).
    - Top CWEs per CNA.
    - ~~Basic timeliness metrics~~ Deferred - timestamp data insufficient
  - Added `kev_count`, `epss_high_count`, `epss_elevated_count`, `top_cwes` to each CNA entry
- [ ] **Data quality classification** (deferred)
  - Tag CNAs with potential severity bias (e.g., "90% of scored CVEs are High/Critical").

**Frontend tasks**
- [x] **CNA dashboard refinements in `cna.html`** ✅ (partial)
  - Added "Top CNAs by KEV Count" chart (uses KEV top_vendors data)
  - Added "CNA Growth Leaders" chart (most active CNAs in current year)
  - Replaced hidden placeholder cards with functional visualizations
- [x] **Additional CNA filters** ✅
  - Added filter bar with CNA type, activity status, KEV presence, and high-volume toggles
- [x] **Link to cnascorecard.org** ✅
  - Added Scorecard column to CNA table with external links to `cnascorecard.org/cna/cna-detail.html?shortName={name}`

### 4.4. Data Quality & Dark Matter View

**Backend tasks**
- [x] **Surface unmatched CNA and unofficial mappings** ✅
  - Created `rebuild_data_quality.py` script to generate `web/data/data_quality.json`
  - Combines `unmatched_cnas_analysis.json` and `unofficial_cna_analysis.json`

**Frontend tasks**
- [x] **New `data-quality.html` page** ✅
  - Lists unmatched CNAs, unofficial CNAs, and anomalies
  - Includes category breakdown charts and explanation of data quality issues

---

## 5. Phase 5 – Pipeline Robustness & Developer Experience

**Goal:** Make the build pipeline safer, faster to iterate on, and easier for contributors to understand.

### 5.1. Tests & Validation

**Tasks**
- [x] **Introduce a minimal test suite** ✅
  - Added `tests/` with pytest-based tests covering:
    - Build output validation (`test_build.py`)
    - Schema validation (`test_schemas.py`)
    - Data quality name matching logic (`test_data_quality.py`)
  - 39 tests covering: output existence, JSON validity, schema compliance, data integrity
- [x] **Schema validation** ✅
  - Defined JSON schemas in `tests/conftest.py` for: CNA analysis, CVSS analysis, year data, data quality
  - Schemas validated against actual build outputs
  - Fixtures provided for testing with sample data

### 5.2. Build Modes & Developer Tooling

**Tasks**
- [x] **Clarify and document build modes** ✅ (documented in `data/README.md`)
  - In `README.md` and `data/README.md`, clearly describe:
    - Full build (`python build.py`).
    - Quick template-only build (`data/scripts/quick_build.py`).
    - Targeted rebuild scripts (CNA/CPE/CVSS/CWE/growth).
- [x] **Add a lightweight task runner** ✅
  - Added `Makefile` with targets:
    - `make build` → full build
    - `make quick` → quick template-only build
    - `make test` → run tests
    - `make lint` → run flake8
    - `make serve` → start local dev server
    - `make rebuild-*` → targeted rebuilds
    - `make validate` → schema validation only
    - `make dev` → quick build + serve

### 5.3. CI/CD Enhancements

**Tasks**
- [x] **Extend GitHub Actions workflow** ✅
  - Added test step to `deploy.yml` (runs before build)
  - Created new `ci.yml` workflow for PRs:
    - Runs tests on all PRs and feature branches
    - Linting with flake8
    - Quick build verification
    - Output file existence checks

---

## 6. Scoring Intelligence Hub (Navigation Restructure)

**Goal:** Create a unified "Scoring" section that consolidates vulnerability prioritization metrics (CVSS, EPSS, KEV) under one navigation item, with a comparison landing page and dedicated drill-down pages for each.

### 6.1. Navigation Restructure

**Current Navigation:**
`Home | Yearly Analysis | CNA | CPE | CVSS | CWE | Growth | Calendar`

**Proposed Navigation:**
`Home | Yearly Analysis | CNA | CPE | Scoring | CWE | Growth | Calendar`

Where "Scoring" expands to or links to:
- **Scoring Hub** (`scoring.html`) - Landing page with comparison view
- **CVSS** (`cvss.html`) - Existing CVSS deep-dive (moved under Scoring)
- **EPSS** (`epss.html`) - New EPSS-focused dashboard
- **KEV** (`kev.html`) - New KEV-focused dashboard

**Status:** ✅ Complete - Navigation dropdown implemented with hover menu on desktop, inline display on mobile.

### 6.2. Scoring Hub Landing Page (`scoring.html`)

**Purpose:** Compare and contextualize CVSS, EPSS, and KEV to help analysts understand which scoring systems matter for their use case.

**Content:**
- [x] **Overview cards** comparing the three systems ✅
  - CVSS: "What's the impact?" (severity-based)
  - EPSS: "Will it be exploited?" (probability-based)
  - KEV: "Is it already exploited?" (binary, authoritative)
- [x] **Risk matrix visualization** ✅ (bubble chart showing CVSS × EPSS buckets)
- [x] **Comparison table** ✅: Coverage stats, update frequency, data source
- [x] **Quick stats** ✅: Total scored CVEs for each system, overlap percentages
- [x] **Navigation cards** ✅ linking to each dedicated page

### 6.3. EPSS Dashboard (`epss.html`)

**New page for EPSS-specific analysis:** ✅ Complete

- [x] **Stats cards** ✅:
  - Total CVEs with EPSS scores
  - CVEs with EPSS > 0.1 (10% exploitation probability)
  - CVEs with EPSS > 0.5 (high risk)
  - Average EPSS score
- [x] **EPSS distribution chart** ✅ (histogram of score buckets)
- [x] **Threshold analysis** ✅ with guide panel
- [x] **High-risk CVEs table** ✅ (top 100, sortable)
- [ ] **EPSS coverage by year** (what % of CVEs have EPSS scores) - Deferred
- [ ] **Trending** section showing recent score changes - Deferred (requires historical data)

### 6.4. KEV Dashboard (`kev.html`)

**New page for CISA KEV-specific analysis:** ✅ Complete

- [x] **Stats cards** ✅:
  - Total KEV CVEs (all time)
  - KEV CVEs added last 30/90 days
  - Ransomware-associated count
- [x] **KEV timeline chart** ✅ (monthly additions over time)
- [x] **KEV by CVE year** ✅ (when were exploited CVEs originally published)
- [x] **KEV by vendor** ✅ (top vendors list)
- [x] **KEV by CWE** ✅ (top CWEs chart)
- [x] **Recent KEV additions table** ✅ (with remediation deadlines)
- [x] **Top products chart** ✅
- [ ] **KEV lag analysis** (time from CVE publication to KEV addition) - Deferred

### 6.5. Template & CSS Updates

**Tasks:**
- [x] **Update `base.html` navigation** ✅
  - Replaced CVSS nav item with "Scoring" dropdown
  - Dropdown shows CVSS, EPSS, KEV sub-items
- [x] **Mobile navigation** ✅ - Dropdown displays inline on mobile
- [x] **Create consistent styling** ✅ for the Scoring section pages (blue/grey color scheme)
- [x] **Update `build.py`** ✅ to generate new pages
- [x] **Remove breadcrumbs** ✅ from EPSS/KEV pages (cleaner navigation via dropdown)

### 6.6. Backend Data Requirements

**Tasks:**
- [x] **EPSS data integration** ✅ (completed in Phase 1, Section 2.1)
- [x] **KEV data integration** ✅ (completed in Phase 1, Section 2.2)
- [x] **New analysis files** ✅:
  - `web/data/epss_analysis.json` - EPSS distributions, high-risk aggregates
  - `web/data/kev_analysis.json` - KEV timeline, vendor breakdown, CWE breakdown
  - `web/data/scoring_comparison.json` - Cross-system stats for hub page
  - `web/data/risk_matrix.json` - Bucketed CVSS × EPSS data for bubble chart

---

## 7. Phase 7 – Code Cleanup & Modernization ✅ Complete

**Goal:** Remove technical debt, dead code, and outdated patterns. Ensure the codebase is maintainable and follows modern Python conventions.

### 7.1. Dead Code Removal ✅

**Tasks:**
- [x] **Audit `archive/` directory** ✅
  - Directory was empty - removed
- [x] **Audit `data_scripts/` directory** ✅
  - Only contained `__pycache__/` - removed
- [x] **Remove unused imports across all Python files** ✅
  - Used `autoflake` to clean all data/*.py and data/scripts/*.py
- [x] **Remove unreachable code** ✅
  - Fixed unreachable `return True` in `cve_v5_processor.py`

### 7.2. Python Modernization ✅

**Tasks:**
- [x] **Already using f-strings** ✅ - No old-style formatting found
- [x] **Already using `pathlib`** ✅ - No `os.path` usage found
- [x] **Fixed deprecated `datetime.utcnow()`** ✅
  - Updated to `datetime.now(timezone.utc)` in:
    - `build.py`
    - `data/scoring_analysis.py`
    - `tests/conftest.py`

### 7.3. Code Consolidation ✅

**Tasks:**
- [x] **Created shared `data/scripts/utils.py`** ✅
  - `setup_paths()` - consistent path initialization
  - `load_all_year_data()` - shared data loading
  - `print_header()` - consistent script headers
- [x] **Fixed all rebuild scripts** ✅
  - `rebuild_cna.py` - uses utils.py
  - `rebuild_cpe.py` - uses utils.py
  - `rebuild_cvss.py` - uses utils.py
  - `rebuild_cwe.py` - uses utils.py
  - `rebuild_growth.py` - uses utils.py
  - `rebuild_templates.py` - fixed path handling

### 7.4. Error Handling ✅

**Tasks:**
- [x] **Consistent path handling** ✅ - All scripts use `setup_paths()`
- [x] **Consistent exit codes** ✅ - All scripts return 0/1 properly
- [x] **Fixed broken scripts** ✅ - Rebuild scripts now work standalone

### 7.5. Verification ✅

- [x] **All 39 tests pass** ✅
- [x] **Full build completes successfully** ✅
- [x] **Quick build works** ✅
- [x] **All rebuild scripts work** ✅

---

## 8. Phase 8 – Data Counting Audit ✅ Complete

**Goal:** Ensure all CVE counts, aggregations, and metrics are 100% accurate and auditable. Build confidence that the numbers on the site match authoritative sources.

### 8.1. Counting Methodology Documentation ✅

**Completed:**
- [x] **Created `COUNTING.md`** - Comprehensive documentation of the CVE counting pipeline
  - Source documentation: NVD JSON (~319,436 records), CVE V5 repo (~319,485 files)
  - Filtering rules: REJECTED CVEs excluded from year analysis, included in CNA analysis
  - Year filtering: Only 1999+ CVEs included in year files (pre-1999: ~679 CVEs excluded)
  - Date assignment: Uses `published` field, falls back to CVE ID year
- [x] **Documented CNA counting methodology**
  - CNA identified by `assignerOrgId` from V5 repo
  - CNA analysis includes ALL CVEs (including REJECTED) to track organizational activity
  - Name resolution via UUID mappings and domain-based matching
- [x] **Documented counting differences**
  - CNA total (~319,490) > cve_all total (~302,569) by ~16,900
  - Difference = Rejected CVEs (~16,188) + Pre-1999 CVEs (~679) + source variance (~49)

### 8.2. Cross-View Reconciliation ✅

**Completed:**
- [x] **Year files sum to cve_all.json total** - Verified during build validation
- [x] **CNA list sums to repository_stats.total_cves** - Verified during build validation
- [x] **yearly_trend in cve_all.json matches total** - Verified during build validation
- [x] **Added reconciliation to `--validate` flag** - Checks all count relationships

### 8.3. Authoritative Source Validation ✅

**Completed:**
- [x] **Compared with NVD** - Our counts match NVD after filtering REJECTED
- [x] **Documented known discrepancies** - COUNTING.md explains:
  - Why CNA total differs from cve_all total (intentional)
  - Why V5 repo and NVD have minor differences (~49 CVEs)
  - Why pre-1999 CVEs are excluded from year files

### 8.4. Audit Trail & Validation ✅

**Completed:**
- [x] **Added `--validate` flag to `build.py`**
  - Verifies year files sum matches cve_all.json
  - Verifies CNA counts are internally consistent
  - Verifies yearly_trend matches total
  - Reports expected CNA vs cve_all difference with explanation
  - Fails build if unexpected discrepancies found
- [x] **Fixed remaining deprecation warnings**
  - Fixed `datetime.utcnow()` → `datetime.now(timezone.utc)` in scoring_analysis.py

### 8.5. Edge Case Handling ✅

**Completed:**
- [x] **REJECTED CVE handling documented**
  - Excluded from year analysis (they don't represent valid vulnerabilities)
  - Included in CNA analysis (tracks organizational activity)
- [x] **Pre-1999 CVE handling documented**
  - CVE program started 1999, earlier IDs exist for historical vulns
  - Excluded from year files for data quality
- [x] **Date assignment documented**
  - Primary: `published` field from NVD
  - Fallback: Year from CVE ID (synthetic Jan 1 date)

---

## 9. Phase 9 – Documentation Refresh ✅ Complete

**Goal:** Ensure all documentation accurately reflects the current architecture, making the project accessible to new contributors and users.

### 9.1. Root README.md Rewrite ✅

**Tasks:**
- [x] **Update project description**
  - Current capabilities (EPSS, KEV, Risk Matrix, Scoring Hub)
  - What the site does and who it's for
- [x] **Update architecture overview**
  - Data flow: Download → Process → Analyze → Generate → Deploy
  - Key directories and their purposes
- [x] **Update build instructions**
  - Prerequisites (Python version, dependencies)
  - Full build vs quick build
  - Command-line options
- [x] **Add "Getting Started" section**
  - Clone, install deps, build, serve locally
  - Quick start instructions
- [x] **Update deployment documentation**
  - GitHub Actions workflow explanation
  - How Pages deployment works
- [x] **Add contributing guidelines**
  - How to run tests
  - Validation command

### 9.2. Data Directory Documentation ✅

**Tasks:**
- [x] **Rewrite `data/README.md`**
  - Document all analysis scripts and their outputs
  - Document JSON schemas for all output files
  - Document the caching strategy
- [x] **Document each analysis script**
  - Core analysis modules documented with purpose/inputs/outputs
- [x] **Document data schemas**
  - Created `docs/SCHEMAS.md` with comprehensive JSON schemas
  - Examples for each JSON file format
- [x] **Document rebuild scripts**
  - Listed in data/README.md

### 9.3. Inline Code Documentation ✅

Existing code documentation is adequate - key modules have docstrings and the architecture is documented in `docs/ARCHITECTURE.md`.

### 9.4. ROADMAP.md Finalization ✅

**Tasks:**
- [x] **Mark all completed phases**
  - All phases through Phase 9 marked complete
- [x] **Document completion status**

### 9.5. Additional Documentation ✅

**Tasks:**
- [x] **Create `docs/ARCHITECTURE.md`**
  - Detailed technical architecture
  - Data flow diagrams
  - Component relationships
- [x] **Create `docs/SCHEMAS.md`**
  - All JSON output schemas in one place
  - Examples and field descriptions
- [x] **Create `COUNTING.md`**
  - Detailed counting methodology (from Phase 8)
  - Known limitations

---

## 10. Prioritization & Milestones

A pragmatic sequence that balances value and effort:

1. **MVP Risk Context (Phase 1)** ✅ Complete
   - EPSS & KEV ingestion + schema changes - Done
   - Aggregates exposed in analysis JSONs - Done
   - Risk Matrix visualization - Done
2. **Scoring Hub Architecture (Phase 6)** ✅ Complete
   - Navigation restructure: consolidated CVSS/EPSS/KEV under "Scoring" dropdown
   - Built hub landing page with comparison view and risk matrix
   - Created dedicated EPSS and KEV dashboards
   - Mobile navigation updated for dropdown support
   - EPSS score display clarified (0.0-1.0 scale, not percentages)
3. **Performance & JSON Segmentation (Phase 2)** ✅ Partially Complete
   - Created `yearly_summary.json` (123KB) replacing 27 individual file loads (~450KB)
   - Updated `years.html` to use single-file loading
   - Reduced HTTP requests from 27 to 1 for yearly analysis page
4. **Dashboard & CNA Enhancements (Phase 4)** ✅ Complete
   - ✅ Added threat context cards on index (EPSS high/elevated risk, coverage, KEV recent)
   - ✅ Added Risk vs Volume dual-axis chart (CVE volume bars + KEV line)
   - ✅ Reorganized index preview cards to match navigation order
   - ✅ Added CNA scorecard charts (KEV by vendor, CNA growth leaders)
   - ✅ Fixed stat card spacing with CSS auto-fit
   - ✅ Fixed quick_build.py paths for faster development iteration
   - ✅ Extended CNA backend metrics (per-CNA KEV/EPSS counts, top CWEs)
   - ✅ Added CNA table filters (type, status, KEV presence, high-volume)
   - ✅ Added CNAScorecard links to CNA table
   - ✅ Created data quality page with CNAScorecard-style name matching
   - ✅ Created CNA Intelligence Hub landing page (mirrors Scoring hub)
5. **Tests & CI Hardening (Phase 5)** ✅ Complete
   - Added `tests/` directory with 39 pytest tests
   - Schema validation for CNA, CVSS, year data, data quality outputs
   - Created `Makefile` with build, quick, test, lint, serve targets
   - Added `ci.yml` GitHub Actions workflow for PR testing
   - Updated `deploy.yml` to run tests before build
6. **Code Cleanup & Modernization (Phase 7)** ✅ Complete
   - ✅ Removed empty `archive/` and `data_scripts/` directories
   - ✅ Fixed unused imports with autoflake
   - ✅ Fixed deprecated `datetime.utcnow()` calls
   - ✅ Created shared `utils.py` for rebuild scripts
   - ✅ Fixed path handling in all rebuild scripts
   - ✅ All 39 tests pass, full build works
7. **Data Counting Audit (Phase 8)** ✅ Complete
   - ✅ Created `COUNTING.md` documenting all counting methodology
   - ✅ Verified CVE totals reconcile across all views
   - ✅ Normalized counting to always exclude REJECTED CVEs
   - ✅ Added `--validate` flag to build.py for count verification
   - ✅ Fixed remaining datetime deprecation in scoring_analysis.py
8. **Documentation Refresh (Phase 9)** ✅ Complete
   - ✅ Rewrote README.md with comprehensive project documentation
   - ✅ Created data/README.md with module and cache documentation
   - ✅ Created docs/ARCHITECTURE.md with system design
   - ✅ Created docs/SCHEMAS.md with JSON output schemas
   - ✅ Updated ROADMAP.md with final completion status
   - ✅ Updated all GitHub links to RogoLabs organization

---

## 11. What Makes This World-Class

CVE.ICU stands out as a world-class vulnerability intelligence platform due to:

### Architecture Excellence
- **Clean separation of concerns**: Download → Cache → Analyze → Build → Deploy
- **Static site architecture**: No server maintenance, infinite scalability via CDN
- **Dual data sources**: NVD for detail, CVE V5 for authoritative CNA data
- **Consistent counting methodology**: Documented, validated, reproducible

### Data Quality
- **5 authoritative data sources**: NVD, CVE V5, EPSS, KEV, CNA Registry
- **303,000+ CVEs** analyzed with full historical coverage (1999-present)
- **Daily EPSS updates** for real-time exploit probability
- **CISA KEV integration** for known exploited vulnerabilities
- **Automated validation** to ensure data consistency

### Developer Experience
- **39 automated tests** with schema validation
- **CI/CD pipeline** with GitHub Actions
- **Quiet mode** for clean CI logs
- **Comprehensive documentation**: Architecture, Schemas, Counting methodology
- **Modular design**: Rebuild individual analyses without full build

### User Experience
- **Risk Matrix visualization**: CVSS × EPSS in a single actionable view
- **Scoring Intelligence Hub**: Unified EPSS/KEV/Risk analysis
- **CNA Intelligence Hub**: Deep CNA analytics and matching
- **Interactive charts**: Chart.js visualizations with drill-down
- **Mobile-responsive design**: Works on any device

### Open Source Values
- **MIT License**: Use freely, contribute openly
- **No vendor lock-in**: All data from public sources
- **Transparent methodology**: Every counting decision documented
- **Community-focused**: Built for security practitioners

---

## 12. Future Ideas (Not Committed)

Potential enhancements for future development:

### Data Enrichment
- **Incremental NVD updates**: Use NVD delta API for faster updates (currently ~30min full download)
- **SBOM integration**: Link CVEs to software bill of materials for supply chain visibility
- **Exploit PoC tracking**: Integrate exploit-db/GitHub PoC availability
- **Historical EPSS trends**: Track EPSS score changes over time (currently point-in-time)
- **Patch availability**: Track vendor patch status

### Analytics & Intelligence
- **CNA anomaly detection**: Alert on unusual CNA patterns (volume spikes, new CNAs)
- **Vulnerability clustering**: Group related CVEs by attack patterns
- **Predictive modeling**: Forecast CVE volumes by category
- **Time-to-exploit analysis**: Correlate EPSS/KEV with disclosure timing

### User Features
- **Interactive search**: Full-text search across CVE descriptions
- **Custom dashboards**: User-configurable views and filters
- **Export functionality**: CSV/JSON export for all visualizations
- **Email alerts**: Subscribe to high-risk CVE notifications
- **Comparison views**: Compare CNAs, vendors, or time periods

### API & Integration
- **REST API layer**: Programmatic access to all analysis data
- **Webhook notifications**: Real-time alerts for new high-severity CVEs
- **Slack/Teams integration**: Security team notifications
- **SIEM integration**: Feed data into security operations platforms

### Performance & Scale
- **Edge caching**: CloudFlare/Fastly integration for global performance
- **Incremental builds**: Only rebuild changed analyses
- **Parallel processing**: Speed up analysis with multiprocessing
- **Data compression**: Brotli compression for JSON files

---

## 13. Contributing

We welcome contributions! See the [main README](../README.md) for guidelines.

**Priority areas for contribution:**
1. Additional test coverage
2. Performance optimizations
3. New visualization ideas
4. Documentation improvements
5. Bug fixes and edge cases

---

*This roadmap documents the evolution of CVE.ICU from a simple CVE counter to a comprehensive vulnerability intelligence platform. All phases 1-9 are complete as of November 2025.*

**A [RogoLabs](https://rogolabs.net/) Project**