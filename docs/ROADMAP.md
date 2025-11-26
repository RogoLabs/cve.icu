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

**Tasks**
- [ ] **Timeline filter component** (initially simple):
  - Implement a year range slider (e.g., 1999–current) controlling which years are loaded/considered.
  - Use this to filter existing charts without introducing heavy dependencies yet.
- [ ] **Roadmap for richer interaction (D3-based)**
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
- [ ] **Additional CNA filters** (deferred)
  - CNA type (vendor vs researcher), KEV presence, EPSS bucket emphasis.
- [ ] **Link to cnascorecard.org**
  - Where relevant, add outbound links based on CNA identifiers.

### 4.4. Data Quality & Dark Matter View

**Backend tasks**
- [ ] **Surface unmatched CNA and unofficial mappings**
  - Use `unmatched_cnas_analysis.json` and related outputs to generate a dedicated `web/data/data_quality.json`.

**Frontend tasks**
- [ ] **New `data-quality.html` page**
  - List unmatched CNAs, unofficial CNAs, and any anomalies.
  - Include explanations about why this matters (governance, attribution, ecosystem gaps).

---

## 5. Phase 4 – Pipeline Robustness & Developer Experience

**Goal:** Make the build pipeline safer, faster to iterate on, and easier for contributors to understand.

### 5.1. Tests & Validation

**Tasks**
- [ ] **Introduce a minimal test suite**
  - Add `tests/` with pytest-based tests covering:
    - Core data modules (`download_cve_data`, `cve_v5_processor`, `cvss_analysis`, `cna_analysis`, `cwe_analysis`).
    - At least one end-to-end smoke test: run a tiny synthetic dataset through the pipeline and assert JSON structures.
- [ ] **Schema validation**
  - Define JSON schemas (even if informal/partial) for key outputs: year files, `cna_analysis.json`, `cvss_analysis.json`, `cwe_analysis.json`.
  - Optionally add a small validation step in the build script when `--validate` is passed.

### 5.2. Build Modes & Developer Tooling

**Tasks**
- [x] **Clarify and document build modes** ✅ (documented in `data/README.md`)
  - In `README.md` and `data/README.md`, clearly describe:
    - Full build (`python build.py`).
    - Quick template-only build (`data/scripts/quick_build.py`).
    - Targeted rebuild scripts (CNA/CPE/CVSS/CWE/growth).
- [ ] **Add a lightweight `make` or task runner**
  - Optionally provide a simple `Makefile` or Python CLI wrapper for:
    - `make build` → full build.
    - `make quick` → quick template-only build.
    - `make test` → run tests.

### 5.3. CI/CD Enhancements

**Tasks**
- [ ] **Extend GitHub Actions workflow**
  - Add steps to:
    - Run tests (including synthetic data builds) on PRs.
    - Fail fast on schema or build regressions.
  - Optionally add a scheduled "sanity build" job independent of deploys.

---

## 6. Phase 5 – Exploratory & Advanced Features (Optional)

These are stretch goals to explore after the core risk context and performance work stabilizes.

### 6.1. Client-Side Query Workbench

- Build an experimental "Query" page backed by SQL.js or DuckDB-WASM.
- Allow structured queries like:
  - "All CWE-79 vulnerabilities with EPSS > 0.5 in the last 3 years."
  - "Top vendors by KEV CVEs this year."
- Enforce tight bounds on data size (e.g., limit to last N years or pre-aggregated tables) to keep downloads reasonable.

### 6.2. Relationship & Network Visualizations

- Prototype a force-directed graph of Vendors × CWEs or CNAs × CWEs.
- Use a dedicated page with lazy loading so the main navigation stays lightweight.
- Start from aggregated counts already produced by `cna_analysis.py` / `cwe_analysis.py`.

### 6.3. Timeline Deep Dive

- Upgrade the simple year-slider to a D3-based brushed timeline that coordinates:
  - Calendar heatmap.
  - CNA/CWE distributions.
  - Risk matrix focus (filtering points by time window).

---

## 7. Scoring Intelligence Hub (Navigation Restructure)

**Goal:** Create a unified "Scoring" section that consolidates vulnerability prioritization metrics (CVSS, EPSS, KEV) under one navigation item, with a comparison landing page and dedicated drill-down pages for each.

### 7.1. Navigation Restructure

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

### 7.2. Scoring Hub Landing Page (`scoring.html`)

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

### 7.3. EPSS Dashboard (`epss.html`)

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

### 7.4. KEV Dashboard (`kev.html`)

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

### 7.5. Template & CSS Updates

**Tasks:**
- [x] **Update `base.html` navigation** ✅
  - Replaced CVSS nav item with "Scoring" dropdown
  - Dropdown shows CVSS, EPSS, KEV sub-items
- [x] **Mobile navigation** ✅ - Dropdown displays inline on mobile
- [x] **Create consistent styling** ✅ for the Scoring section pages (blue/grey color scheme)
- [x] **Update `build.py`** ✅ to generate new pages
- [x] **Remove breadcrumbs** ✅ from EPSS/KEV pages (cleaner navigation via dropdown)

### 7.6. Backend Data Requirements

**Tasks:**
- [x] **EPSS data integration** ✅ (completed in Phase 1, Section 2.1)
- [x] **KEV data integration** ✅ (completed in Phase 1, Section 2.2)
- [x] **New analysis files** ✅:
  - `web/data/epss_analysis.json` - EPSS distributions, high-risk aggregates
  - `web/data/kev_analysis.json` - KEV timeline, vendor breakdown, CWE breakdown
  - `web/data/scoring_comparison.json` - Cross-system stats for hub page
  - `web/data/risk_matrix.json` - Bucketed CVSS × EPSS data for bubble chart

---

## 8. Prioritization & Milestones

A pragmatic sequence that balances value and effort:

1. **MVP Risk Context (Phase 1)** ✅ Complete
   - EPSS & KEV ingestion + schema changes - Done
   - Aggregates exposed in analysis JSONs - Done
   - Risk Matrix visualization - Done
2. **Scoring Hub Architecture (Phase 7)** ✅ Complete
   - Navigation restructure: consolidated CVSS/EPSS/KEV under "Scoring" dropdown
   - Built hub landing page with comparison view and risk matrix
   - Created dedicated EPSS and KEV dashboards
   - Mobile navigation updated for dropdown support
   - EPSS score display clarified (0.0-1.0 scale, not percentages)
3. **Performance & JSON Segmentation (Phase 2)** ✅ Partially Complete
   - Created `yearly_summary.json` (123KB) replacing 27 individual file loads (~450KB)
   - Updated `years.html` to use single-file loading
   - Reduced HTTP requests from 27 to 1 for yearly analysis page
4. **Dashboard & CNA Enhancements (Phase 4)** 🔶 Partially Complete
   - ✅ Added threat context cards on index (EPSS high/elevated risk, coverage, KEV recent)
   - ✅ Added Risk vs Volume dual-axis chart (CVE volume bars + KEV line)
   - ✅ Reorganized index preview cards to match navigation order
   - ✅ Added CNA scorecard charts (KEV by vendor, CNA growth leaders)
   - ✅ Fixed stat card spacing with CSS auto-fit
   - ✅ Fixed quick_build.py paths for faster development iteration
   - ⬜ Time navigation (timeline filter, D3 brush/zoom) - Deferred
   - ⬜ Extended CNA backend metrics (per-CNA KEV/EPSS) - Deferred
   - ⬜ Data quality page - Deferred
5. **Tests & CI Hardening (Phase 5)** ⬅️ **NEXT**
   - Introduce tests and validation; wire into GitHub Actions
6. **Exploratory Features (Phase 6)**
   - Query workbench and advanced visualizations, time permitting

This roadmap should remain a living document. As new datasets (e.g., SBOM feeds, exploit PoC tracking) or ecosystem changes emerge, they can be slotted into the same framework: enrich data in Python, expose compact JSON artifacts, then build focused, analyst-centric views on top.
