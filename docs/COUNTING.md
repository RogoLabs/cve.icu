# CVE.ICU Data Counting Methodology

This document explains how CVE data is counted and filtered throughout the CVE.ICU pipeline, ensuring all numbers are auditable and consistent.

## Data Sources

### 1. NVD JSON (`data/cache/nvd.json`)

- **Source**: NIST National Vulnerability Database API
- **Format**: JSON array of CVE vulnerability records
- **Total Records**: ~319,436
- **Year Range**: 1999-2025 (NVD itself starts at 1999)

### 2. CVE V5 Repository (`data/cache/cvelistV5/`)

- **Source**: MITRE CVE List V5 Git repository
- **Format**: Individual JSON files per CVE
- **Total Files**: ~319,485
- **Year Range**: 1999-2025

## CVE States

Both data sources track CVE status/state:

| State | NVD Field | V5 Field | Meaning |
|-------|-----------|----------|---------|
| Published | `vulnStatus: Modified/Analyzed/etc.` | `state: PUBLISHED` | Valid, active CVE |
| Rejected | `vulnStatus: Rejected` | `state: REJECTED` | Withdrawn/invalid CVE |

**Raw counts (as of last audit):**

- Total records: ~319,436 (NVD) / ~319,485 (V5)
- Rejected: ~16,188 (both sources)
- Published: ~303,248 (NVD) / ~303,297 (V5)

## Filtering Rules

**All analyses consistently exclude REJECTED CVEs.** Rejected CVEs are withdrawn vulnerabilities that no longer represent valid security issues.

### Year-Based Analysis (`cve_all.json`, `cve_YYYY.json`)

**Source**: NVD JSON  
**Processing**: `data/cve_years.py`

Filters applied:

1. **Valid CVE ID**: Must start with `CVE-`
2. **Not Rejected**: Skip if `vulnStatus` contains "Rejected"
3. **Year >= 1999**: Only include CVEs from 1999 onwards
4. **Publication Date**: Uses `published` field, falls back to CVE ID year

```text
Total NVD records:     319,436
- Rejected:           -16,188
- Pre-1999:              -679
= Final count:        ~302,569
```

### CNA Analysis (`cna_analysis.json`)

**Source**: CVE V5 Repository (Git)  
**Processing**: `data/cve_v5_processor.py`

Filters applied:

1. **Valid JSON file**: Must parse successfully
2. **Not Rejected**: Skip if `state` is "REJECTED"
3. **Has assignerOrgId**: Must have CNA organization ID

```text
Total V5 files:       319,485
- Rejected:           -16,188
= Final count:        ~303,297
```

## Output File Summary

| File | Source | Filters | Total CVEs |
|------|--------|---------|------------|
| `cve_all.json` | NVD | No Rejected, 1999+ | ~302,569 |
| `cve_YYYY.json` | NVD | No Rejected, year match | Varies |
| `cna_analysis.json` | V5 Repo | No Rejected | ~303,297 |
| `cna_analysis_current_year.json` | V5 Repo | No Rejected, current year | Varies |

## Known Discrepancies

### CNA Total vs cve_all Total

`cna_analysis.json` (V5) always runs ahead of `cve_all.json` (NVD, 1999+). The gap is
**two independent terms**, and they behave completely differently:

```text
gap = pre_1999_offset + nvd_ingestion_lag
```

| Term | Size | Behaviour |
|------|------|-----------|
| **Pre-1999 offset** | 679 (measured 2026-08-26) | **Frozen.** Legacy CVEs backdated to their original 1988-1998 disclosure date (1997: 252, 1998: 246). `cve_all.json` is assembled from the 1999+ year files, so they are dropped there; `cna_analysis.json` counts every non-rejected V5 record. Does not grow with the corpus. |
| **NVD ingestion lag** | 100-1,500, spiky | **Varies with _daily publication volume_, not corpus size.** cvelistV5 has a CVE the instant the CNA publishes; NVD ingests behind. One Oracle CPU day lands 1,100-1,400 CVEs at once. |

Both sources consistently exclude REJECTED CVEs.

The build measures the pre-1999 term rather than assuming it, and publishes it as
`cve_all.json:excluded_pre_1999`. `reconcile_cna_vs_year_totals()` in `build.py`
subtracts it and bounds only the lag term, in both directions:

- **Lag > `MAX_INGESTION_LAG` (3,000)** — two heavy publication days with no ingestion.
  The NVD feed has stalled. Fails the build.
- **Lag < `-MAX_NVD_LEAD` (-100)** — NVD is *ahead* of cvelistV5, which cannot legitimately
  happen. One of the feeds is wrong. Fails the build.

#### Why not a single tolerance?

This check previously compared `abs(CNA - cve_all)` against a flat `< 1000`, which measured
both terms together. The fixed 679-record offset consumed two thirds of the budget, leaving
only ~321 CVEs of headroom for the term that actually moves. On **2026-08-25** a busy but
unremarkable publication day (787 CVEs, 327 of them one Chrome batch) pushed the gap to
1,196 and failed the scheduled deploy.

Widening the tolerance to a percentage of corpus size does not fix this — it scales the
budget against a number that has no relationship to either term. Subtracting the known
offset is what restores the full budget to the lag.

## Validation

To verify counting is correct, run:

```bash
# Run build with validation
python build.py --validate

# Or manually verify:
# Count NVD records
python3 -c "import json; d=json.load(open('data/cache/nvd.json')); print(len(d))"

# Count V5 files
find data/cache/cvelistV5/cves -name 'CVE-*.json' | wc -l

# Verify cve_all.json
python3 -c "import json; d=json.load(open('web/data/cve_all.json')); print(d['total_cves'])"

# Verify CNA total
python3 -c "import json; d=json.load(open('web/data/cna_analysis.json')); print(d['repository_stats']['total_cves'])"
```

## Design Decisions

### Why exclude REJECTED CVEs?

Rejected CVEs are withdrawn vulnerabilities that no longer represent valid security issues. All analyses consistently exclude REJECTED CVEs to:

- Accurately represent the active vulnerability landscape
- Avoid inflating counts with invalid entries
- Maintain consistency across all views

### Why start from 1999?

The CVE program began in 1999. While some CVEs have earlier IDs (for pre-existing vulnerabilities), the data quality and completeness is best from 1999 onwards.

## Audit Checklist

When auditing the counting:

1. [ ] Download fresh data (`python data/download_cve_data.py`)
2. [ ] Count raw NVD entries
3. [ ] Count raw V5 files  
4. [ ] Count rejected in each source
5. [ ] Verify year files sum to cve_all total
6. [ ] Verify CNA list sums to repository_stats.total_cves
7. [ ] Run full build and check for warnings
