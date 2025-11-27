# CVE.ICU JSON Schemas

This document describes the JSON output file schemas used by CVE.ICU.

## Overview

All JSON files are written to `web/data/` and follow consistent patterns:

- Timestamps in ISO 8601 format
- Snake_case for field names
- Nested objects for complex data structures
- Arrays for lists and time series

## Output Files

### cve_YYYY.json / cve_all.json

Per-year CVE analysis with individual CVE records.

```json
{
  "metadata": {
    "year": 2024,
    "generated_at": "2024-01-15T10:30:00Z",
    "total_cves": 28000,
    "source": "NVD"
  },
  "cves": [
    {
      "id": "CVE-2024-1234",
      "published": "2024-01-10T15:30:00Z",
      "modified": "2024-01-12T09:00:00Z",
      "description": "A vulnerability in...",
      "cvss_v3": {
        "score": 7.5,
        "severity": "HIGH",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
      },
      "cvss_v2": {
        "score": 5.0,
        "severity": "MEDIUM"
      },
      "cwes": ["CWE-79", "CWE-89"],
      "cpes": ["cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"],
      "references": [
        {
          "url": "https://example.com/advisory",
          "source": "vendor"
        }
      ]
    }
  ],
  "statistics": {
    "by_severity": {
      "CRITICAL": 500,
      "HIGH": 3000,
      "MEDIUM": 8000,
      "LOW": 2000,
      "NONE": 100
    },
    "by_month": {
      "2024-01": 2500,
      "2024-02": 2800
    }
  }
}
```

### cna_analysis.json

CNA (CVE Numbering Authority) assignment statistics.

```json
{
  "metadata": {
    "generated_at": "2024-01-15T10:30:00Z",
    "total_cves": 303000,
    "total_cnas": 400,
    "source": "CVE V5 Repository"
  },
  "repository_stats": {
    "total_files": 305000,
    "total_cves": 303000,
    "rejected_count": 2000,
    "parse_errors": 50
  },
  "top_cnas": [
    {
      "name": "MITRE",
      "cve_count": 50000,
      "percentage": 16.5
    },
    {
      "name": "Red Hat",
      "cve_count": 15000,
      "percentage": 4.9
    }
  ],
  "cna_details": {
    "MITRE": {
      "cve_count": 50000,
      "official_name": "The MITRE Corporation",
      "cna_id": "abc123",
      "yearly_counts": {
        "2020": 8000,
        "2021": 9000,
        "2022": 10000,
        "2023": 11000,
        "2024": 12000
      }
    }
  },
  "yearly_totals": {
    "2020": 18000,
    "2021": 20000,
    "2022": 25000,
    "2023": 29000,
    "2024": 28000
  }
}
```

### cvss_analysis.json

CVSS score distribution analysis.

```json
{
  "metadata": {
    "generated_at": "2024-01-15T10:30:00Z",
    "total_cves": 280000,
    "cves_with_cvss_v3": 200000,
    "cves_with_cvss_v2": 150000
  },
  "cvss_v3": {
    "distribution": {
      "0.0-0.9": 1000,
      "1.0-1.9": 2000,
      "2.0-2.9": 5000,
      "3.0-3.9": 10000,
      "4.0-4.9": 20000,
      "5.0-5.9": 30000,
      "6.0-6.9": 40000,
      "7.0-7.9": 50000,
      "8.0-8.9": 30000,
      "9.0-10.0": 12000
    },
    "by_severity": {
      "CRITICAL": 15000,
      "HIGH": 80000,
      "MEDIUM": 80000,
      "LOW": 20000,
      "NONE": 5000
    },
    "average_score": 6.8,
    "median_score": 6.5
  },
  "cvss_v2": {
    "distribution": {},
    "by_severity": {
      "HIGH": 50000,
      "MEDIUM": 70000,
      "LOW": 30000
    },
    "average_score": 5.5
  },
  "yearly_averages": {
    "2020": {"v3": 6.5, "v2": 5.2},
    "2021": {"v3": 6.7, "v2": 5.3},
    "2022": {"v3": 6.8, "v2": 5.4},
    "2023": {"v3": 6.9, "v2": null},
    "2024": {"v3": 7.0, "v2": null}
  }
}
```

### cwe_analysis.json

CWE (Common Weakness Enumeration) analysis.

```json
{
  "metadata": {
    "generated_at": "2024-01-15T10:30:00Z",
    "total_cves": 280000,
    "cves_with_cwe": 250000,
    "unique_cwes": 500
  },
  "top_cwes": [
    {
      "cwe_id": "CWE-79",
      "name": "Cross-site Scripting (XSS)",
      "count": 45000,
      "percentage": 18.0
    },
    {
      "cwe_id": "CWE-89",
      "name": "SQL Injection",
      "count": 30000,
      "percentage": 12.0
    }
  ],
  "cwe_categories": {
    "injection": {
      "cwes": ["CWE-79", "CWE-89", "CWE-78"],
      "total_count": 100000
    },
    "memory_safety": {
      "cwes": ["CWE-120", "CWE-119", "CWE-787"],
      "total_count": 50000
    }
  },
  "yearly_trends": {
    "2020": {"CWE-79": 8000, "CWE-89": 5000},
    "2021": {"CWE-79": 9000, "CWE-89": 5500},
    "2022": {"CWE-79": 10000, "CWE-89": 6000}
  }
}
```

### cpe_analysis.json

CPE (Common Platform Enumeration) affected product analysis.

```json
{
  "metadata": {
    "generated_at": "2024-01-15T10:30:00Z",
    "total_cves": 280000,
    "cves_with_cpe": 260000,
    "unique_vendors": 5000,
    "unique_products": 50000
  },
  "top_vendors": [
    {
      "vendor": "microsoft",
      "cve_count": 15000,
      "percentage": 5.7,
      "top_products": ["windows", "office", "edge"]
    },
    {
      "vendor": "linux",
      "cve_count": 10000,
      "percentage": 3.8,
      "top_products": ["linux_kernel"]
    }
  ],
  "top_products": [
    {
      "vendor": "linux",
      "product": "linux_kernel",
      "cve_count": 8000
    },
    {
      "vendor": "microsoft",
      "product": "windows",
      "cve_count": 5000
    }
  ],
  "vendor_yearly": {
    "microsoft": {
      "2020": 1500,
      "2021": 1600,
      "2022": 1700
    }
  }
}
```

### calendar_analysis.json

CVE publication timing analysis.

```json
{
  "metadata": {
    "generated_at": "2024-01-15T10:30:00Z",
    "total_cves": 280000
  },
  "by_day_of_week": {
    "Monday": 55000,
    "Tuesday": 60000,
    "Wednesday": 58000,
    "Thursday": 55000,
    "Friday": 40000,
    "Saturday": 6000,
    "Sunday": 6000
  },
  "by_hour": {
    "0": 5000,
    "1": 4000,
    "12": 25000,
    "17": 30000,
    "23": 8000
  },
  "by_month": {
    "January": 22000,
    "February": 20000,
    "March": 25000,
    "December": 18000
  },
  "patch_tuesday_analysis": {
    "patch_tuesday_cves": 15000,
    "percentage": 5.4
  },
  "heatmap": {
    "Monday_0": 800,
    "Monday_1": 750,
    "Tuesday_12": 5000
  }
}
```

### growth_analysis.json

CVE growth and trend analysis.

```json
{
  "metadata": {
    "generated_at": "2024-01-15T10:30:00Z",
    "start_year": 1999,
    "end_year": 2024
  },
  "yearly_counts": {
    "1999": 894,
    "2000": 1020,
    "2020": 18000,
    "2021": 20000,
    "2022": 25000,
    "2023": 29000,
    "2024": 28000
  },
  "cumulative_counts": {
    "1999": 894,
    "2000": 1914,
    "2024": 303000
  },
  "growth_rates": {
    "2020": 0.12,
    "2021": 0.11,
    "2022": 0.25,
    "2023": 0.16,
    "2024": -0.03
  },
  "projections": {
    "2025": {
      "low": 26000,
      "mid": 30000,
      "high": 35000
    }
  },
  "milestones": [
    {"count": 100000, "date": "2019-06-15"},
    {"count": 200000, "date": "2022-03-20"},
    {"count": 300000, "date": "2024-08-10"}
  ]
}
```

### scoring_analysis.json

EPSS and KEV exploit scoring analysis.

```json
{
  "metadata": {
    "generated_at": "2024-01-15T10:30:00Z",
    "epss_date": "2024-01-15",
    "kev_date": "2024-01-15"
  },
  "epss": {
    "total_scored": 200000,
    "distribution": {
      "0.0-0.1": 150000,
      "0.1-0.2": 30000,
      "0.2-0.5": 15000,
      "0.5-1.0": 5000
    },
    "top_scores": [
      {
        "cve_id": "CVE-2021-44228",
        "epss_score": 0.975,
        "description": "Log4Shell"
      }
    ],
    "average_score": 0.05,
    "median_score": 0.01
  },
  "kev": {
    "total_count": 1100,
    "by_year": {
      "2020": 150,
      "2021": 300,
      "2022": 350,
      "2023": 200,
      "2024": 100
    },
    "by_vendor": {
      "microsoft": 200,
      "apple": 80,
      "google": 60
    },
    "recent_additions": [
      {
        "cve_id": "CVE-2024-1234",
        "date_added": "2024-01-10",
        "vendor": "example"
      }
    ]
  },
  "correlation": {
    "kev_with_high_epss": 950,
    "high_epss_not_in_kev": 4000,
    "kev_with_low_epss": 150
  }
}
```

## Schema Patterns

### Metadata Block

All files include a metadata block:

```json
{
  "metadata": {
    "generated_at": "ISO 8601 timestamp",
    "total_cves": "integer count",
    "source": "data source name"
  }
}
```

### Current Year Variants

Files ending in `_current_year.json` have the same schema but filtered to the current calendar year only.

### Severity Levels

CVSS v3 severities: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NONE`
CVSS v2 severities: `HIGH`, `MEDIUM`, `LOW`

### Counts and Percentages

Large counts include both absolute values and percentages:

```json
{
  "count": 50000,
  "percentage": 16.5
}
```

## Validation

Use the `--validate` flag on build.py to verify schema consistency:

```bash
python build.py --validate
```

This checks:
- Required fields are present
- Data types are correct
- Counts are consistent across files
