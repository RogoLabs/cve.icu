"""
Pytest configuration and shared fixtures for CVE.ICU tests.
"""
from __future__ import annotations

import json
import sys
import tempfile
from collections.abc import Generator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

# Add the data directory to the path for imports
ROOT_DIR = Path(__file__).parent.parent
DATA_DIR = ROOT_DIR / "data"
sys.path.insert(0, str(DATA_DIR))


@pytest.fixture(autouse=True)
def quiet_logging():
    """Automatically silence logging during tests to reduce noise."""
    from logging_config import silence_for_tests, restore_logging
    silence_for_tests()
    yield
    restore_logging()


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for test outputs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_cve_record() -> dict[str, Any]:
    """Return a sample CVE record in V5 format."""
    return {
        "cveMetadata": {
            "cveId": "CVE-2024-12345",
            "assignerOrgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",
            "assignerShortName": "mitre",
            "state": "PUBLISHED",
            "datePublished": "2024-06-15T10:30:00.000Z",
            "dateUpdated": "2024-06-20T14:00:00.000Z"
        },
        "containers": {
            "cna": {
                "affected": [
                    {
                        "vendor": "example_vendor",
                        "product": "example_product",
                        "versions": [
                            {"version": "1.0.0", "status": "affected"}
                        ]
                    }
                ],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "A sample vulnerability description for testing."
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "type": "CWE",
                                "cweId": "CWE-79",
                                "description": "Cross-site Scripting (XSS)"
                            }
                        ]
                    }
                ],
                "metrics": [
                    {
                        "cvssV3_1": {
                            "version": "3.1",
                            "baseScore": 7.5,
                            "baseSeverity": "HIGH",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                        }
                    }
                ],
                "references": [
                    {
                        "url": "https://example.com/advisory/CVE-2024-12345"
                    }
                ]
            }
        }
    }


@pytest.fixture
def sample_epss_data() -> dict[str, dict[str, float]]:
    """Return sample EPSS data as a dict keyed by CVE ID."""
    return {
        "CVE-2024-12345": {"epss_score": 0.15, "epss_percentile": 0.85},
        "CVE-2024-12346": {"epss_score": 0.75, "epss_percentile": 0.98},
        "CVE-2024-12347": {"epss_score": 0.02, "epss_percentile": 0.45},
    }


@pytest.fixture
def sample_kev_data() -> set[str]:
    """Return sample KEV data as a list of CVE IDs."""
    return {
        "CVE-2024-12346",  # High EPSS, in KEV
        "CVE-2023-99999",  # Historical KEV entry
    }


@pytest.fixture
def sample_cna_analysis() -> dict[str, Any]:
    """Return a sample CNA analysis structure."""
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_cnas": 5,
        "active_cnas": 4,
        "inactive_cnas": 1,
        "cna_list": [
            {
                "name": "mitre",
                "count": 1000,
                "kev_count": 50,
                "epss_high_count": 100,
                "activity_status": "Active",
                "cna_types": ["Program"],
                "is_official": True
            },
            {
                "name": "google",
                "count": 500,
                "kev_count": 20,
                "epss_high_count": 45,
                "activity_status": "Active",
                "cna_types": ["Vendor"],
                "is_official": True
            }
        ]
    }


@pytest.fixture
def sample_cvss_analysis() -> dict[str, Any]:
    """Return a sample CVSS analysis structure."""
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_cves_with_cvss": 10000,
        "total_by_version": {
            "v3.1": 7000,
            "v3.0": 2000,
            "v2.0": 1000
        },
        "severity_distribution": {
            "v3.1": {
                "CRITICAL": 500,
                "HIGH": 2000,
                "MEDIUM": 3500,
                "LOW": 900,
                "NONE": 100
            }
        }
    }


@pytest.fixture
def sample_year_data() -> dict[str, Any]:
    """Return sample year data structure."""
    return {
        "year": 2024,
        "total_cves": 5000,
        "date_data": {
            "monthly_distribution": {
                "1": 400, "2": 380, "3": 450, "4": 420, "5": 410, "6": 430,
                "7": 440, "8": 390, "9": 460, "10": 470, "11": 400, "12": 350
            },
            "daily_analysis": {
                "total_days": 365,
                "days_with_cves": 350,
                "avg_cves_per_day": 13.7,
                "max_cves_in_day": 85
            }
        },
        "cvss": {
            "severity_distribution": {
                "CRITICAL": 250,
                "HIGH": 1250,
                "MEDIUM": 2000,
                "LOW": 1250,
                "NONE": 250
            }
        }
    }


@pytest.fixture
def mock_cve_list_dir(temp_dir: Path) -> Generator[Path, None, None]:
    """Create a mock CVE list directory structure with sample data."""
    cves_dir = temp_dir / "cvelistV5" / "cves"
    
    # Create year/number directories
    year_dir = cves_dir / "2024" / "12xxx"
    year_dir.mkdir(parents=True)
    
    # Create a sample CVE file
    cve_file = year_dir / "CVE-2024-12345.json"
    cve_data = {
        "cveMetadata": {
            "cveId": "CVE-2024-12345",
            "assignerOrgId": "test-org-id",
            "assignerShortName": "test_cna",
            "state": "PUBLISHED",
            "datePublished": "2024-06-15T10:30:00.000Z"
        },
        "containers": {
            "cna": {
                "affected": [{"vendor": "test_vendor", "product": "test_product"}],
                "descriptions": [{"lang": "en", "value": "Test vulnerability"}],
                "problemTypes": [{"descriptions": [{"type": "CWE", "cweId": "CWE-79"}]}],
                "metrics": [{"cvssV3_1": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]
            }
        }
    }
    
    with open(cve_file, 'w') as f:
        json.dump(cve_data, f)
    
    yield temp_dir


# JSON Schema definitions for validation
CVE_YEAR_SCHEMA = {
    "type": "object",
    "required": ["year", "total_cves"],
    "properties": {
        "year": {"type": "integer", "minimum": 1999},
        "total_cves": {"type": "integer", "minimum": 0},
        "date_data": {"type": "object"},
        "cvss": {"type": "object"},
        "kev": {"type": "object"},
        "vendors": {"type": "object"},
        "cwe": {"type": "object"}
    }
}

CNA_ANALYSIS_SCHEMA = {
    "type": "object",
    "required": ["total_cnas", "cna_list"],
    "properties": {
        "generated_at": {"type": "string"},
        "total_cnas": {"type": "integer", "minimum": 0},
        "active_cnas": {"type": "integer", "minimum": 0},
        "inactive_cnas": {"type": "integer", "minimum": 0},
        "cna_list": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["name", "count"],
                "properties": {
                    "name": {"type": "string"},
                    "count": {"type": "integer", "minimum": 0},
                    "kev_count": {"type": "integer", "minimum": 0},
                    "epss_high_count": {"type": "integer", "minimum": 0},
                    "activity_status": {"type": "string"},
                    "is_official": {"type": "boolean"}
                }
            }
        }
    }
}

CVSS_ANALYSIS_SCHEMA = {
    "type": "object",
    "required": ["total_cves_with_cvss", "severity_distribution"],
    "properties": {
        "generated_at": {"type": "string"},
        "total_cves_with_cvss": {"type": "integer", "minimum": 0},
        "total_by_version": {"type": "object"},
        "severity_distribution": {"type": "object"},
        "score_distribution": {"type": "object"},
        "kev_global_count": {"type": "integer"},
        "kev_by_year": {"type": "object"}
    }
}

DATA_QUALITY_SCHEMA = {
    "type": "object",
    "required": ["stats"],
    "properties": {
        "stats": {
            "type": "object",
            "required": ["total_cnas_in_analysis", "exact_matches", "unmatched"],
            "properties": {
                "total_cnas_in_analysis": {"type": "integer"},
                "exact_matches": {"type": "integer"},
                "case_mismatches": {"type": "integer"},
                "org_name_matches": {"type": "integer"},
                "normalized_matches": {"type": "integer"},
                "partial_matches": {"type": "integer"},
                "unmatched": {"type": "integer"}
            }
        },
        "exact_matches": {"type": "array"},
        "case_mismatches": {"type": "array"},
        "unmatched": {"type": "array"}
    }
}
