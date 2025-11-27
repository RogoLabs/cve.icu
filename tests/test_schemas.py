"""
Tests for JSON schema validation of output files.

These tests validate that the generated JSON files conform to expected schemas,
ensuring data consistency and catching regressions.
"""

import json
import sys
from pathlib import Path

import pytest
from jsonschema import validate, ValidationError

# Add tests directory to path for importing conftest schemas
sys.path.insert(0, str(Path(__file__).parent))

from conftest import (
    CVE_YEAR_SCHEMA,
    CNA_ANALYSIS_SCHEMA,
    CVSS_ANALYSIS_SCHEMA,
    DATA_QUALITY_SCHEMA,
)


# Path to web data directory
WEB_DATA_DIR = Path(__file__).parent.parent / "web" / "data"


class TestSchemaValidation:
    """Test that generated JSON files conform to expected schemas."""
    
    @pytest.mark.skipif(
        not (WEB_DATA_DIR / "cna_analysis.json").exists(),
        reason="CNA analysis file not found - run build first"
    )
    def test_cna_analysis_schema(self):
        """Validate cna_analysis.json against schema."""
        with open(WEB_DATA_DIR / "cna_analysis.json") as f:
            data = json.load(f)
        
        # Validate against schema
        validate(instance=data, schema=CNA_ANALYSIS_SCHEMA)
        
        # Additional assertions
        assert data["total_cnas"] > 0, "Should have at least one CNA"
        assert len(data["cna_list"]) > 0, "CNA list should not be empty"
        assert data["active_cnas"] + data["inactive_cnas"] == data["total_cnas"]
    
    @pytest.mark.skipif(
        not (WEB_DATA_DIR / "cvss_analysis.json").exists(),
        reason="CVSS analysis file not found - run build first"
    )
    def test_cvss_analysis_schema(self):
        """Validate cvss_analysis.json against schema."""
        with open(WEB_DATA_DIR / "cvss_analysis.json") as f:
            data = json.load(f)
        
        # Validate against schema
        validate(instance=data, schema=CVSS_ANALYSIS_SCHEMA)
        
        # Additional assertions
        assert data["total_cves_with_cvss"] > 0, "Should have scored CVEs"
        assert len(data["severity_distribution"]) > 0, "Severity distribution should have entries"
    
    @pytest.mark.skipif(
        not (WEB_DATA_DIR / "data_quality.json").exists(),
        reason="Data quality file not found - run build first"
    )
    def test_data_quality_schema(self):
        """Validate data_quality.json against schema."""
        with open(WEB_DATA_DIR / "data_quality.json") as f:
            data = json.load(f)
        
        # Validate against schema
        validate(instance=data, schema=DATA_QUALITY_SCHEMA)
        
        # Additional assertions
        stats = data["stats"]
        total_analyzed = stats["total_cnas_in_analysis"]
        matched = (
            stats["exact_matches"] + 
            stats["case_mismatches"] + 
            stats["org_name_matches"] + 
            stats["normalized_matches"] + 
            stats["partial_matches"]
        )
        unmatched = stats["unmatched"]
        
        assert total_analyzed == matched + unmatched, \
            "Total should equal matched + unmatched"
    
    @pytest.mark.skipif(
        not (WEB_DATA_DIR / "cve_2024.json").exists(),
        reason="Year data file not found - run build first"
    )
    def test_year_data_schema(self):
        """Validate a sample year data file against schema."""
        with open(WEB_DATA_DIR / "cve_2024.json") as f:
            data = json.load(f)
        
        # Validate against schema
        validate(instance=data, schema=CVE_YEAR_SCHEMA)
        
        # Additional assertions
        assert data["year"] == 2024
        assert data["total_cves"] > 0


class TestDataIntegrity:
    """Test data integrity and consistency across files."""
    
    @pytest.mark.skipif(
        not (WEB_DATA_DIR / "cna_analysis.json").exists(),
        reason="CNA analysis file not found - run build first"
    )
    def test_cna_list_has_required_fields(self):
        """Verify all CNAs have required fields populated."""
        with open(WEB_DATA_DIR / "cna_analysis.json") as f:
            data = json.load(f)
        
        for cna in data["cna_list"]:
            assert "name" in cna, f"CNA missing 'name' field"
            assert "count" in cna, f"CNA {cna.get('name', 'unknown')} missing 'count'"
            assert cna["count"] >= 0, f"CNA {cna['name']} has negative count"
    
    @pytest.mark.skipif(
        not (WEB_DATA_DIR / "yearly_summary.json").exists(),
        reason="Yearly summary file not found - run build first"
    )
    def test_yearly_summary_completeness(self):
        """Verify yearly summary contains all expected years."""
        with open(WEB_DATA_DIR / "yearly_summary.json") as f:
            data = json.load(f)
        
        years = data.get("years", {})
        
        # Should have data from 1999 to current year
        assert "1999" in years or 1999 in years, "Missing 1999 data"
        assert "2024" in years or 2024 in years, "Missing 2024 data"
        
        # Each year should have required fields
        for year, year_data in years.items():
            assert "total_cves" in year_data, f"Year {year} missing total_cves"
            assert year_data["total_cves"] >= 0, f"Year {year} has negative CVE count"
    
    @pytest.mark.skipif(
        not all((WEB_DATA_DIR / f).exists() for f in ["cna_analysis.json", "cve_all.json"]),
        reason="Required files not found - run build first"
    )
    def test_cve_totals_reasonable(self):
        """Verify CVE totals are in reasonable ranges."""
        with open(WEB_DATA_DIR / "cna_analysis.json") as f:
            cna_data = json.load(f)
        
        with open(WEB_DATA_DIR / "cve_all.json") as f:
            all_data = json.load(f)
        
        # Total CVEs from CNA analysis
        cna_total = sum(cna["count"] for cna in cna_data["cna_list"])
        
        # cve_all.json contains metadata with total
        all_total = all_data.get("total_cves", 0)
        
        # Both should be in reasonable range (200K+ CVEs exist)
        assert cna_total > 200000, f"CNA total ({cna_total}) seems too low"
        assert all_total > 200000, f"All total ({all_total}) seems too low"
        
        # They may differ due to data sources/timing, but should be same order of magnitude
        ratio = cna_total / all_total if all_total > 0 else 0
        assert 0.8 <= ratio <= 1.2, \
            f"CNA total ({cna_total}) differs significantly from cve_all ({all_total})"


class TestFixtureSchemas:
    """Test that fixtures conform to schemas (validates our test data)."""
    
    def test_sample_cna_analysis_valid(self, sample_cna_analysis):
        """Verify sample CNA analysis fixture is valid."""
        validate(instance=sample_cna_analysis, schema=CNA_ANALYSIS_SCHEMA)
    
    def test_sample_cvss_analysis_valid(self, sample_cvss_analysis):
        """Verify sample CVSS analysis fixture is valid."""
        validate(instance=sample_cvss_analysis, schema=CVSS_ANALYSIS_SCHEMA)
    
    def test_sample_year_data_valid(self, sample_year_data):
        """Verify sample year data fixture is valid."""
        validate(instance=sample_year_data, schema=CVE_YEAR_SCHEMA)
