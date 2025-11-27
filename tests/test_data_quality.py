"""
Tests for the data quality analysis module (rebuild_data_quality.py).

Tests the CNAScorecard-style name matching logic.
"""

import pytest
import sys
from pathlib import Path

# Add data/scripts to path
DATA_SCRIPTS_DIR = Path(__file__).parent.parent / "data" / "scripts"
sys.path.insert(0, str(DATA_SCRIPTS_DIR))


class TestNameNormalization:
    """Test the name normalization function."""
    
    def test_normalize_removes_spaces(self):
        """Normalization should remove spaces."""
        from rebuild_data_quality import normalize_name
        
        assert normalize_name("Red Hat") == "redhat"
        assert normalize_name("Microsoft Corporation") == "microsoftcorporation"
    
    def test_normalize_removes_hyphens(self):
        """Normalization should remove hyphens."""
        from rebuild_data_quality import normalize_name
        
        assert normalize_name("F-Secure") == "fsecure"
        assert normalize_name("Hewlett-Packard") == "hewlettpackard"
    
    def test_normalize_removes_underscores(self):
        """Normalization should remove underscores."""
        from rebuild_data_quality import normalize_name
        
        assert normalize_name("some_vendor") == "somevendor"
    
    def test_normalize_removes_dots(self):
        """Normalization should remove dots."""
        from rebuild_data_quality import normalize_name
        
        assert normalize_name("example.com") == "examplecom"
    
    def test_normalize_lowercases(self):
        """Normalization should lowercase."""
        from rebuild_data_quality import normalize_name
        
        assert normalize_name("MICROSOFT") == "microsoft"
        assert normalize_name("Google") == "google"
    
    def test_normalize_empty_string(self):
        """Normalization should handle empty strings."""
        from rebuild_data_quality import normalize_name
        
        assert normalize_name("") == ""
        assert normalize_name(None) == ""


class TestNameMatching:
    """Test the CNA name matching function."""
    
    @pytest.fixture
    def official_cna_list(self):
        """Sample official CNA list."""
        return [
            {"shortName": "microsoft", "organizationName": "Microsoft Corporation", "cnaID": "CNA-001"},
            {"shortName": "google", "organizationName": "Google LLC", "cnaID": "CNA-002"},
            {"shortName": "redhat", "organizationName": "Red Hat, Inc.", "cnaID": "CNA-003"},
            {"shortName": "f-secure", "organizationName": "F-Secure Corporation", "cnaID": "CNA-004"},
        ]
    
    @pytest.fixture
    def lookup_maps(self, official_cna_list):
        """Build lookup maps from official CNA list."""
        from rebuild_data_quality import build_official_cna_lookups
        return build_official_cna_lookups(official_cna_list)
    
    def test_exact_match(self, lookup_maps, official_cna_list):
        """Test exact shortName match."""
        from rebuild_data_quality import map_cve_name_to_official
        
        short_map, org_map, all_names, norm_map = lookup_maps
        
        result, match_type, confidence = map_cve_name_to_official(
            "microsoft", short_map, org_map, norm_map, official_cna_list
        )
        
        assert result is not None
        assert result["shortName"] == "microsoft"
        assert match_type == "exact_short"
        assert confidence == "high"
    
    def test_case_insensitive_match(self, lookup_maps, official_cna_list):
        """Test case-insensitive match."""
        from rebuild_data_quality import map_cve_name_to_official
        
        short_map, org_map, all_names, norm_map = lookup_maps
        
        result, match_type, confidence = map_cve_name_to_official(
            "MICROSOFT", short_map, org_map, norm_map, official_cna_list
        )
        
        assert result is not None
        assert result["shortName"] == "microsoft"
        assert match_type == "case_short"
        assert confidence == "high"
    
    def test_organization_name_match(self, lookup_maps, official_cna_list):
        """Test match via organization name."""
        from rebuild_data_quality import map_cve_name_to_official
        
        short_map, org_map, all_names, norm_map = lookup_maps
        
        result, match_type, confidence = map_cve_name_to_official(
            "Microsoft Corporation", short_map, org_map, norm_map, official_cna_list
        )
        
        assert result is not None
        assert result["shortName"] == "microsoft"
        assert match_type in ("exact_org", "case_org")
        assert confidence == "high"
    
    def test_normalized_match(self, lookup_maps, official_cna_list):
        """Test match via normalization (removing hyphens, spaces)."""
        from rebuild_data_quality import map_cve_name_to_official
        
        short_map, org_map, all_names, norm_map = lookup_maps
        
        # "fsecure" should match "f-secure" after normalization
        result, match_type, confidence = map_cve_name_to_official(
            "fsecure", short_map, org_map, norm_map, official_cna_list
        )
        
        assert result is not None
        assert result["shortName"] == "f-secure"
        assert match_type == "normalized"
        assert confidence == "medium"
    
    def test_partial_match(self, lookup_maps, official_cna_list):
        """Test partial/substring match."""
        from rebuild_data_quality import map_cve_name_to_official
        
        short_map, org_map, all_names, norm_map = lookup_maps
        
        # "microsoftinc" contains "microsoft"
        result, match_type, confidence = map_cve_name_to_official(
            "microsoftinc", short_map, org_map, norm_map, official_cna_list
        )
        
        assert result is not None
        assert result["shortName"] == "microsoft"
        assert match_type == "partial"
        assert confidence == "low"
    
    def test_no_match(self, lookup_maps, official_cna_list):
        """Test when no match is found."""
        from rebuild_data_quality import map_cve_name_to_official
        
        short_map, org_map, all_names, norm_map = lookup_maps
        
        result, match_type, confidence = map_cve_name_to_official(
            "unknownvendor123", short_map, org_map, norm_map, official_cna_list
        )
        
        assert result is None
        assert match_type is None
        assert confidence is None
    
    def test_empty_name(self, lookup_maps, official_cna_list):
        """Test handling of empty name."""
        from rebuild_data_quality import map_cve_name_to_official
        
        short_map, org_map, all_names, norm_map = lookup_maps
        
        result, match_type, confidence = map_cve_name_to_official(
            "", short_map, org_map, norm_map, official_cna_list
        )
        
        assert result is None
        assert match_type is None


class TestBuildLookups:
    """Test the lookup map building function."""
    
    def test_build_lookups_creates_all_maps(self):
        """Verify all lookup maps are created."""
        from rebuild_data_quality import build_official_cna_lookups
        
        cna_list = [
            {"shortName": "test", "organizationName": "Test Corp", "cnaID": "CNA-TEST"}
        ]
        
        short_map, org_map, all_names, norm_map = build_official_cna_lookups(cna_list)
        
        assert "test" in short_map
        assert "Test Corp" in org_map
        assert "test" in all_names
        assert "testcorp" in norm_map  # normalized org name
    
    def test_build_lookups_handles_missing_fields(self):
        """Verify handling of CNAs with missing fields."""
        from rebuild_data_quality import build_official_cna_lookups
        
        cna_list = [
            {"shortName": "test1"},  # Missing organizationName
            {"organizationName": "Test Corp 2"},  # Missing shortName
            {"shortName": "", "organizationName": ""},  # Empty fields
        ]
        
        # Should not raise
        short_map, org_map, all_names, norm_map = build_official_cna_lookups(cna_list)
        
        assert "test1" in short_map
        assert "Test Corp 2" in org_map
