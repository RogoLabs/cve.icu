"""
End-to-end smoke tests for the CVE.ICU build pipeline.

These tests verify the build produces valid output without running
a full build against live data.
"""

import json
import os
from pathlib import Path

import pytest


# Paths
ROOT_DIR = Path(__file__).parent.parent
WEB_DIR = ROOT_DIR / "web"
WEB_DATA_DIR = WEB_DIR / "data"
TEMPLATES_DIR = ROOT_DIR / "templates"


class TestBuildOutputExists:
    """Verify that expected build outputs exist."""
    
    @pytest.mark.skipif(
        not WEB_DIR.exists(),
        reason="Web directory not found - run build first"
    )
    def test_web_directory_exists(self):
        """Web output directory should exist."""
        assert WEB_DIR.exists()
        assert WEB_DIR.is_dir()
    
    @pytest.mark.skipif(
        not WEB_DATA_DIR.exists(),
        reason="Web data directory not found - run build first"
    )
    def test_data_directory_exists(self):
        """Web data directory should exist."""
        assert WEB_DATA_DIR.exists()
        assert WEB_DATA_DIR.is_dir()
    
    @pytest.mark.skipif(
        not WEB_DATA_DIR.exists(),
        reason="Web data directory not found - run build first"
    )
    def test_core_json_files_exist(self):
        """Core JSON data files should exist."""
        required_files = [
            "cna_analysis.json",
            "cvss_analysis.json",
            "cwe_analysis.json",
            "cpe_analysis.json",
            "growth_analysis.json",
            "calendar_analysis.json",
            "yearly_summary.json",
            "cve_all.json",
        ]
        
        for filename in required_files:
            filepath = WEB_DATA_DIR / filename
            assert filepath.exists(), f"Missing required file: {filename}"
    
    @pytest.mark.skipif(
        not WEB_DIR.exists(),
        reason="Web directory not found - run build first"
    )
    def test_html_pages_exist(self):
        """HTML pages should be generated."""
        required_pages = [
            "index.html",
            "years.html",
            "cna.html",
            "cna-hub.html",
            "cpe.html",
            "cvss.html",
            "cwe.html",
            "calendar.html",
            "growth.html",
            "scoring.html",
            "epss.html",
            "kev.html",
            "data-quality.html",
            "about.html",
        ]
        
        for page in required_pages:
            filepath = WEB_DIR / page
            assert filepath.exists(), f"Missing HTML page: {page}"
    
    @pytest.mark.skipif(
        not (WEB_DIR / "static").exists(),
        reason="Static directory not found - run build first"
    )
    def test_static_assets_exist(self):
        """Static assets should be present."""
        static_dir = WEB_DIR / "static"
        
        # Check CSS
        css_dir = static_dir / "css"
        assert css_dir.exists(), "CSS directory missing"
        assert (css_dir / "style.css").exists(), "Main stylesheet missing"
        
        # Check JS directory exists
        js_dir = static_dir / "js"
        assert js_dir.exists(), "JS directory missing"


class TestBuildOutputValidity:
    """Verify that build outputs are valid and well-formed."""
    
    @pytest.mark.skipif(
        not WEB_DATA_DIR.exists(),
        reason="Web data directory not found - run build first"
    )
    def test_json_files_are_valid(self):
        """All JSON files should be valid JSON."""
        json_files = list(WEB_DATA_DIR.glob("*.json"))
        
        assert len(json_files) > 0, "No JSON files found"
        
        for json_file in json_files:
            try:
                with open(json_file) as f:
                    json.load(f)
            except json.JSONDecodeError as e:
                pytest.fail(f"Invalid JSON in {json_file.name}: {e}")
    
    @pytest.mark.skipif(
        not WEB_DIR.exists(),
        reason="Web directory not found - run build first"
    )
    def test_html_files_have_content(self):
        """HTML files should not be empty."""
        html_files = list(WEB_DIR.glob("*.html"))
        
        assert len(html_files) > 0, "No HTML files found"
        
        for html_file in html_files:
            content = html_file.read_text()
            assert len(content) > 100, f"HTML file {html_file.name} appears empty"
            assert "<!DOCTYPE html>" in content or "<html" in content, \
                f"HTML file {html_file.name} missing HTML structure"
    
    @pytest.mark.skipif(
        not (WEB_DATA_DIR / "cna_analysis.json").exists(),
        reason="CNA analysis file not found - run build first"
    )
    def test_cna_analysis_has_data(self):
        """CNA analysis should have meaningful data."""
        with open(WEB_DATA_DIR / "cna_analysis.json") as f:
            data = json.load(f)
        
        assert data.get("total_cnas", 0) > 100, "Too few CNAs - data may be incomplete"
        assert len(data.get("cna_list", [])) > 100, "CNA list too short"
    
    @pytest.mark.skipif(
        not (WEB_DATA_DIR / "yearly_summary.json").exists(),
        reason="Yearly summary file not found - run build first"
    )
    def test_yearly_summary_has_all_years(self):
        """Yearly summary should contain all years from 1999."""
        with open(WEB_DATA_DIR / "yearly_summary.json") as f:
            data = json.load(f)
        
        years = data.get("years", {})
        
        # Convert keys to integers for comparison
        year_ints = [int(y) for y in years.keys()]
        
        assert min(year_ints) == 1999, "Missing early years"
        assert max(year_ints) >= 2024, "Missing recent years"
        
        # Should have reasonable total CVE counts
        total_cves = sum(y.get("total_cves", 0) for y in years.values())
        assert total_cves > 200000, f"Total CVEs ({total_cves}) seems too low"


class TestTemplateValidity:
    """Verify that Jinja2 templates are valid."""
    
    def test_templates_exist(self):
        """Template directory should have templates."""
        assert TEMPLATES_DIR.exists(), "Templates directory missing"
        
        templates = list(TEMPLATES_DIR.glob("*.html"))
        assert len(templates) > 10, "Too few templates found"
    
    def test_templates_extend_base(self):
        """Most templates should extend base.html."""
        templates = list(TEMPLATES_DIR.glob("*.html"))
        
        for template in templates:
            if template.name == "base.html":
                continue
            
            content = template.read_text()
            # Most templates should extend base
            if "{% extends" in content:
                assert "base.html" in content, \
                    f"Template {template.name} extends something other than base.html"
    
    def test_base_template_has_required_blocks(self):
        """Base template should define required blocks."""
        base_path = TEMPLATES_DIR / "base.html"
        assert base_path.exists(), "base.html template missing"
        
        content = base_path.read_text()
        
        # Check for essential blocks
        assert "{% block content %}" in content, "Missing content block"
        assert "{% block title %}" in content, "Missing title block"
        
        # Check for navigation
        assert "nav" in content.lower(), "Missing navigation"
        
        # Check for footer
        assert "footer" in content.lower(), "Missing footer"


class TestDataConsistency:
    """Verify data consistency across files."""
    
    @pytest.mark.skipif(
        not all((WEB_DATA_DIR / f).exists() for f in ["cna_analysis.json", "cna_analysis_current_year.json"]),
        reason="Required files not found - run build first"
    )
    def test_current_year_subset_of_all(self):
        """Current year CNAs should be a subset of all CNAs."""
        with open(WEB_DATA_DIR / "cna_analysis.json") as f:
            all_data = json.load(f)
        
        with open(WEB_DATA_DIR / "cna_analysis_current_year.json") as f:
            current_data = json.load(f)
        
        all_cna_names = {cna["name"] for cna in all_data.get("cna_list", [])}
        current_cna_names = {cna["name"] for cna in current_data.get("cna_list", [])}
        
        # All current year CNAs should exist in the all-time list
        missing = current_cna_names - all_cna_names
        assert len(missing) == 0, f"Current year CNAs not in all-time: {missing}"
    
    @pytest.mark.skipif(
        not (WEB_DATA_DIR / "data_quality.json").exists(),
        reason="Data quality file not found - run build first"
    )
    def test_data_quality_match_rate(self):
        """Data quality should show reasonable match rate."""
        with open(WEB_DATA_DIR / "data_quality.json") as f:
            data = json.load(f)
        
        stats = data.get("stats", {})
        total = stats.get("total_cnas_in_analysis", 0)
        unmatched = stats.get("unmatched", 0)
        
        if total > 0:
            match_rate = (total - unmatched) / total
            # Should match at least 80% of CNAs
            assert match_rate >= 0.80, f"Match rate too low: {match_rate:.1%}"
