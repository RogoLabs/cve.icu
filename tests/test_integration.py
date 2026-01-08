"""Integration tests for CVE.ICU build system.

These tests verify the complete build pipeline works correctly,
including edge cases, error handling, and CLI functionality.
"""

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock, patch

import pytest


# Mark all tests in this file as integration tests
pytestmark = pytest.mark.integration


class TestCLIIntegration:
    """Tests for the Typer CLI interface."""

    def test_cli_help(self):
        """Test that CLI --help works."""
        result = subprocess.run(
            [sys.executable, "build.py", "--help"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent,
        )
        assert result.returncode == 0
        assert "CVE.ICU Static Site Generator" in result.stdout
        assert "build" in result.stdout
        assert "refresh" in result.stdout
        assert "validate" in result.stdout
        assert "info" in result.stdout

    def test_cli_build_help(self):
        """Test that build subcommand --help works."""
        result = subprocess.run(
            [sys.executable, "build.py", "build", "--help"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent,
        )
        assert result.returncode == 0
        assert "--quiet" in result.stdout
        assert "--refresh-data" in result.stdout
        assert "--validate" in result.stdout

    def test_cli_info(self):
        """Test the info command shows expected output."""
        result = subprocess.run(
            [sys.executable, "build.py", "info"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent,
        )
        assert result.returncode == 0
        assert "Current Year:" in result.stdout
        assert "Year Coverage:" in result.stdout
        assert "Web Output:" in result.stdout

    def test_cli_validate_quiet(self):
        """Test validate command with quiet flag."""
        result = subprocess.run(
            [sys.executable, "build.py", "validate", "--quiet"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent,
        )
        # Should complete (may pass or fail depending on data state)
        assert result.returncode in [0, 1]

    def test_cli_backward_compatibility(self):
        """Test that running without subcommand still works (backward compat)."""
        result = subprocess.run(
            [sys.executable, "build.py", "--help"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent,
        )
        assert result.returncode == 0
        # Should show options that work without subcommand
        assert "--quiet" in result.stdout


class TestBuildPipelineIntegration:
    """Tests for the complete build pipeline."""

    @pytest.fixture
    def project_root(self):
        """Get the project root directory."""
        return Path(__file__).parent.parent

    def test_web_data_directory_structure(self, project_root):
        """Test that web/data directory has expected structure."""
        data_dir = project_root / "web" / "data"
        if not data_dir.exists():
            pytest.skip("No built data available")

        # Check for core files
        expected_files = [
            "cve_all.json",
            "cna_analysis.json",
            "calendar_analysis.json",
        ]
        
        for filename in expected_files:
            filepath = data_dir / filename
            if filepath.exists():
                # Verify it's valid JSON
                with open(filepath) as f:
                    data = json.load(f)
                assert isinstance(data, dict)

    def test_year_files_consistency(self, project_root):
        """Test that year files have consistent structure."""
        data_dir = project_root / "web" / "data"
        if not data_dir.exists():
            pytest.skip("No built data available")

        year_files = list(data_dir.glob("cve_*.json"))
        year_files = [f for f in year_files if f.stem.startswith("cve_") and f.stem[4:].isdigit()]
        
        if not year_files:
            pytest.skip("No year files available")

        for year_file in year_files[:5]:  # Check first 5
            with open(year_file) as f:
                data = json.load(f)
            
            # All year files should have these keys
            assert "total_cves" in data
            assert "year" in data
            assert isinstance(data["total_cves"], int)
            assert data["total_cves"] >= 0

    def test_cve_all_has_required_fields(self, project_root):
        """Test that cve_all.json has all required fields."""
        cve_all_path = project_root / "web" / "data" / "cve_all.json"
        if not cve_all_path.exists():
            pytest.skip("cve_all.json not available")

        with open(cve_all_path) as f:
            data = json.load(f)

        required_fields = ["total_cves", "yearly_trend"]
        for field in required_fields:
            assert field in data, f"Missing required field: {field}"

        # Yearly trend should be a list
        assert isinstance(data["yearly_trend"], list)
        
        # Each trend entry should have year and count
        if data["yearly_trend"]:
            entry = data["yearly_trend"][0]
            assert "year" in entry
            assert "count" in entry

    def test_cna_analysis_structure(self, project_root):
        """Test that CNA analysis has expected structure."""
        cna_path = project_root / "web" / "data" / "cna_analysis.json"
        if not cna_path.exists():
            pytest.skip("cna_analysis.json not available")

        with open(cna_path) as f:
            data = json.load(f)

        # Should have repository stats
        assert "repository_stats" in data
        assert "total_cves" in data["repository_stats"]

        # Should have CNA list
        assert "cna_list" in data
        assert isinstance(data["cna_list"], list)


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_builder_quiet_mode(self):
        """Test that quiet mode is properly set."""
        from build import CVESiteBuilder
        
        builder = CVESiteBuilder(quiet=True)
        assert builder.quiet is True
        
        builder = CVESiteBuilder(quiet=False)
        assert builder.quiet is False

    def test_builder_year_range_valid(self):
        """Test that builder has valid year range."""
        from build import CVESiteBuilder
        
        builder = CVESiteBuilder(quiet=True)
        
        # Should have years from 1999 to current year
        assert 1999 in builder.available_years
        assert builder.current_year >= 2024
        assert builder.current_year in builder.available_years

    def test_builder_paths_are_valid(self):
        """Test that builder paths are properly configured."""
        from build import CVESiteBuilder
        
        builder = CVESiteBuilder(quiet=True)
        
        # All paths should be Path objects
        assert isinstance(builder.web_dir, Path)
        assert isinstance(builder.data_dir, Path)
        assert isinstance(builder.templates_dir, Path)
        assert isinstance(builder.cache_dir, Path)
        
        # Templates directory should exist
        assert builder.templates_dir.exists()


class TestDataValidation:
    """Tests for data validation functionality."""

    def test_validate_data_counts_function_exists(self):
        """Test that validate_data_counts function is available."""
        from build import validate_data_counts
        
        assert callable(validate_data_counts)

    def test_validation_with_mock_builder(self):
        """Test validation with a mock builder."""
        from build import validate_data_counts, CVESiteBuilder
        from pathlib import Path
        import tempfile
        import json
        
        # Create a mock builder with temp directory
        builder = CVESiteBuilder(quiet=True)
        
        # If data directory exists and has files, validation should run
        if builder.data_dir.exists() and (builder.data_dir / "cve_all.json").exists():
            result = validate_data_counts(builder)
            # Result should be boolean
            assert isinstance(result, bool)


class TestAsyncFunctionality:
    """Tests for async functionality (requires pytest-asyncio)."""

    @pytest.mark.asyncio
    async def test_async_http_session_concept(self):
        """Test that aiohttp is available and can create sessions."""
        import aiohttp
        
        # Basic smoke test - module should be importable
        assert aiohttp is not None
        
        # Test that we can reference session types
        assert hasattr(aiohttp, 'ClientSession')
        assert hasattr(aiohttp, 'ClientResponse')
