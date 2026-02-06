#!/usr/bin/env python3
"""
CVE.ICU Static Site Generator
Fixed build system that works with existing code structure
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from functools import cache
from pathlib import Path
from typing import Annotated, Any

import jinja2


# Add data folder to path for imports
sys.path.append("data")

import typer
from jinja2 import Environment, FileSystemLoader, select_autoescape
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from data.async_downloader import AsyncCVEDownloader
from data.logging_config import get_logger, setup_logging


logger = get_logger(__name__)
console = Console()

# Create Typer app
app = typer.Typer(
    name="cve-icu",
    help="CVE.ICU Static Site Generator - Build and manage vulnerability intelligence site.",
    add_completion=True,
    rich_markup_mode="rich",
    invoke_without_command=True,  # Allow running without subcommand
)


@app.callback(invoke_without_command=True)
def default_command(
    ctx: typer.Context,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Minimal output mode for CI/CD")] = False,
    refresh_data: Annotated[
        bool, typer.Option("--refresh-data", "-r", help="Download fresh CVE data before building")
    ] = False,
    force_refresh: Annotated[
        bool, typer.Option("--force-refresh", "-f", help="Force re-download even if cache is valid")
    ] = False,
    validate_flag: Annotated[bool, typer.Option("--validate", help="Validate data consistency after build")] = False,
    log_level: Annotated[str, typer.Option("--log-level", help="Logging level (DEBUG, INFO, WARNING, ERROR)")] = "INFO",
) -> None:
    """Default command - runs build if no subcommand specified.

    This maintains backward compatibility with the original CLI:
        python build.py              # Runs build
        python build.py --quiet      # Runs build in quiet mode
        python build.py build        # Explicitly runs build subcommand
    """
    # If a subcommand is being invoked, skip this callback
    if ctx.invoked_subcommand is not None:
        return

    # No subcommand - run build with the provided options
    build(
        quiet=quiet,
        refresh_data=refresh_data,
        force_refresh=force_refresh,
        validate=validate_flag,
        log_level=log_level,
    )


class CVESiteBuilder:
    """Main class for building the CVE.ICU static site"""

    def __init__(self, quiet: bool = False) -> None:
        self.quiet: bool = quiet or os.getenv("CVE_BUILD_QUIET", "").lower() in ("1", "true", "yes")
        self.current_year: int = datetime.now().year
        self.available_years: list[int] = list(range(1999, self.current_year + 1))
        self.base_dir: Path = Path(__file__).parent
        self.output_root_dir: Path = self.base_dir / "web"
        self.templates_dir: Path = self.base_dir / "templates"
        self.source_static_dir: Path = self.output_root_dir / "static"
        self.data_scripts_dir: Path = self.base_dir / "data"
        self.cache_dir: Path = self.data_scripts_dir / "cache"
        self._set_output_dirs(self.output_root_dir)

        # Set up Jinja2 environment
        self.jinja_env = Environment(
            loader=FileSystemLoader(self.templates_dir), autoescape=select_autoescape(["html", "xml"])
        )

        # Add custom filters and globals
        self.jinja_env.globals["current_year"] = self.current_year
        self.jinja_env.globals["available_years"] = self.available_years
        self.jinja_env.filters["format_number"] = self.format_number

        if not self.quiet:
            logger.info("🚀 CVE.ICU Build System Initialized")
            logger.info(f"📅 Current Year: {self.current_year}")
            logger.info(f"📊 Coverage: 1999-{self.current_year} ({len(self.available_years)} years)")
            logger.info(f"🌐 Web output: {self.web_dir}")
            logger.debug(f"📁 Data scripts: {self.data_scripts_dir}")

    def _set_output_dirs(self, web_dir: Path) -> None:
        """Update output directory paths for staged/production builds."""
        self.web_dir = web_dir
        self.static_dir = self.web_dir / "static"
        self.data_dir = self.web_dir / "data"

    def print_verbose(self, message: str) -> None:
        """Print message only if not in quiet mode"""
        if not self.quiet:
            logger.info(message)

    def print_always(self, message: str) -> None:
        """Print message regardless of quiet mode (for errors and essential info)"""
        logger.info(message)

    @staticmethod
    @cache
    def format_number(num: int | float) -> str:
        """Format numbers for display (e.g., 1000 -> 1K). Cached for performance."""
        if num >= 1000000:
            return f"{num / 1000000:.1f}M"
        elif num >= 1000:
            return f"{num / 1000:.1f}K"
        return str(num)

    def refresh_data(self, force: bool = False) -> bool:
        """Refresh CVE data from all sources using async parallel downloads.

        Downloads data from 5 sources in parallel (~3x faster than sequential):
        - NVD CVE database
        - CNA organization list
        - CNA name mappings
        - EPSS exploit prediction scores
        - CISA KEV catalog

        Args:
            force: Force re-download even if cache is valid

        Returns:
            True if all critical downloads succeeded
        """
        self.print_verbose("📥 Refreshing CVE data from all sources...")

        try:
            downloader = AsyncCVEDownloader(
                cache_dir=self.cache_dir,
                quiet=self.quiet,
            )
            results = downloader.download_all_sync(force=force)

            # Parse supplemental data
            downloader.parse_epss()
            downloader.parse_kev()

            # Check for critical failures (NVD is required)
            nvd_result = results.get("nvd")
            if not nvd_result or not nvd_result.success:
                logger.error("❌ NVD download failed - cannot proceed")
                return False

            # Log summary
            successful = sum(1 for r in results.values() if r.success)
            self.print_verbose(f"✅ Data refresh complete: {successful}/{len(results)} sources")

            return True

        except ImportError as e:
            logger.warning(f"⚠️  Async downloads unavailable: {e}")
            logger.info("   Install httpx for parallel downloads: pip install httpx")
            return True  # Continue with existing cache
        except Exception as e:
            logger.error(f"❌ Data refresh failed: {e}")
            return False

    def clean_build(self) -> None:
        """Clean and recreate the active output directory."""
        self.print_verbose("🧹 Cleaning web directory...")

        if self.web_dir.exists():
            shutil.rmtree(self.web_dir)

        self.web_dir.mkdir(parents=True, exist_ok=True)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.print_verbose("✅ Web directory cleaned and recreated")

    def ensure_static_assets(self) -> None:
        """Ensure static assets are in place"""
        self.print_verbose("📁 Checking static assets...")

        if not self.static_dir.exists():
            if self.source_static_dir.exists() and self.static_dir != self.source_static_dir:
                self.print_verbose("📦 Copying static assets into staged output...")
                shutil.copytree(self.source_static_dir, self.static_dir)
            else:
                self.print_verbose("⚠️  Warning: Static directory not found, creating...")
                self.static_dir.mkdir(parents=True, exist_ok=True)

        # Check for required files
        required_files = ["css/style.css", "js/chart.min.js", "images/logo.png"]

        for file_path in required_files:
            full_path = self.static_dir / file_path
            if full_path.exists():
                self.print_verbose(f"  ✅ Found {file_path}")
            else:
                self.print_verbose(f"  ⚠️  Missing {file_path}")

        # Preserve root-level deployment files (for example GitHub Pages custom domain).
        for root_file_name in ["CNAME"]:
            source_root_file = self.output_root_dir / root_file_name
            destination_root_file = self.web_dir / root_file_name
            if source_root_file.exists():
                shutil.copy2(source_root_file, destination_root_file)
                self.print_verbose(f"  ✅ Preserved {root_file_name}")

        self.print_verbose("✅ Static assets check complete")

    def validate_build_outputs(self) -> None:
        """Validate critical artifacts before publishing staged output."""
        required_html = [
            "index.html",
            "years.html",
            "cna-hub.html",
            "cna.html",
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
        required_json = [
            "cna_analysis.json",
            "cna_analysis_current_year.json",
            "cpe_analysis.json",
            "cpe_analysis_current_year.json",
            "cvss_analysis.json",
            "cvss_analysis_current_year.json",
            "cwe_analysis.json",
            "cwe_analysis_current_year.json",
            "calendar_analysis.json",
            "calendar_analysis_current_year.json",
            "growth_analysis.json",
            "yearly_summary.json",
            "cve_all.json",
            "epss_analysis.json",
            "kev_analysis.json",
            "risk_matrix.json",
            "scoring_comparison.json",
            "data_quality.json",
            "homepage_summary.json",
        ]

        missing_html = [name for name in required_html if not (self.web_dir / name).exists()]
        missing_json = [name for name in required_json if not (self.data_dir / name).exists()]
        if missing_html or missing_json:
            missing = ", ".join([*missing_html, *[f"data/{name}" for name in missing_json]])
            raise RuntimeError(f"Missing required build artifacts: {missing}")

    def publish_staged_site(self, staged_web_dir: Path) -> None:
        """Atomically replace production web output with staged build."""
        final_web_dir = self.output_root_dir
        backup_web_dir = self.base_dir / ".web_backup"

        if backup_web_dir.exists():
            shutil.rmtree(backup_web_dir)

        if final_web_dir.exists():
            final_web_dir.rename(backup_web_dir)

        try:
            staged_web_dir.rename(final_web_dir)
        except OSError as exc:
            if backup_web_dir.exists() and not final_web_dir.exists():
                backup_web_dir.rename(final_web_dir)
            raise RuntimeError(f"Failed to publish staged site: {exc}") from exc
        else:
            if backup_web_dir.exists():
                shutil.rmtree(backup_web_dir)

    def generate_year_data_json(self) -> list[dict[str, Any]]:
        """Generate JSON data files for all available years"""
        self.print_verbose("📊 Generating year data JSON files...")

        try:
            # Import the real CVE years analyzer
            from cve_years import CVEYearsAnalyzer

            self.print_verbose("🔽 Initializing CVE data processing...")
            analyzer = CVEYearsAnalyzer(quiet=self.quiet)

            # Generate data for all years
            all_year_data = []

            for year in self.available_years:
                self.print_verbose(f"  📅 Processing year {year}...")

                try:
                    # Use the real analyzer to get year data
                    year_data = analyzer.get_year_data(year)

                    if year_data:
                        # Save individual year file
                        year_file = self.data_dir / f"cve_{year}.json"
                        with open(year_file, "w") as f:
                            json.dump(year_data, f, indent=2, default=str)

                        all_year_data.append(year_data)
                        self.print_verbose(
                            f"    ✅ Generated cve_{year}.json ({year_data.get('total_cves', 0):,} CVEs)"
                        )
                    else:
                        self.print_verbose(f"    ⚠️  Skipped {year} - no data available")

                except (KeyError, json.JSONDecodeError, OSError) as e:
                    self.print_always(f"  ❌ Failed to process {year}: {e}")
                    continue

            self.print_always(f"✅ Generated {len(all_year_data)} year data files")
            return all_year_data

        except ImportError as e:
            logger.error(f"❌ Failed to import CVE years analyzer: {e}")
            logger.info("📝 Creating minimal data as fallback...")
            return self.create_minimal_year_data()
        except (json.JSONDecodeError, OSError, KeyError) as e:
            logger.error(f"❌ Error generating year data: {e}")
            self.print_verbose("📝 Creating minimal data as fallback...")
            return self.create_minimal_year_data()

    def create_minimal_year_data(self) -> list[dict[str, Any]]:
        """Create minimal year data for basic functionality"""
        self.print_verbose("📝 Creating minimal year data for basic functionality...")
        all_year_data: list[dict[str, Any]] = []

        for year in self.available_years:
            year_data = {
                "year": year,
                "total_cves": max(100, (year - 1999) * 500),
                "date_data": {
                    "monthly_distribution": {str(i): max(10, (year - 1999) * 5) for i in range(1, 13)},
                    "daily_analysis": {
                        "total_days": 365,
                        "days_with_cves": min(365, max(50, (year - 1999) * 10)),
                        "avg_cves_per_day": max(1, (year - 1999) * 1.5),
                        "max_cves_in_day": max(5, (year - 1999) * 3),
                        "daily_counts": {},
                    },
                },
            }

            # Save individual year file
            year_file = self.data_dir / f"cve_{year}.json"
            with open(year_file, "w") as f:
                json.dump(year_data, f, indent=2)

            all_year_data.append(year_data)

        logger.info(f"✅ Generated {len(all_year_data)} minimal year data files")
        return all_year_data

    def generate_combined_analysis_json(self, all_year_data: list[dict[str, Any]]) -> dict[str, str]:
        """Generate combined analysis JSON files"""
        logger.info("📊 Generating combined analysis JSON files...")

        # Generate comprehensive CNA analysis using CVE V5 as authoritative source
        try:
            from cve_v5_processor import CVEV5Processor

            if not self.quiet:
                logger.info("  🏢 Generating comprehensive CNA analysis from CVE V5 data...")
            v5_processor = CVEV5Processor(self.base_dir, self.cache_dir, self.data_dir, quiet=self.quiet)
            cna_analysis = v5_processor.generate_comprehensive_cna_analysis()

            if cna_analysis:
                if not self.quiet:
                    logger.info(
                        f"  ✅ Generated cna_analysis.json with {cna_analysis['total_cnas']} CNAs (CVE V5 authoritative)"
                    )
            else:
                logger.error("  ❌ CVE V5 CNA analysis failed")

        except (ImportError, json.JSONDecodeError, OSError, subprocess.SubprocessError) as e:
            logger.error(f"  ❌ Error generating CVE V5 CNA analysis: {e}")
            import traceback

            traceback.print_exc()
            logger.warning("  ⚠️  CNA analysis will be missing")

        # Generate current year CNA analysis using CVE V5 data
        try:
            from cve_v5_processor import CVEV5Processor

            if not self.quiet:
                logger.info("  🗓️  Generating current year CNA analysis from CVE V5 data...")
            v5_processor = CVEV5Processor(self.base_dir, self.cache_dir, self.data_dir, quiet=self.quiet)
            current_cna_analysis = v5_processor.generate_current_year_analysis()

            if current_cna_analysis:
                if not self.quiet:
                    logger.info(
                        f"  ✅ Generated cna_analysis_current_year.json with {current_cna_analysis['total_cnas']} CNAs (CVE V5 authoritative)"
                    )
            else:
                logger.error("  ❌ CVE V5 current year analysis failed")

        except (ImportError, json.JSONDecodeError, OSError, subprocess.SubprocessError) as e:
            logger.error(f"  ❌ Error generating CVE V5 current year CNA analysis: {e}")
            import traceback

            traceback.print_exc()
            logger.warning("  ⚠️  Current year CNA analysis will be missing")

        # Fall back to NVD-based CNA analysis if CVE V5 artifacts are unavailable.
        if not (self.data_dir / "cna_analysis.json").exists() or not (
            self.data_dir / "cna_analysis_current_year.json"
        ).exists():
            self.generate_cna_analysis_fallback(all_year_data)

        # Generate CPE analysis
        try:
            from cpe_analysis import CPEAnalyzer

            if not self.quiet:
                logger.info("  🔍 Generating comprehensive CPE analysis...")
            cpe_analyzer = CPEAnalyzer(self.base_dir, self.cache_dir, self.data_dir, quiet=self.quiet)
            cpe_analysis = cpe_analyzer.generate_cpe_analysis(all_year_data)

            if cpe_analysis:
                if not self.quiet:
                    logger.info(
                        f"  ✅ Generated cpe_analysis.json with {cpe_analysis['total_unique_cpes']:,} unique CPEs"
                    )
            else:
                logger.error("  ❌ CPE analysis failed")

        except (ImportError, json.JSONDecodeError, OSError) as e:
            logger.error(f"  ❌ Error generating CPE analysis: {e}")
            import traceback

            traceback.print_exc()
            logger.warning("  ⚠️  CPE analysis will be missing")

        # Generate current year CPE analysis
        try:
            from cpe_analysis import CPEAnalyzer

            if not self.quiet:
                logger.info("  📅 Generating current year CPE analysis...")
            cpe_analyzer = CPEAnalyzer(self.base_dir, self.cache_dir, self.data_dir, quiet=self.quiet)
            current_year_data = next((data for data in all_year_data if data["year"] == datetime.now().year), {})
            current_cpe_analysis = cpe_analyzer.generate_current_year_cpe_analysis(current_year_data)

            if current_cpe_analysis:
                if not self.quiet:
                    logger.info(
                        f"  ✅ Generated cpe_analysis_current_year.json with {current_cpe_analysis['total_unique_cpes']:,} unique CPEs"
                    )
            else:
                logger.error("  ❌ Current year CPE analysis failed")

        except (ImportError, json.JSONDecodeError, OSError, KeyError) as e:
            logger.error(f"  ❌ Error generating current year CPE analysis: {e}")
            import traceback

            traceback.print_exc()
            logger.warning("  ⚠️  Current year CPE analysis will be missing")

        # Generate CVSS analysis
        try:
            from cvss_analysis import CVSSAnalyzer

            if not self.quiet:
                logger.info("  📊 Generating comprehensive CVSS analysis...")
            cvss_analyzer = CVSSAnalyzer(self.base_dir, self.cache_dir, self.data_dir, quiet=self.quiet)
            cvss_analysis = cvss_analyzer.generate_cvss_analysis(all_year_data)

            if cvss_analysis:
                if not self.quiet:
                    logger.info("  ✅ Comprehensive CVSS analysis generated")
            else:
                logger.error("  ❌ Comprehensive CVSS analysis failed")

        except (ImportError, json.JSONDecodeError, OSError) as e:
            logger.error(f"  ❌ Error generating comprehensive CVSS analysis: {e}")
            import traceback

            traceback.print_exc()
            logger.warning("  ⚠️  Comprehensive CVSS analysis will be missing")

        # Generate current year CVSS analysis
        try:
            current_year_data = next((d for d in all_year_data if d.get("year") == self.current_year), None)
            if current_year_data:
                if not self.quiet:
                    logger.info("  📅 Generating current year CVSS analysis...")
                current_year_cvss_analysis = cvss_analyzer.generate_current_year_cvss_analysis(current_year_data)

                if current_year_cvss_analysis:
                    if not self.quiet:
                        logger.info("  ✅ Current year CVSS analysis generated")
                else:
                    logger.error("  ❌ Current year CVSS analysis failed")
            else:
                logger.warning(f"  ⚠️  No data found for current year {self.current_year}")

        except (ImportError, json.JSONDecodeError, OSError, KeyError) as e:
            logger.error(f"  ❌ Error generating current year CVSS analysis: {e}")
            import traceback

            traceback.print_exc()
            logger.warning("  ⚠️  Current year CVSS analysis will be missing")

        # Generate CWE analysis
        try:
            from cwe_analysis import CWEAnalyzer

            if not self.quiet:
                logger.info("  🔍 Generating comprehensive CWE analysis...")
            cwe_analyzer = CWEAnalyzer(self.base_dir, self.cache_dir, self.data_dir, quiet=self.quiet)
            cwe_analysis = cwe_analyzer.generate_cwe_analysis(all_year_data)

            if cwe_analysis:
                if not self.quiet:
                    logger.info(
                        f"  ✅ Generated cwe_analysis.json with {cwe_analysis['total_unique_cwes']} unique CWEs"
                    )
            else:
                logger.error("  ❌ CWE analysis failed")

        except (ImportError, json.JSONDecodeError, OSError) as e:
            logger.error(f"  ❌ Error generating CWE analysis: {e}")
            import traceback

            traceback.print_exc()
            logger.warning("  ⚠️  CWE analysis will be missing")

        # Generate current year CWE analysis
        try:
            current_year_data = next((d for d in all_year_data if d.get("year") == self.current_year), None)
            if current_year_data:
                if not self.quiet:
                    logger.info("  📅 Generating current year CWE analysis...")
                current_year_cwe_analysis = cwe_analyzer.generate_current_year_cwe_analysis(current_year_data)

                if current_year_cwe_analysis:
                    if not self.quiet:
                        logger.info(
                            f"  ✅ Generated cwe_analysis_current_year.json with {current_year_cwe_analysis['total_unique_cwes']} unique CWEs"
                        )
                else:
                    logger.error("  ❌ Current year CWE analysis failed")
            else:
                logger.warning(f"  ⚠️  No data found for current year {self.current_year}")

        except (ImportError, json.JSONDecodeError, OSError, KeyError) as e:
            logger.error(f"  ❌ Error generating current year CWE analysis: {e}")
            import traceback

            traceback.print_exc()
            logger.warning("  ⚠️  Current year CWE analysis will be missing")

        # Generate Calendar analysis
        try:
            from calendar_analysis import CalendarAnalyzer

            if not self.quiet:
                logger.info("  📅 Generating comprehensive calendar analysis...")
            calendar_analyzer = CalendarAnalyzer(self.base_dir, self.cache_dir, self.data_dir, quiet=self.quiet)
            calendar_analysis = calendar_analyzer.generate_calendar_analysis()

            if calendar_analysis:
                if not self.quiet:
                    logger.info(
                        f"  ✅ Generated calendar_analysis.json with {calendar_analysis['metadata']['total_days']:,} days of data"
                    )
            else:
                logger.error("  ❌ Calendar analysis failed")

        except (ImportError, json.JSONDecodeError, OSError) as e:
            logger.error(f"  ❌ Error generating calendar analysis: {e}")
            import traceback

            traceback.print_exc()
            logger.warning("  ⚠️  Calendar analysis will be missing")

        # Generate current year calendar analysis
        try:
            current_year_calendar_analysis = calendar_analyzer.generate_current_year_calendar_analysis()

            if current_year_calendar_analysis:
                logger.info(
                    f"  ✅ Generated calendar_analysis_current_year.json with {current_year_calendar_analysis['metadata']['total_days']:,} days"
                )
            else:
                logger.error("  ❌ Current year calendar analysis failed")

        except (ImportError, json.JSONDecodeError, OSError, KeyError) as e:
            logger.error(f"  ❌ Error generating current year calendar analysis: {e}")
            import traceback

            traceback.print_exc()
            logger.warning("  ⚠️  Current year calendar analysis will be missing")

        # Generate growth analysis
        try:
            from yearly_analysis import YearlyAnalyzer

            logger.info("  📈 Generating growth analysis...")
            yearly_analyzer = YearlyAnalyzer(self.base_dir, self.cache_dir, self.data_dir)
            growth_analysis = yearly_analyzer.generate_growth_analysis(all_year_data)

            if growth_analysis:
                logger.info("  ✅ Growth analysis generated")
            else:
                logger.error("  ❌ Growth analysis failed")

        except (ImportError, json.JSONDecodeError, OSError) as e:
            logger.error(f"  ❌ Error generating growth analysis: {e}")
            import traceback

            traceback.print_exc()
            logger.warning("  ⚠️  Growth analysis will be missing")

        # Generate scoring analysis (EPSS, KEV, Risk Matrix)
        try:
            from scoring_analysis import ScoringAnalyzer

            logger.info("  🎯 Generating scoring analysis (EPSS, KEV, Risk Matrix)...")
            scoring_analyzer = ScoringAnalyzer(self.base_dir, self.cache_dir, self.data_dir)
            scoring_results = scoring_analyzer.generate_all_scoring_analysis()

            if scoring_results:
                logger.info(f"  ✅ Scoring analysis generated: {', '.join(scoring_results.keys())}")
            else:
                logger.error("  ❌ Scoring analysis failed")

        except (ImportError, json.JSONDecodeError, OSError) as e:
            logger.error(f"  ❌ Error generating scoring analysis: {e}")
            import traceback

            traceback.print_exc()
            logger.warning("  ⚠️  Scoring analysis will be missing")

        # Generate cve_all.json from year data
        self.generate_cve_all_json(all_year_data)
        self.generate_homepage_summary_json(all_year_data)

        logger.info("✅ Combined analysis JSON files generated")

        return {
            "cna_analysis": "generated",
            "cpe_analysis": "generated",
            "cvss_analysis": "generated",
            "cwe_analysis": "generated",
            "calendar_analysis": "generated",
            "growth_analysis": "generated",
            "cve_all": "generated",
            "homepage_summary": "generated",
        }

    def _read_json_file(self, file_name: str, default: Any) -> Any:
        """Read a JSON file from the output data directory with graceful fallback."""
        file_path = self.data_dir / file_name
        if not file_path.exists():
            logger.warning(f"  ⚠️  Missing {file_name}, using defaults for homepage summary")
            return default

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"  ⚠️  Could not read {file_name} ({e}), using defaults for homepage summary")
            return default

    def generate_homepage_summary_json(self, all_year_data: list[dict[str, Any]]) -> None:
        """Generate a compact aggregate payload for homepage charts and stat cards."""
        logger.info("  🏠 Generating homepage_summary.json...")

        # Build compact yearly totals directly from generated year data.
        yearly_summary_years: dict[str, dict[str, Any]] = {}
        for year_data in sorted(all_year_data, key=lambda x: x.get("year", 0)):
            year = year_data.get("year")
            if not isinstance(year, int):
                continue
            yearly_summary_years[str(year)] = {
                "year": year,
                "total_cves": year_data.get("total_cves", 0),
            }

        growth_analysis_raw = self._read_json_file("growth_analysis.json", {})
        cvss_analysis_raw = self._read_json_file("cvss_analysis.json", {})
        epss_analysis_raw = self._read_json_file("epss_analysis.json", {})
        kev_analysis_raw = self._read_json_file("kev_analysis.json", {})
        cwe_analysis_raw = self._read_json_file("cwe_analysis.json", {})
        cna_analysis_raw = self._read_json_file("cna_analysis.json", {})
        cpe_analysis_raw = self._read_json_file("cpe_analysis.json", {})
        calendar_current_year_raw = self._read_json_file("calendar_analysis_current_year.json", {})

        homepage_summary = {
            "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "current_year": self.current_year,
            "yearly_summary": {
                "years": yearly_summary_years,
            },
            "growth_analysis": {
                "growth_data": growth_analysis_raw.get("growth_data", []),
            },
            "cvss_analysis": {
                "score_distribution": cvss_analysis_raw.get("score_distribution", {}),
                "kev_global_count": cvss_analysis_raw.get("kev_global_count", 0),
            },
            "epss_analysis": {
                "statistics": epss_analysis_raw.get("statistics", {}),
                "total_cves_with_epss": epss_analysis_raw.get("total_cves_with_epss", 0),
            },
            "kev_analysis": {
                "statistics": kev_analysis_raw.get("statistics", {}),
                "by_year_added": kev_analysis_raw.get("by_year_added", {}),
                "by_year_published": kev_analysis_raw.get("by_year_published", {}),
            },
            "cwe_analysis": {
                "top_cwes": cwe_analysis_raw.get("top_cwes", [])[:10],
            },
            "cna_analysis": {
                "cna_list": cna_analysis_raw.get("cna_list", [])[:25],
            },
            "cpe_analysis": {
                "top_cpes": cpe_analysis_raw.get("top_cpes", [])[:25],
            },
            "calendar_analysis_current_year": {
                "daily_data": calendar_current_year_raw.get("daily_data", []),
            },
        }

        output_file = self.data_dir / "homepage_summary.json"
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(homepage_summary, f, indent=2)

        logger.info("  ✅ Generated homepage_summary.json")

    def generate_cna_analysis_fallback(self, all_year_data: list[dict[str, Any]]) -> None:
        """Fallback CNA generation using cached NVD data when CVE V5 data is unavailable."""
        logger.warning("  ⚠️  Falling back to NVD-based CNA analysis")
        try:
            from cna_analysis import CNAAnalyzer

            cna_analyzer = CNAAnalyzer(self.base_dir, self.cache_dir, self.data_dir, quiet=self.quiet)
            comprehensive = cna_analyzer.generate_comprehensive_cna_analysis(all_year_data)
            cna_list = comprehensive.get("cna_list", [])
            fallback_total = sum(cna.get("count", 0) for cna in cna_list)
            comprehensive["repository_stats"] = {
                "total_cves": fallback_total,
                "source": "nvd_fallback",
            }

            # Persist normalized fallback metadata for downstream validation.
            with open(self.data_dir / "cna_analysis.json", "w", encoding="utf-8") as f:
                json.dump(comprehensive, f, indent=2)

            current_year_data = next((data for data in all_year_data if data.get("year") == self.current_year), {})
            current_year = cna_analyzer.generate_current_year_cna_analysis(current_year_data)

            logger.info(
                "  ✅ Fallback CNA analysis generated: "
                f"{comprehensive.get('total_cnas', 0)} total CNAs, "
                f"{current_year.get('total_cnas', 0)} current-year CNAs, "
                f"{fallback_total:,} total CVEs"
            )
        except (ImportError, json.JSONDecodeError, OSError, KeyError, TypeError) as e:
            logger.error(f"  ❌ Fallback CNA analysis failed: {e}")

    def _write_fallback_data_quality_json(self, reason: str) -> None:
        """Write a minimal data_quality.json payload when detailed analysis cannot be generated."""
        fallback_data = {
            "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "status": "fallback",
            "reason": reason,
            "stats": {
                "total_cnas_in_analysis": 0,
                "exact_matches": 0,
                "case_mismatches": 0,
                "org_name_matches": 0,
                "normalized_matches": 0,
                "partial_matches": 0,
                "unmatched": 0,
                "case_mismatch_cves": 0,
                "org_name_match_cves": 0,
                "normalized_match_cves": 0,
                "partial_match_cves": 0,
                "unmatched_cves": 0,
            },
            "case_mismatches": [],
            "org_name_matches": [],
            "normalized_matches": [],
            "partial_matches": [],
            "unmatched": [],
        }

        output_file = self.data_dir / "data_quality.json"
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(fallback_data, f, indent=2)

        logger.warning(f"  ⚠️  Wrote fallback data_quality.json ({reason})")

    def generate_cve_all_json(self, all_year_data: list[dict[str, Any]]) -> None:
        """Generate overall CVE statistics across all years"""
        logger.info("  📊 Generating cve_all.json...")

        if not all_year_data:
            logger.warning("  ⚠️  No year data available")
            return

        # Calculate totals
        total_cves = sum(year_data.get("total_cves", 0) for year_data in all_year_data)
        years_with_data = len(all_year_data)

        # Find peak year
        peak_year_data = max(all_year_data, key=lambda x: x.get("total_cves", 0))
        peak_year = peak_year_data.get("year", self.current_year)
        peak_count = peak_year_data.get("total_cves", 0)

        # Calculate YOY growth (current vs previous year)
        current_year_data = next((d for d in all_year_data if d.get("year") == self.current_year), None)
        prev_year_data = next((d for d in all_year_data if d.get("year") == self.current_year - 1), None)

        yoy_growth = 0
        if current_year_data and prev_year_data:
            current_count = current_year_data.get("total_cves", 0)
            prev_count = prev_year_data.get("total_cves", 0)
            if prev_count > 0:
                yoy_growth = ((current_count - prev_count) / prev_count) * 100

        # Create yearly trend data using list comprehension
        yearly_data = [
            {"year": year_data.get("year"), "count": year_data.get("total_cves", 0)}
            for year_data in sorted(all_year_data, key=lambda x: x.get("year", 0))
        ]

        cve_all_data = {
            "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "total_cves": total_cves,
            "years_covered": years_with_data,
            "current_year": self.current_year,
            "current_year_cves": current_year_data.get("total_cves", 0) if current_year_data else 0,
            "peak_year": peak_year,
            "peak_count": peak_count,
            "yoy_growth_rate": round(yoy_growth, 1),
            "yearly_trend": yearly_data,
        }

        # Save to file
        output_file = self.data_dir / "cve_all.json"
        with open(output_file, "w") as f:
            json.dump(cve_all_data, f, indent=2)

        logger.info(f"  ✅ Generated cve_all.json with {total_cves:,} total CVEs")

        # Also generate yearly_summary.json for efficient loading
        self.generate_yearly_summary_json(all_year_data)

    def generate_yearly_summary_json(self, all_year_data: list[dict[str, Any]]) -> None:
        """Generate consolidated yearly summary for efficient single-file loading.

        This file contains all the data needed by years.html in one request,
        avoiding 27 separate HTTP requests for individual year files.
        """
        logger.info("  📊 Generating yearly_summary.json...")

        if not all_year_data:
            logger.warning("  ⚠️  No year data available for summary")
            return

        # Build summary structure with everything years.html needs
        summary = {"generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"), "years": {}}

        for year_data in sorted(all_year_data, key=lambda x: x.get("year", 0)):
            year = year_data.get("year")
            if not year:
                continue

            # Extract just the aggregates needed for charts (skip daily_counts)
            year_summary = {
                "year": year,
                "total_cves": year_data.get("total_cves", 0),
                "date_data": {
                    "monthly_distribution": year_data.get("date_data", {}).get("monthly_distribution", {}),
                    "daily_analysis": {
                        "total_days": year_data.get("date_data", {}).get("daily_analysis", {}).get("total_days", 0),
                        "avg_per_day": year_data.get("date_data", {}).get("daily_analysis", {}).get("avg_per_day", 0),
                        "highest_day": year_data.get("date_data", {}).get("daily_analysis", {}).get("highest_day", {}),
                        "lowest_day": year_data.get("date_data", {}).get("daily_analysis", {}).get("lowest_day", {}),
                        # Note: daily_counts omitted to save ~300KB
                    },
                },
                "cvss": year_data.get("cvss", {}),
                "kev": year_data.get("kev", {}),
                "vendors": year_data.get("vendors", {}),
                "cwe": year_data.get("cwe", {}),
                "metadata": year_data.get("metadata", {}),
            }

            summary["years"][year] = year_summary

        output_file = self.data_dir / "yearly_summary.json"
        with open(output_file, "w") as f:
            json.dump(summary, f)  # No indent for smaller file size

        # Calculate file size
        file_size = output_file.stat().st_size / 1024
        logger.info(f"  ✅ Generated yearly_summary.json ({file_size:.1f}KB, {len(summary['years'])} years)")

    def generate_current_year_analysis_json(self, all_year_data: list[dict[str, Any]]) -> dict[str, str]:
        """Generate current year specific analysis files"""
        logger.debug(f"🗓️  Current year ({self.current_year}) analysis already handled in combined analysis")

        # Current year analysis is now handled in generate_combined_analysis_json
        # This method is kept for compatibility but doesn't need to do anything

        return {"cna_current": "handled_in_combined_analysis"}

    def generate_data_quality_json(self) -> None:
        """Generate data quality analysis JSON using CNAScorecard-style name matching"""
        logger.info("🔍 Generating data quality analysis...")

        output_env_key = "CVE_OUTPUT_DATA_DIR"
        previous_output_env = os.environ.get(output_env_key)
        os.environ[output_env_key] = str(self.data_dir)

        try:
            # Import and run the rebuild_data_quality script
            import sys

            script_dir = self.base_dir / "data" / "scripts"
            if str(script_dir) not in sys.path:
                sys.path.insert(0, str(script_dir))

            # Import the module
            import importlib.util

            spec = importlib.util.spec_from_file_location(
                "rebuild_data_quality", script_dir / "rebuild_data_quality.py"
            )
            if spec is None or spec.loader is None:
                raise ImportError("Could not load rebuild_data_quality module")
            rebuild_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(rebuild_module)

            # Run the main function (it handles its own output)
            rebuild_module.main()

            output_file = self.data_dir / "data_quality.json"
            if output_file.exists():
                logger.info("  ✅ Data quality analysis generated")
            else:
                self._write_fallback_data_quality_json("rebuild script completed without output")

        except FileNotFoundError:
            logger.warning("  ⚠️  rebuild_data_quality.py not found, skipping data quality analysis")
            self._write_fallback_data_quality_json("rebuild_data_quality.py not found")
        except SystemExit as e:
            logger.warning(f"  ⚠️  Data quality script exited early ({e}), skipping data quality analysis")
            self._write_fallback_data_quality_json(f"data quality script exited early ({e})")
        except (ImportError, OSError) as e:
            logger.warning(f"  ⚠️  Error generating data quality: {e}")
            self._write_fallback_data_quality_json(f"data quality generation error: {e}")
        finally:
            if previous_output_env is None:
                os.environ.pop(output_env_key, None)
            else:
                os.environ[output_env_key] = previous_output_env

    def generate_html_pages(self) -> None:
        """Generate HTML pages from templates"""
        self.print_verbose("📄 Generating HTML pages...")

        # Define pages to generate
        pages = [
            {"template": "index.html", "output": "index.html", "title": "CVE Intelligence Dashboard"},
            {"template": "years.html", "output": "years.html", "title": "Yearly Analysis"},
            {"template": "cna-hub.html", "output": "cna-hub.html", "title": "CNA Intelligence Hub"},
            {"template": "cna.html", "output": "cna.html", "title": "CNA Intelligence Dashboard"},
            {"template": "cpe.html", "output": "cpe.html", "title": "CPE Analysis"},
            {"template": "cvss.html", "output": "cvss.html", "title": "CVSS Analysis"},
            {"template": "cwe.html", "output": "cwe.html", "title": "CWE Analysis"},
            {"template": "calendar.html", "output": "calendar.html", "title": "Calendar View"},
            {"template": "growth.html", "output": "growth.html", "title": "Growth Analysis"},
            {"template": "scoring.html", "output": "scoring.html", "title": "Scoring Hub"},
            {"template": "epss.html", "output": "epss.html", "title": "EPSS Analysis"},
            {"template": "kev.html", "output": "kev.html", "title": "KEV Analysis"},
            {"template": "data-quality.html", "output": "data-quality.html", "title": "CNA Name Matching"},
            {"template": "about.html", "output": "about.html", "title": "About CVE.ICU"},
        ]

        # Generate each page
        for page in pages:
            try:
                template = self.jinja_env.get_template(page["template"])

                context = {
                    "title": f"{page['title']} - CVE.ICU",
                    "current_year": self.current_year,
                    "available_years": self.available_years,
                }

                html_content = template.render(**context)

                with open(self.web_dir / page["output"], "w") as f:
                    f.write(html_content)

                self.print_verbose(f"  📄 Generated {page['output']}")

            except (jinja2.TemplateError, OSError) as e:
                self.print_always(f"  ❌ Error generating {page['output']}: {e}")

        self.print_always("✅ HTML pages generated successfully")

    def build_site(self, refresh_data: bool = False, force_refresh: bool = False) -> bool:
        """Main build function - orchestrates the entire build process

        Args:
            refresh_data: If True, refresh CVE data before building
            force_refresh: If True, force re-download even if cache is valid
        """
        self.print_always("\n🏗️  Starting CVE.ICU site build...")
        if not self.quiet:
            logger.info("=" * 50)

        staged_web_dir = Path(tempfile.mkdtemp(prefix=".web_build_", dir=self.base_dir))
        self._set_output_dirs(staged_web_dir)

        try:
            # Step 0: Optionally refresh data from upstream sources
            if refresh_data and not self.refresh_data(force=force_refresh):
                logger.error("❌ Data refresh failed, cannot continue build")
                return False

            # Step 1: Clean build directory
            self.clean_build()

            # Step 2: Ensure static assets are in place
            self.ensure_static_assets()

            # Step 3: Generate JSON data files
            all_year_data = self.generate_year_data_json()

            if not all_year_data:
                logger.error("❌ No year data generated, cannot continue build")
                return False

            # Step 4: Generate combined analysis JSON files
            combined_analysis = self.generate_combined_analysis_json(all_year_data)

            # Step 5: Generate current year analysis files
            current_year_analysis = self.generate_current_year_analysis_json(all_year_data)

            # Step 6: Generate data quality analysis
            self.generate_data_quality_json()

            # Step 7: Generate HTML pages
            self.generate_html_pages()

            # Step 8: Validate generated artifacts before publishing
            self.validate_build_outputs()

            # Step 9: Atomically publish staged output
            self.publish_staged_site(staged_web_dir)
            self._set_output_dirs(self.output_root_dir)

            if not self.quiet:
                logger.info("\n" + "=" * 50)
            self.print_always("✅ Build completed successfully!")
            if not self.quiet:
                logger.info(f"📁 Site generated in: {self.web_dir}")
                logger.info("🌐 Ready for deployment")
                logger.info(f"📊 Coverage: {len(self.available_years)} years (1999-{self.current_year})")
                logger.info(f"📊 Year data files: {len(all_year_data)} years processed")
                logger.debug(f"🏢 CNA Analysis: {combined_analysis.get('cna_analysis', 'processed')}")
                logger.debug(f"📈 CVE All data: {combined_analysis.get('cve_all', 'processed')}")
                logger.debug(f"🗓️  Current year analysis: {current_year_analysis.get('cna_current', 'processed')}")

            return True

        except (ImportError, json.JSONDecodeError, OSError, RuntimeError, jinja2.TemplateError) as e:
            logger.error(f"\n❌ Build failed: {e}")
            if not self.quiet:
                import traceback

                traceback.print_exc()
            return False
        finally:
            self._set_output_dirs(self.output_root_dir)
            if staged_web_dir.exists():
                shutil.rmtree(staged_web_dir, ignore_errors=True)


def main() -> None:
    """Main entry point - delegates to Typer CLI"""
    app()


@app.command()
def build(
    quiet: Annotated[
        bool, typer.Option("--quiet", "-q", help="Minimal output mode - reduces verbosity for CI/CD environments")
    ] = False,
    refresh_data: Annotated[
        bool, typer.Option("--refresh-data", "-r", help="Download fresh CVE data from all sources before building")
    ] = False,
    force_refresh: Annotated[
        bool,
        typer.Option(
            "--force-refresh", "-f", help="Force re-download even if cache is valid (requires --refresh-data)"
        ),
    ] = False,
    validate: Annotated[
        bool, typer.Option("--validate", help="Validate data counting consistency after build")
    ] = False,
    log_level: Annotated[str, typer.Option("--log-level", help="Logging level")] = "INFO",
) -> None:
    """Build the CVE.ICU static site.

    This is the main build command that generates all HTML pages
    and JSON data files for the CVE.ICU vulnerability intelligence site.

    Examples:
        python build.py build              # Normal verbose output
        python build.py build --quiet      # Minimal output for CI/CD
        python build.py build --refresh-data  # Download fresh data before build
        python build.py build --refresh-data --force-refresh  # Force re-download
        python build.py build --validate   # Validate data consistency
    """
    # Validate log level
    valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR"]
    if log_level.upper() not in valid_levels:
        console.print(f"[red]Invalid log level: {log_level}. Must be one of {valid_levels}[/red]")
        raise typer.Exit(1)

    # Setup logging based on args
    if quiet:
        setup_logging(level="WARNING")
    else:
        setup_logging(level=log_level.upper())

    builder = CVESiteBuilder(quiet=quiet)
    success = builder.build_site(
        refresh_data=refresh_data,
        force_refresh=force_refresh,
    )

    if success and validate:
        logger.info("\n🔍 Running data validation...")
        if not validate_data_counts(builder):
            console.print("[red]❌ Validation failed[/red]")
            raise typer.Exit(1)
        console.print("[green]✅ Validation passed[/green]")

    if not success:
        raise typer.Exit(1)


@app.command()
def refresh(
    force: Annotated[bool, typer.Option("--force", "-f", help="Force re-download even if cache is valid")] = False,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Minimal output mode")] = False,
) -> None:
    """Download fresh CVE data from all sources.

    Downloads data from 5 sources in parallel (~3x faster than sequential):
    - NVD CVE database
    - CNA organization list
    - CNA name mappings
    - EPSS exploit prediction scores
    - KEV (Known Exploited Vulnerabilities)
    """
    if quiet:
        setup_logging(level="WARNING")
    else:
        setup_logging(level="INFO")

    builder = CVESiteBuilder(quiet=quiet)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task(description="Downloading CVE data...", total=None)
        success = builder.refresh_data(force=force)

    if success:
        console.print("[green]✅ Data refresh completed successfully[/green]")
    else:
        console.print("[red]❌ Data refresh failed[/red]")
        raise typer.Exit(1)


@app.command()
def validate(
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Minimal output mode")] = False,
) -> None:
    """Validate data counting consistency.

    Checks that:
    - Sum of year files equals cve_all.json total
    - CNA analysis totals are consistent
    - Yearly trend data matches totals
    """
    if quiet:
        setup_logging(level="WARNING")
    else:
        setup_logging(level="INFO")

    builder = CVESiteBuilder(quiet=quiet)

    console.print("\n🔍 Running data validation...")
    if validate_data_counts(builder):
        console.print("[green]✅ All validation checks passed[/green]")
    else:
        console.print("[red]❌ Validation failed[/red]")
        raise typer.Exit(1)


@app.command()
def info() -> None:
    """Show build system information and paths."""
    builder = CVESiteBuilder(quiet=True)

    console.print("\n[bold cyan]CVE.ICU Build System Info[/bold cyan]\n")
    console.print(f"  📅 Current Year: [green]{builder.current_year}[/green]")
    console.print(
        f"  📊 Year Coverage: [green]1999-{builder.current_year}[/green] ({len(builder.available_years)} years)"
    )
    console.print(f"  🌐 Web Output: [blue]{builder.web_dir}[/blue]")
    console.print(f"  📁 Templates: [blue]{builder.templates_dir}[/blue]")
    console.print(f"  💾 Cache Dir: [blue]{builder.cache_dir}[/blue]")
    console.print(f"  📂 Data Dir: [blue]{builder.data_dir}[/blue]")

    # Check cache status
    cache_info = builder.cache_dir / "cache_info.json"
    if cache_info.exists():
        import json

        with open(cache_info) as f:
            info = json.load(f)
        console.print("\n  [bold]Cache Status:[/bold]")
        console.print(f"    Last download: [yellow]{info.get('download_time', 'unknown')}[/yellow]")
    else:
        console.print("\n  [yellow]⚠️  No cache info found - run 'build --refresh-data'[/yellow]")


def validate_data_counts(builder: CVESiteBuilder) -> bool:
    """Validate that data counting is consistent across output files.

    See COUNTING.md for detailed documentation of expected behavior.
    """
    import json

    data_dir = builder.data_dir
    errors: list[str] = []
    warnings: list[str] = []

    logger.info("  📊 Checking year file totals...")

    # 1. Sum of year files should equal cve_all.json total
    year_sum = 0
    for year in range(1999, builder.current_year + 1):
        year_file = data_dir / f"cve_{year}.json"
        if year_file.exists():
            with open(year_file) as f:
                data = json.load(f)
            year_sum += data.get("total_cves", 0)

    cve_all_file = data_dir / "cve_all.json"
    if cve_all_file.exists():
        with open(cve_all_file) as f:
            cve_all = json.load(f)
        cve_all_total = cve_all.get("total_cves", 0)

        if year_sum != cve_all_total:
            errors.append(f"Year files sum ({year_sum:,}) != cve_all.json total ({cve_all_total:,})")
        else:
            logger.info(f"    ✅ Year files sum matches cve_all.json: {year_sum:,}")
    else:
        errors.append("cve_all.json not found")

    # 2. CNA analysis should have repository_stats.total_cves matching CNA list sum
    logger.info("  🏢 Checking CNA analysis totals...")
    cna_file = data_dir / "cna_analysis.json"
    if cna_file.exists():
        with open(cna_file) as f:
            cna_data = json.load(f)

        repo_total = cna_data.get("repository_stats", {}).get("total_cves", 0)
        cna_list = cna_data.get("cna_list", [])
        cna_sum = sum(cna.get("count", 0) for cna in cna_list)

        if repo_total != cna_sum:
            errors.append(f"CNA repo_stats ({repo_total:,}) != sum of CNA counts ({cna_sum:,})")
        else:
            logger.info(f"    ✅ CNA counts consistent: {cna_sum:,}")

        # CNA and cve_all should now be close (both exclude REJECTED)
        # Small difference expected due to pre-1999 CVEs (~700) and source variance
        diff = abs(repo_total - cve_all_total) if cve_all_file.exists() else 0
        if diff <= 1000:
            logger.info(f"    ✅ CNA total ({repo_total:,}) ≈ cve_all ({cve_all_total:,}) [diff: {diff}]")
        else:
            errors.append(f"CNA vs cve_all difference ({diff:,}) too large (expected <1000)")
    else:
        warnings.append("cna_analysis.json not found")

    # 3. Yearly trend in cve_all.json should match year files
    logger.info("  📈 Checking yearly trend consistency...")
    if cve_all_file.exists():
        yearly_trend = cve_all.get("yearly_trend", [])
        trend_sum = sum(y.get("count", 0) for y in yearly_trend)
        if trend_sum != cve_all_total:
            errors.append(f"yearly_trend sum ({trend_sum:,}) != total_cves ({cve_all_total:,})")
        else:
            logger.info(f"    ✅ Yearly trend sum matches total: {trend_sum:,}")

    # Report results
    if errors:
        logger.error("\n  ❌ Validation errors:")
        for error in errors:
            logger.error(f"     - {error}")

    if warnings:
        logger.warning("\n  ⚠️  Validation warnings:")
        for warning in warnings:
            logger.warning(f"     - {warning}")

    return len(errors) == 0


if __name__ == "__main__":
    main()
