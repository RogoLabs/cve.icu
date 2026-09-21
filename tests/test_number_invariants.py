"""Invariants for every number the site displays.

These encode an audit of the figures shown across the 14 pages. Each check is a
relationship that must hold for the site to be internally honest: a subset must
not exceed its superset, a breakdown must sum to its total, and the same
quantity must not differ between two pages.

Where two figures legitimately disagree - because they come from different
sources or count different things - the tolerance is stated and explained
rather than left implicit. A failure here means either a real regression or a
change in what a number means; both need a human decision.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


DATA = Path(__file__).parent.parent / "web" / "data"


def load(name: str):
    path = DATA / name
    if not path.exists():
        pytest.skip(f"{name} not built")
    return json.loads(path.read_text())


@pytest.fixture(scope="module")
def d() -> dict:
    names = [
        "yearly_summary",
        "homepage_summary",
        "cvss_analysis",
        "epss_analysis",
        "kev_analysis",
        "cwe_analysis",
        "cpe_analysis",
        "cna_analysis",
        "growth_analysis",
        "data_quality",
        "scoring_comparison",
    ]
    return {n: load(f"{n}.json") for n in names}


@pytest.fixture(scope="module")
def site_total(d) -> int:
    """The site's own CVE count: what every other figure is judged against."""
    return sum(y["total_cves"] for y in d["yearly_summary"]["years"].values())


class TestSubsets:
    """A count of CVEs with some property cannot exceed the number of CVEs."""

    @pytest.mark.parametrize(
        "label,path",
        [
            ("CWE classified", ("cwe_analysis", "total_cves_with_cwe")),
            ("CPE with product data", ("cpe_analysis", "total_cves_with_cpes")),
            ("KEV", ("kev_analysis", "total_kev_cves")),
            ("EPSS matched", ("epss_analysis", "total_cves_with_epss_matched")),
        ],
    )
    def test_subset_never_exceeds_site_total(self, d, site_total, label, path):
        value = d[path[0]].get(path[1])
        if value is None:
            pytest.skip(f"{label} not present")
        assert value <= site_total, (
            f"{label} ({value:,}) exceeds the site's own CVE total ({site_total:,}). "
            "Either it counts a different population, or a denominator is wrong."
        )

    def test_cvss_scores_are_not_a_subset(self, d, site_total):
        """CVSS is the documented exception: it counts scores, not CVEs.

        A CVE can hold a score under several metric versions, so this figure
        exceeding the total is expected - the pages label it accordingly.
        """
        assert d["cvss_analysis"]["total_cves_with_cvss"] > site_total


class TestBreakdownsSumToTotals:
    def test_cvss_versions_sum_to_total(self, d):
        c = d["cvss_analysis"]
        assert sum(c["total_by_version"].values()) == c["total_cves_with_cvss"]

    @pytest.mark.parametrize("version", ["v2.0", "v3.0", "v3.1", "v4.0"])
    def test_cvss_severity_bands_sum_to_version_total(self, d, version):
        c = d["cvss_analysis"]
        if version not in c["total_by_version"]:
            pytest.skip(f"{version} absent")
        assert sum(c["severity_distribution"][version].values()) == c["total_by_version"][version]

    @pytest.mark.parametrize("grouping", ["by_year_added", "by_year_published", "timeline"])
    def test_kev_groupings_sum_to_catalog_total(self, d, grouping):
        k = d["kev_analysis"]
        assert sum(k[grouping].values()) == k["total_kev_cves"], (
            f"KEV {grouping} does not account for every catalog entry"
        )

    def test_epss_score_buckets_sum_to_row_count(self, d):
        e = d["epss_analysis"]
        assert sum(e["score_buckets"].values()) == e["total_cves_with_epss"]

    def test_data_quality_buckets_account_for_every_publisher(self, d):
        s = d["data_quality"]["stats"]
        soft = s["case_mismatches"] + s["org_name_matches"] + s["normalized_matches"] + s["partial_matches"]
        assert s["exact_matches"] + soft + s["unmatched"] == s["total_cnas_in_analysis"]

    def test_cna_active_plus_inactive_equals_total(self, d):
        c = d["cna_analysis"]
        assert c["active_cnas"] + c["inactive_cnas"] == c["total_cnas"]


class TestCrossPageAgreement:
    """The same quantity must not differ depending on which page you open."""

    def test_kev_total_agrees_across_sources(self, d):
        assert d["kev_analysis"]["total_kev_cves"] == d["cvss_analysis"]["kev_global_count"]

    def test_scoring_comparison_matches_its_sources(self, d):
        sysd = d["scoring_comparison"]["systems"]
        assert sysd["cvss"]["total_scored"] == d["cvss_analysis"]["total_cves_with_cvss"]
        assert sysd["kev"]["total_scored"] == d["kev_analysis"]["total_kev_cves"]

    def test_per_year_kev_agrees_between_sources(self, d):
        years = d["yearly_summary"]["years"]
        published = d["kev_analysis"]["by_year_published"]
        for year, data in years.items():
            recorded = (data.get("kev") or {}).get("kev_count")
            if recorded is None:
                continue
            assert recorded == published.get(year, 0), f"{year} KEV count differs between sources"

    def test_growth_counts_match_yearly_summary(self, d):
        years = d["yearly_summary"]["years"]
        for row in d["growth_analysis"]["growth_data"]:
            assert row["cves"] == years[str(row["year"])]["total_cves"], (
                f"{row['year']} differs between growth_analysis and yearly_summary"
            )


class TestEpssPublicationBucketing:
    """EPSS is bucketed by publication date so it is comparable with the totals.

    These apply only to data produced by the current pipeline. The repository
    also carries committed output from earlier builds, which bucketed EPSS by
    CVE ID year and would legitimately fail here - that is the defect this
    change fixed, not a regression to catch. `total_cves_with_epss_matched` is
    only emitted by the fixed analyzer, so its presence marks data the
    invariants apply to. After the first build on the new pipeline the skip
    stops firing.
    """

    @pytest.fixture(autouse=True)
    def _requires_current_pipeline(self, d):
        if "total_cves_with_epss_matched" not in d["epss_analysis"]:
            pytest.skip("epss_analysis.json predates publication-date bucketing")

    def test_coverage_never_exceeds_its_own_denominator(self, d):
        over = [y for y, v in d["epss_analysis"]["year_coverage"].items() if v["with_epss"] > v["total"]]
        assert not over, f"more CVEs have EPSS scores than exist, in: {over}"

    def test_coverage_denominators_sum_to_site_total(self, d, site_total):
        cov = d["epss_analysis"]["year_coverage"]
        assert sum(v["total"] for v in cov.values()) == site_total

    def test_matched_plus_unmatched_equals_raw(self, d):
        e = d["epss_analysis"]
        assert e["total_cves_with_epss_matched"] + e["epss_without_published_record"] == (e["total_cves_with_epss"])

    def test_thresholds_are_monotonic(self, d):
        s = d["epss_analysis"]["statistics"]
        assert s["gt_0_1"] >= s["gt_0_3"] >= s["gt_0_5"] >= s["gt_0_7"] >= s["gt_0_9"]


class TestKnownSourceDisagreement:
    """The CNA pipeline reads cvelistV5 while the yearly totals read NVD.

    They will not agree exactly. The site says so on the Publishers page, and
    source_reconciliation.json measures it. This bounds the gap so a real
    regression is not mistaken for the usual drift.
    """

    MAX_ALLTIME_GAP = 5000

    def test_cna_attribution_gap_stays_bounded(self, d, site_total):
        attributed = sum(c["count"] for c in d["cna_analysis"]["cna_list"])
        gap = attributed - site_total
        assert abs(gap) <= self.MAX_ALLTIME_GAP, (
            f"CNA attribution ({attributed:,}) differs from the site total "
            f"({site_total:,}) by {gap:+,}, beyond the tolerated drift. "
            "See docs/COUNTING.md and source_reconciliation.json."
        )
