import json
from pathlib import Path

from cvd.normalize import FINDING_COLUMNS, normalize, normalize_grype, normalize_trivy

FIX = Path(__file__).parent / "fixtures"


def load(name):
    return json.loads((FIX / name).read_text())


def by_id(rows):
    return {r["vuln_id"]: r for r in rows}


def test_trivy_dedupes_maps_status_and_drops_not_affected():
    rows = normalize_trivy(load("trivy_sbom.json"))
    ids = by_id(rows)
    assert len(rows) == 4  # duplicate libc6 row collapsed, not_affected dropped
    assert "CVE-2024-0000" not in ids
    assert ids["CVE-2023-4911"]["fix_state"] == "fixed"
    assert ids["CVE-2023-4911"]["pkg_class"] == "os"
    assert ids["CVE-2011-3374"]["fix_state"] == "not-fixed"
    assert ids["CVE-2022-0563"]["fix_state"] == "wont-fix"
    assert ids["CVE-2024-21538"]["pkg_class"] == "lang"
    assert set(rows[0]) == set(FINDING_COLUMNS)


def test_grype_prefers_cve_id_and_maps_negligible():
    rows = normalize_grype(load("grype_sbom.json"))
    ids = by_id(rows)
    assert "CVE-2024-21538" in ids  # GHSA converted to its CVE
    assert ids["CVE-2024-21538"]["aliases"] == "GHSA-3xgq-45jj-v275"
    assert ids["CVE-2011-3374"]["severity"] == "LOW"
    assert ids["CVE-2011-3374"]["severity_raw"] == "Negligible"
    assert ids["CVE-2025-1111"]["fix_state"] == "wont-fix"
    assert ids["CVE-2023-4911"]["pkg_class"] == "os"
    assert ids["CVE-2024-21538"]["pkg_class"] == "lang"


def test_scanners_comparable_on_shared_ids():
    t = {r["vuln_id"] for r in normalize("trivy", load("trivy_sbom.json"))}
    g = {r["vuln_id"] for r in normalize("grype", load("grype_sbom.json"))}
    assert t & g == {"CVE-2023-4911", "CVE-2024-21538", "CVE-2011-3374"}


def test_empty_reports():
    assert normalize_trivy({}) == []
    assert normalize_grype({"matches": None}) == []
