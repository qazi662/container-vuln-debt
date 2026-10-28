"""Turn Trivy and Grype JSON into one flat finding schema.

One row per (vulnerability, package, version) per image per scanner:
vuln_id, aliases, pkg_name, pkg_version, pkg_type, pkg_class, purl,
severity, severity_raw, fix_state, fixed_version
"""

from __future__ import annotations

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
OS_TYPES = {
    # trivy result types
    "alpine", "debian", "ubuntu", "redhat", "centos", "rocky", "alma", "amazon", "oracle",
    "photon", "suse", "opensuse", "opensuse.leap", "sles", "wolfi", "chainguard", "mariner", "azurelinux",
    "cbl-mariner", "bitnami",
    # grype artifact types
    "deb", "apk", "rpm",
}

FINDING_COLUMNS = [
    "vuln_id", "aliases", "pkg_name", "pkg_version", "pkg_type", "pkg_class", "purl",
    "severity", "severity_raw", "fix_state", "fixed_version",
]

_TRIVY_STATUS = {
    "fixed": "fixed",
    "affected": "not-fixed",
    "fix_deferred": "not-fixed",
    "under_investigation": "not-fixed",
    "will_not_fix": "wont-fix",
    "end_of_life": "wont-fix",
    "not_affected": "not-affected",
}


def _severity(raw: str | None) -> str:
    s = (raw or "UNKNOWN").upper()
    if s == "NEGLIGIBLE":
        return "LOW"
    return s if s in SEVERITIES else "UNKNOWN"


def _pkg_class(pkg_type: str) -> str:
    return "os" if (pkg_type or "").lower() in OS_TYPES else "lang"


def _canonical_id(primary: str, related: list[str]) -> str:
    """Prefer a CVE id so the two scanners can be compared (Grype often reports GHSA ids)."""
    if primary.startswith("CVE-"):
        return primary
    for rid in related:
        if rid.startswith("CVE-"):
            return rid
    return primary


def normalize_trivy(report: dict) -> list[dict]:
    rows = []
    for result in report.get("Results") or []:
        rtype = result.get("Type", "")
        rclass = "os" if result.get("Class") == "os-pkgs" else _pkg_class(rtype)
        for v in result.get("Vulnerabilities") or []:
            vid = v.get("VulnerabilityID", "")
            fixed = v.get("FixedVersion") or ""
            status = v.get("Status")
            if status:
                fix_state = _TRIVY_STATUS.get(status, "unknown")
            else:
                fix_state = "fixed" if fixed else "unknown"
            if fix_state == "not-affected":
                continue
            rows.append({
                "vuln_id": vid,
                "aliases": "",
                "pkg_name": v.get("PkgName", ""),
                "pkg_version": v.get("InstalledVersion", ""),
                "pkg_type": rtype,
                "pkg_class": rclass,
                "purl": (v.get("PkgIdentifier") or {}).get("PURL", ""),
                "severity": _severity(v.get("Severity")),
                "severity_raw": v.get("Severity", ""),
                "fix_state": fix_state,
                "fixed_version": fixed,
            })
    return _dedupe(rows)


def normalize_grype(report: dict) -> list[dict]:
    rows = []
    for m in report.get("matches") or []:
        vuln = m.get("vulnerability") or {}
        art = m.get("artifact") or {}
        related = [r.get("id", "") for r in m.get("relatedVulnerabilities") or []]
        primary = vuln.get("id", "")
        vid = _canonical_id(primary, related)
        fix = vuln.get("fix") or {}
        state = fix.get("state") or "unknown"
        if state not in ("fixed", "not-fixed", "wont-fix", "unknown"):
            state = "unknown"
        aliases = sorted({primary, *related} - {vid} - {""})
        rows.append({
            "vuln_id": vid,
            "aliases": ",".join(aliases),
            "pkg_name": art.get("name", ""),
            "pkg_version": art.get("version", ""),
            "pkg_type": art.get("type", ""),
            "pkg_class": _pkg_class(art.get("type", "")),
            "purl": art.get("purl", ""),
            "severity": _severity(vuln.get("severity")),
            "severity_raw": vuln.get("severity", ""),
            "fix_state": state,
            "fixed_version": ",".join(fix.get("versions") or []),
        })
    return _dedupe(rows)


def normalize(scanner: str, report: dict) -> list[dict]:
    if scanner == "trivy":
        return normalize_trivy(report)
    if scanner == "grype":
        return normalize_grype(report)
    raise ValueError(f"unknown scanner {scanner}")


def _dedupe(rows: list[dict]) -> list[dict]:
    seen, out = set(), []
    for r in rows:
        key = (r["vuln_id"], r["pkg_name"], r["pkg_version"])
        if key not in seen:
            seen.add(key)
            out.append(r)
    return out
