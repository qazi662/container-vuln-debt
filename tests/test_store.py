import pandas as pd

from cvd.store import connect


def test_kernel_header_packages_excluded(tmp_path):
    (tmp_path / "findings").mkdir()
    (tmp_path / "state").mkdir()
    pd.DataFrame({
        "date": ["2026-11-19"] * 3, "ref": ["node:22"] * 3, "scanner": ["trivy"] * 3,
        "vuln_id": ["CVE-1", "CVE-2", "CVE-3"], "pkg_name": ["libc6", "linux-libc-dev", "linux-headers-amd64"],
    }).to_parquet(tmp_path / "findings" / "2026-11-19.parquet")
    pd.DataFrame([{"date": "2026-11-19", "ref": "node:22", "app": "node", "variant": "default",
                   "roles": "variant", "index_digest": "sha256:x"}]).to_csv(
        tmp_path / "state" / "digests.csv", index=False)
    pd.DataFrame([{"date": "2026-11-19", "ref": "node:22", "scanner": "trivy", "status": "ok",
                   "n_findings": 3, "error": ""}]).to_csv(tmp_path / "state" / "scans.csv", index=False)
    con = connect(tmp_path)
    assert con.execute("SELECT count(*) FROM findings_all").fetchone()[0] == 3
    assert [r[0] for r in con.execute("SELECT vuln_id FROM findings").fetchall()] == ["CVE-1"]
