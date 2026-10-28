# %% [markdown]
# # RQ1: How much known vulnerability debt do popular official images carry, and how much matters?
# Unit: unique CVE ids per image (latest scan, primary scanner). "Matters" = fix available, in CISA KEV,
# or EPSS >= 0.1.

# %%
import matplotlib.pyplot as plt

from common import PRIMARY, SEV_COLORS, save, setup

con, date = setup()
print(f"scan date {date}, scanner {PRIMARY}")

# %% per image counts by severity (images with zero findings included)
per_image = con.execute(
    """
    SELECT i.app, i.ref, i.variant,
           count(DISTINCT f.vuln_id) FILTER (WHERE f.severity = 'CRITICAL') AS CRITICAL,
           count(DISTINCT f.vuln_id) FILTER (WHERE f.severity = 'HIGH') AS HIGH,
           count(DISTINCT f.vuln_id) FILTER (WHERE f.severity = 'MEDIUM') AS MEDIUM,
           count(DISTINCT f.vuln_id) FILTER (WHERE f.severity = 'LOW') AS LOW,
           count(DISTINCT f.vuln_id) AS total,
           count(DISTINCT f.vuln_id) FILTER (WHERE f.fix_state = 'fixed') AS fixable,
           count(DISTINCT f.vuln_id) FILTER (WHERE f.in_kev) AS kev,
           count(DISTINCT f.vuln_id) FILTER (WHERE f.epss >= 0.1) AS epss_ge_01
    FROM images i
    LEFT JOIN findings f ON f.date = i.date AND f.ref = i.ref AND f.scanner = i.scanner
    WHERE i.date = ? AND i.scanner = ?
    GROUP BY ALL
    """,
    [date, PRIMARY],
).df()
print(per_image.sort_values("total", ascending=False).to_string(index=False))

# %% headline numbers for the report
n = len(per_image)
print(f"\nimages scanned: {n}")
print(f"median unique CVEs per image: {per_image.total.median():.0f}")
print(f"images with at least one CRITICAL: {(per_image.CRITICAL > 0).mean():.0%}")

overall = con.execute(
    """
    SELECT count(DISTINCT vuln_id) AS unique_cves,
           count(DISTINCT vuln_id) FILTER (WHERE fix_state = 'fixed') AS fixable,
           count(DISTINCT vuln_id) FILTER (WHERE in_kev) AS kev,
           count(DISTINCT vuln_id) FILTER (WHERE epss >= 0.1) AS epss_ge_01
    FROM findings WHERE date = ? AND scanner = ?
    """,
    [date, PRIMARY],
).df().iloc[0]
u = max(int(overall.unique_cves), 1)
print(f"unique CVEs across all images: {overall.unique_cves}")
print(f"  with a fix available: {overall.fixable} ({overall.fixable / u:.0%})")
print(f"  in CISA KEV: {overall.kev} ({overall.kev / u:.1%})")
print(f"  EPSS >= 0.1: {overall.epss_ge_01} ({overall.epss_ge_01 / u:.1%})")

by_class = con.execute(
    """
    SELECT pkg_class, count(DISTINCT vuln_id) AS cves FROM findings
    WHERE date = ? AND scanner = ? GROUP BY 1
    """,
    [date, PRIMARY],
).df()
print("\nOS packages vs language packages:\n", by_class.to_string(index=False))

# %% Figure: critical and high per image, stacked by severity (top 25 by critical+high)
top = per_image.assign(ch=per_image.CRITICAL + per_image.HIGH).sort_values("ch", ascending=True).tail(25)
fig, ax = plt.subplots(figsize=(6.5, 0.22 * len(top) + 1))
left = None
for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
    ax.barh(top.ref, top[sev], left=left, color=SEV_COLORS[sev], label=sev.title())
    left = top[sev] if left is None else left + top[sev]
ax.set_xlabel("Unique CVEs (known, by severity)")
ax.set_title(f"Known vulnerabilities per image, {date} ({PRIMARY})", loc="left")
ax.legend(frameon=False, loc="upper left", bbox_to_anchor=(1.0, 1.0))
save(fig, "rq1_per_image")
