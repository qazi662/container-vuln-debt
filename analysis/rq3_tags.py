# %% [markdown]
# # RQ3: Do floating, pinned and end of life tags differ in fixable vulnerabilities?
# "Fixable" = scanner reports a fixed version exists. A fixable CVE in an image means the image is
# behind available patches, which is the debt a tag choice controls.

# %%
import matplotlib.pyplot as plt

from common import PRIMARY, save, setup

con, date = setup()

rows = con.execute(
    """
    WITH roles AS (
        SELECT i.*, unnest(string_split(i.roles, '|')) AS role FROM images i
        WHERE i.date = ? AND i.scanner = ?
    )
    SELECT r.app, r.ref, r.role,
           count(DISTINCT f.vuln_id) FILTER (WHERE f.fix_state = 'fixed') AS fixable,
           count(DISTINCT f.vuln_id) FILTER (WHERE f.fix_state = 'fixed' AND f.severity IN ('CRITICAL','HIGH'))
               AS fixable_crit_high,
           count(DISTINCT f.vuln_id) AS total
    FROM roles r
    LEFT JOIN findings f ON f.date = r.date AND f.ref = r.ref AND f.scanner = r.scanner
    WHERE r.role IN ('floating', 'pinned', 'eol')
    GROUP BY ALL
    """,
    [date, PRIMARY],
).df()

groups = [g for g in ["floating", "pinned", "eol"] if g in set(rows.role)]
print(rows.groupby("role")[["fixable", "fixable_crit_high", "total"]].median().loc[groups].to_string())

# %% paired view: within each app, EOL or pinned vs that app's floating tag
floating = rows[rows.role == "floating"].groupby("app").fixable.median()
for g in ["pinned", "eol"]:
    other = rows[rows.role == g].groupby("app").fixable.median()
    both = floating.to_frame("floating").join(other.rename(g), how="inner")
    both = both[both.floating > 0]
    if len(both):
        ratio = (both[g] / both.floating).median()
        print(f"{g}: median {ratio:.1f}x the fixable CVEs of the same app's floating tag ({len(both)} apps)")

# %% Figure: box plot of fixable CVEs per tag role, with points
fig, ax = plt.subplots(figsize=(5, 3))
data = [rows[rows.role == g].fixable for g in groups]
ax.boxplot(data, showfliers=False)
ax.set_xticks(range(1, len(groups) + 1), groups)
for k, d in enumerate(data, start=1):
    ax.scatter([k] * len(d), d, s=10, alpha=0.6, color="#333")
ax.set_ylabel("Fixable CVEs per image")
ax.set_title(f"Tag choice and patch debt, {date} ({PRIMARY})", loc="left")
save(fig, "rq3_tags")
