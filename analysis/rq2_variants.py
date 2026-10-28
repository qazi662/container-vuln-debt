# %% [markdown]
# # RQ2: How much does the base variant change vulnerability debt for the same app release?
# Compares tags with role "variant" within each app: default vs slim vs alpine vs distroless.

# %%
import matplotlib.pyplot as plt
import numpy as np

from common import PRIMARY, save, setup

con, date = setup()

df = con.execute(
    """
    SELECT i.app, i.ref, i.variant,
           count(DISTINCT f.vuln_id) FILTER (WHERE f.severity IN ('CRITICAL','HIGH')) AS crit_high,
           count(DISTINCT f.vuln_id) AS total,
           count(DISTINCT f.vuln_id) FILTER (WHERE f.fix_state = 'fixed') AS fixable
    FROM images i
    LEFT JOIN findings f ON f.date = i.date AND f.ref = i.ref AND f.scanner = i.scanner
    WHERE i.date = ? AND i.scanner = ? AND i.roles LIKE '%variant%'
    GROUP BY ALL
    """,
    [date, PRIMARY],
).df()

order = ["default", "slim", "alpine", "distroless", "chainguard", "other"]
variants = [v for v in order if v in set(df.variant)]

# %% table and reduction vs default
pivot_total = df.pivot_table(index="app", columns="variant", values="total", aggfunc="first")[variants]
pivot_ch = df.pivot_table(index="app", columns="variant", values="crit_high", aggfunc="first")[variants]
print("Total unique CVEs\n", pivot_total.to_string())
print("\nCritical + high\n", pivot_ch.to_string())

if "default" in pivot_total:
    for v in variants:
        if v == "default":
            continue
        pair = pivot_total[["default", v]].dropna()
        pair = pair[pair["default"] > 0]
        if len(pair):
            red = 1 - (pair[v] / pair["default"])
            print(f"{v:<11} vs default: median reduction in total CVEs {red.median():.0%} across {len(pair)} apps")
        pch = pivot_ch[["default", v]].dropna()
        pch = pch[pch["default"] > 0]
        if len(pch):
            red = 1 - (pch[v] / pch["default"])
            print(f"{'':<11}            median reduction in critical+high {red.median():.0%}")

# %% Figure: grouped bars, critical+high per app per variant
apps = list(pivot_ch.index)
x = np.arange(len(apps))
w = 0.8 / len(variants)
fig, ax = plt.subplots(figsize=(6.5, 3))
for k, v in enumerate(variants):
    ax.bar(x + (k - (len(variants) - 1) / 2) * w, pivot_ch[v].fillna(0), width=w, label=v)
ax.set_xticks(x, apps, rotation=30, ha="right")
ax.set_ylabel("Critical + high CVEs")
ax.set_title(f"Same app, different base variant, {date} ({PRIMARY})", loc="left")
ax.legend(frameon=False, loc="upper left", bbox_to_anchor=(1.0, 1.0))
save(fig, "rq2_variants")
