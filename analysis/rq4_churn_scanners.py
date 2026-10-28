# %% [markdown]
# # RQ4: Tag churn over the study window, CVE closure, and Trivy vs Grype agreement
# Churn: how often each tag points to a new digest between weekly scans.
# Closure: CVEs present one week and gone the next, split by whether the image was rebuilt
# (digest changed) or only the scanner database changed.
# Agreement: Jaccard similarity of the two scanners' CVE id sets for the same image and date.

# %%
import matplotlib.pyplot as plt

from common import PRIMARY, save, setup

con, date = setup()
dates = [r[0] for r in con.execute("SELECT DISTINCT date FROM images ORDER BY 1").fetchall()]
print(f"scan dates: {dates}")

# %% churn: digest changes per tag across consecutive scans
churn = con.execute(
    """
    WITH d AS (
        SELECT ref, date, index_digest,
               lag(index_digest) OVER (PARTITION BY ref ORDER BY date) AS prev
        FROM digests WHERE status = 'ok'
    )
    SELECT ref, count(*) FILTER (WHERE prev IS NOT NULL) AS intervals,
           count(*) FILTER (WHERE prev IS NOT NULL AND prev <> index_digest) AS rebuilds
    FROM d GROUP BY ref ORDER BY rebuilds DESC
    """
).df()
if churn.intervals.max() > 0:
    print(churn.to_string(index=False))
    print(f"tags rebuilt at least once: {(churn.rebuilds > 0).mean():.0%}")
else:
    print("only one scan date so far; churn needs at least two")

# %% closure between consecutive scans (primary scanner)
closure = con.execute(
    """
    WITH s AS (
        SELECT DISTINCT f.date, f.ref, f.vuln_id, f.pkg_name, i.index_digest
        FROM findings f JOIN images i ON i.date = f.date AND i.ref = f.ref AND i.scanner = f.scanner
        WHERE f.scanner = ?
    ),
    dates AS (SELECT date, lead(date) OVER (ORDER BY date) AS next FROM (SELECT DISTINCT date FROM images)),
    img AS (SELECT DISTINCT date, ref, index_digest FROM images WHERE scanner = ?),
    pairs AS (
        SELECT a.ref, a.date, d.next, a.index_digest AS dig_a, ib.index_digest AS dig_b,
               b.vuln_id IS NOT NULL AS still_there
        FROM s a
        JOIN dates d ON d.date = a.date AND d.next IS NOT NULL
        LEFT JOIN img ib ON ib.ref = a.ref AND ib.date = d.next
        LEFT JOIN s b ON b.ref = a.ref AND b.date = d.next AND b.vuln_id = a.vuln_id AND b.pkg_name = a.pkg_name
    )
    SELECT date, next,
           count(*) FILTER (WHERE dig_b IS NOT NULL AND NOT still_there AND dig_a <> dig_b) AS closed_by_rebuild,
           count(*) FILTER (WHERE dig_b IS NOT NULL AND NOT still_there AND dig_a = dig_b) AS closed_by_db_change,
           count(*) FILTER (WHERE dig_b IS NOT NULL) AS findings_tracked
    FROM pairs GROUP BY 1, 2 ORDER BY 1
    """,
    [PRIMARY, PRIMARY],
).df()
print("\nCVE findings closed between scans\n", closure.to_string(index=False))

# %% scanner agreement per image on the latest date
agree = con.execute(
    """
    WITH t AS (SELECT DISTINCT ref, vuln_id FROM findings WHERE date = ? AND scanner = 'trivy'),
         g AS (SELECT DISTINCT ref, vuln_id FROM findings WHERE date = ? AND scanner = 'grype'),
         both_ok AS (
            SELECT ref FROM images WHERE date = ? GROUP BY ref HAVING count(DISTINCT scanner) = 2
         ),
         j AS (
            SELECT coalesce(t.ref, g.ref) AS ref, t.vuln_id IS NOT NULL AS in_t, g.vuln_id IS NOT NULL AS in_g
            FROM t FULL OUTER JOIN g ON t.ref = g.ref AND t.vuln_id = g.vuln_id
         )
    SELECT b.ref,
           count(j.ref) FILTER (WHERE j.in_t) AS trivy,
           count(j.ref) FILTER (WHERE j.in_g) AS grype,
           count(j.ref) FILTER (WHERE j.in_t AND j.in_g) AS both_found,
           count(j.ref) AS union_n
    FROM both_ok b LEFT JOIN j ON j.ref = b.ref
    GROUP BY b.ref
    """,
    [date, date, date],
).df()
agree["jaccard"] = agree.apply(lambda r: r.both_found / r.union_n if r.union_n else 1.0, axis=1)
agree = agree.sort_values("jaccard")
print("\nTrivy vs Grype\n", agree.to_string(index=False))
tot = agree[["trivy", "grype", "both_found", "union_n"]].sum()
if tot.union_n:
    print(f"pooled agreement (Jaccard): {tot.both_found / tot.union_n:.0%}; "
          f"only Trivy {(tot.trivy - tot.both_found) / tot.union_n:.0%}, "
          f"only Grype {(tot.grype - tot.both_found) / tot.union_n:.0%}")
print(f"median per image Jaccard: {agree.jaccard.median():.2f}")

# %% Figure: agreement per image
fig, ax = plt.subplots(figsize=(5, 3))
ax.hist(agree.jaccard, bins=10, range=(0, 1), color="#4a78a8", edgecolor="white")
ax.set_xlabel("Jaccard similarity of CVE sets (1 = identical)")
ax.set_ylabel("Images")
ax.set_title(f"Trivy vs Grype on the same SBOMs, {date}", loc="left")
save(fig, "rq4_scanner_agreement")

if len(closure):
    fig, ax = plt.subplots(figsize=(5, 3))
    ax.bar(closure.next, closure.closed_by_rebuild, label="image rebuilt", color="#4a78a8")
    ax.bar(closure.next, closure.closed_by_db_change, bottom=closure.closed_by_rebuild,
           label="scanner DB change only", color="#c8c8c8")
    ax.set_ylabel("Findings closed since previous scan")
    ax.set_title("Where closed findings come from", loc="left")
    ax.legend(frameon=False)
    save(fig, "rq4_closure")
