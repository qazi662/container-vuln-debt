"""Shared setup for the analysis scripts. Run scripts from the repo root:  python analysis/rq1_snapshot.py"""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from cvd.store import connect, latest_date  # noqa: E402

PRIMARY = "trivy"  # main scanner for RQ1 to RQ3; Grype is compared in RQ4
FIG_DIR = Path(__file__).parent / "figures"
FIG_DIR.mkdir(exist_ok=True)

SEV_COLORS = {"CRITICAL": "#8b1a1a", "HIGH": "#d9534f", "MEDIUM": "#f0ad4e", "LOW": "#9fb8d0"}

plt.rcParams.update({
    "figure.dpi": 150,
    "savefig.bbox": "tight",
    "font.size": 9,
    "axes.spines.top": False,
    "axes.spines.right": False,
})


def setup():
    con = connect()
    return con, latest_date(con)


def save(fig, name: str) -> Path:
    path = FIG_DIR / f"{name}.png"
    fig.savefig(path)
    fig.savefig(FIG_DIR / f"{name}.pdf")
    plt.close(fig)
    print(f"saved {path}")
    return path
