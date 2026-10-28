# container-vuln-debt

**How much known vulnerability debt do popular container images carry, and how much of it comes from choices you control: base variant, tag, and scanner?**

An automated weekly measurement of Docker Official Images. Each run resolves every tag to its digest, builds an SBOM for new digests with Syft, scans every SBOM with both Trivy and Grype, adds exploit signals from CISA KEV and EPSS, and commits the results.

> Status: in progress (CPEG697 Advanced Cybersecurity term project, University of Delaware, Fall 2026). Findings land here in December 2026.

## Key findings

_Filled in after the final scan (Dec 2026)._

1. RQ1:
2. RQ2:
3. RQ3:
4. RQ4:

## How it works

```
config/images.yaml
      |
  resolve tag -> digest (registry HEAD, no pull)
      |
  new digest? -> syft SBOM (CycloneDX, cached in data/sboms)
      |
  trivy sbom + grype sbom   (same package list, fresh DBs each run)
      |
  normalize -> one schema   (CVE ids, severity, fix state, OS vs language package)
      |
  enrich: CISA KEV + FIRST EPSS
      |
  data/findings/<date>.parquet + data/state/*.csv  -> DuckDB -> analysis/ and `cvd` CLI
```

Why SBOM first: each image is pulled only when its digest changes, and both scanners read exactly the same package inventory, so differences between them come from their vulnerability data, not from package detection.

## Quick start (macOS)

```bash
# 1. tools
brew install syft grype trivy
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# 2. Docker Hub login (free account; Account settings > Personal access tokens, read only)
docker login -u YOUR_USER          # syft reads ~/.docker/config.json
export DOCKERHUB_USERNAME=YOUR_USER DOCKERHUB_TOKEN=YOUR_TOKEN

# 3. sanity checks
pytest -q
cvd check                          # validates config, finds tools, resolves every tag (no pulls)

# 4. a small first run, then the full baseline
cvd run --only nginx node
cvd summary
cvd run                            # all images (baseline scan 1)
```

No Docker daemon is needed for scanning; Syft pulls image layers straight from the registry.

## Commands

| Command | What it does |
| --- | --- |
| `cvd check` | Validate `config/images.yaml`, check tools, resolve every tag and list any that do not exist |
| `cvd run [--only APP ...] [--date YYYY-MM-DD]` | Full run: resolve, SBOM, scan with both scanners, enrich, save |
| `cvd summary [--scanner grype]` | Per image table for the latest scan |
| `cvd suggest node:22` | Rank tracked tags of the same app by critical/high findings |
| `cvd validate-sbom --sample 5` | Compare SBOM based results with a direct `trivy image` scan |

## Analysis

```bash
python analysis/rq1_snapshot.py        # debt per image, fixable, KEV, EPSS
python analysis/rq2_variants.py        # default vs slim vs alpine vs distroless
python analysis/rq3_tags.py            # floating vs pinned vs end of life tags
python analysis/rq4_churn_scanners.py  # rebuilds, closed findings, Trivy vs Grype agreement
```

Figures are written to `analysis/figures/` as PNG and PDF. The scripts use `# %%` cells, so they also open as notebooks in VS Code.

## Automation

`.github/workflows/weekly-scan.yml` runs every Monday and commits `data/findings` and `data/state`. Raw scanner JSON is uploaded as a workflow artifact (kept 90 days). Add two repository secrets first: `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`. Pin the scanner versions in that file before the baseline scan and do not change them during the study.

## Data

| Path | Contents | In git |
| --- | --- | --- |
| `data/findings/<date>.parquet` | All normalized findings for one scan date | yes |
| `data/state/digests.csv` | Tag to digest per date (or missing/error) | yes |
| `data/state/scans.csv` | Scan status and finding count per image and scanner | yes |
| `data/state/versions/<date>.json` | Syft, Trivy, Grype and DB versions used | yes |
| `data/sboms/` | Cached SBOMs | no (CI cache) |
| `data/raw/` | Raw scanner JSON | no (CI artifact) |

## Limitations

A known CVE in an image is not proof that it is exploitable in a given deployment. Results depend on scanner databases at scan time (recorded per run). Coverage is Docker Official Images plus Google distroless on linux/amd64, over about five weeks. See `docs/methodology.md`.

## Related work

- S. Tekin et al. Death Is Not the End: A Longitudinal Study on the Impact of Automatic Updates on Container Vulnerability Lifespans. IEEE S&P 2026.
- R. Shu, X. Gu, W. Enck. A Study of Security Vulnerabilities on Docker Hub. ACM CODASPY 2017.
- A. Zerouali et al. On the Relation between Outdated Docker Containers, Severity Vulnerabilities, and Bugs. IEEE SANER 2019.

## License

Code: MIT. Dataset: CC BY 4.0.
