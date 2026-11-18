# Methodology

## Image selection

Docker Official Images widely used in production, plus Google distroless images as the distroless variant. Each tag in `config/images.yaml` has a variant and one or more roles:

| Role | Feeds | Definition |
| --- | --- | --- |
| variant | RQ2 | Same app and release line, different base flavor (default, slim, alpine, distroless) |
| floating | RQ3 | Tag that moves with new releases, e.g. `node:22`, `nginx:stable` |
| pinned | RQ3 | Exact release, e.g. `node:22.11.0` |
| eol | RQ3 | Release line past end of support, e.g. `node:18`, `postgres:12` |

The image list is frozen after the baseline scan. Platform: linux/amd64.

## Collection (weekly)

1. **Resolve.** HEAD request on the registry manifest endpoint returns the tag's current index digest. HEAD requests do not count toward Docker Hub pull limits.
2. **SBOM inventory.** For digests not seen before, `syft scan registry:<image>@<digest> --platform linux/amd64 -o cyclonedx-json`. SBOMs are cached by (platform, digest) and used for package counts; they are not the scan input.
3. **Databases.** Trivy and Grype databases are updated once at the start of each run; every scan in that run uses the same snapshot. Tool and DB versions are saved to `data/state/versions/<date>.json`.
4. **Scan.** Each image is scanned by digest with `trivy image --image-src remote` and `grype registry:`, so both tools see the exact same image and each uses its own package cataloger.
5. **Normalize.** One row per (vulnerability, package, version). Grype GHSA ids are mapped to CVE ids through related vulnerabilities so the scanners can be compared. Grype "Negligible" maps to LOW. Trivy `not_affected` findings are dropped.
6. **Enrich.** CISA KEV membership and FIRST EPSS score per CVE, cached per run date.

## Exclusion: kernel header packages

Full Debian images (e.g. `node:22`, built on buildpack-deps) ship `linux-libc-dev`, the Linux kernel headers. Trivy matches every Linux kernel CVE against it (6,000 to 7,300 unique CVEs per node image on Nov 18, 2026, about 85% of Trivy's findings), while Grype ignores kernel header packages by default. A container runs on the host's kernel, so these CVEs do not describe risk inside the image. The `findings` view used by all analysis excludes `linux-libc-dev`, `linux-headers-*`, `linux-image-*` and `linux-kbuild-*`; the raw data and the `findings_all` view keep them, and RQ1 reports how many were excluded.

## Metrics

| RQ | Metric |
| --- | --- |
| RQ1 | Unique CVE ids per image by severity; share with a fix available (`fix_state = fixed`); share in KEV; share with EPSS at least 0.1; OS vs language packages |
| RQ2 | Per app, critical+high and total unique CVEs per variant; median reduction vs the default variant |
| RQ3 | Fixable CVEs per image by tag role; within app ratio of pinned and EOL tags to the floating tag |
| RQ4 | Digest changes per tag between consecutive scans; findings closed between scans, split into image rebuilt vs scanner DB change only; Jaccard similarity of Trivy and Grype CVE sets per image |

Primary scanner for RQ1 to RQ3 is Trivy; RQ1 to RQ3 are repeated with Grype as a robustness check.

## Validity checks

- SBOM vs direct scanning (Oct 28 and Nov 18, 2026): with Trivy reading a Syft CycloneDX SBOM, `gcr.io/distroless/nodejs22-debian12` produced 2 findings (Debian LTS advisory ids only); a direct `trivy image` scan of the same image produced 99, matching Grype's CVE ids. Debian and Alpine images were not affected the same way, but the study switched to direct scans for both tools so results reflect each scanner as teams use it.
- Images with zero findings are counted through `data/state/scans.csv`, so averages are not biased upward.
- Scanner and DB versions are recorded per run.

## Threats to validity

- Known vulnerable package present is not the same as exploitable in a deployment.
- Distro advisories (backports, "will not fix") differ from NVD; results reflect each scanner's data sources.
- Short window (about five weeks) limits RQ4.
- Official Images and distroless only, amd64 only; company internal images may differ.
- Distroless python3 tracks Debian's Python version, not the same release as `python:3.12`.
