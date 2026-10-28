"""Run Trivy and Grype on the same SBOM and record tool and database versions."""

from __future__ import annotations

import gzip
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

SCANNERS = ("trivy", "grype")


class ScanError(RuntimeError):
    pass


def _run(cmd: list[str], timeout: int = 900, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env, check=False)


def check_tools() -> list[str]:
    """Names of required tools missing from PATH."""
    return [t for t in ("syft", "trivy", "grype") if shutil.which(t) is None]


def update_databases() -> None:
    """Download fresh vulnerability databases once per run, so every scan uses the same snapshot."""
    for cmd in (
        ["trivy", "image", "--download-db-only", "--quiet"],
        ["trivy", "image", "--download-java-db-only", "--quiet"],
        ["grype", "db", "update"],
    ):
        r = _run(cmd, timeout=1800)
        if r.returncode != 0:
            raise ScanError(f"{' '.join(cmd)} failed: {r.stderr.strip()[-1500:]}")


def tool_versions() -> dict:
    """Raw version output of each tool and DB, stored with every run for reproducibility."""
    out = {}
    for name, cmd in {
        "syft": ["syft", "version", "-o", "json"],
        "trivy": ["trivy", "version", "--format", "json"],
        "grype": ["grype", "version", "-o", "json"],
        "grype_db": ["grype", "db", "status", "-o", "json"],
    }.items():
        try:
            r = _run(cmd, timeout=120)
            text = r.stdout.strip()
            try:
                out[name] = json.loads(text)
            except json.JSONDecodeError:
                out[name] = text or r.stderr.strip()
        except (OSError, subprocess.TimeoutExpired) as exc:
            out[name] = f"error: {exc}"
    return out


def scan_sbom(scanner: str, sbom_gz: Path) -> dict:
    """Scan a gzipped CycloneDX SBOM. Databases must already be up to date."""
    with tempfile.TemporaryDirectory() as td:
        sbom = Path(td) / "sbom.cdx.json"
        with gzip.open(sbom_gz, "rb") as src, sbom.open("wb") as dst:
            shutil.copyfileobj(src, dst)
        env = dict(os.environ)
        if scanner == "trivy":
            cmd = ["trivy", "sbom", "--format", "json", "--quiet",
                   "--skip-db-update", "--skip-java-db-update", str(sbom)]
        elif scanner == "grype":
            env["GRYPE_DB_AUTO_UPDATE"] = "false"
            cmd = ["grype", f"sbom:{sbom}", "-o", "json", "-q"]
        else:
            raise ValueError(f"unknown scanner {scanner}")
        r = _run(cmd, env=env)
        if r.returncode != 0:
            raise ScanError(f"{scanner} failed: {r.stderr.strip()[-1500:]}")
        return json.loads(r.stdout)


def scan_image_direct(image_with_digest: str, platform: str) -> dict:
    """Trivy scan of the image itself (no SBOM), used to validate SBOM based scanning."""
    cmd = ["trivy", "image", "--format", "json", "--quiet", "--scanners", "vuln",
           "--skip-db-update", "--skip-java-db-update", "--platform", platform, image_with_digest]
    r = _run(cmd, timeout=1800)
    if r.returncode != 0:
        raise ScanError(f"trivy image failed: {r.stderr.strip()[-1500:]}")
    return json.loads(r.stdout)
