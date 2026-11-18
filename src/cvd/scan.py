"""Run Trivy and Grype on each image (by digest) and record tool and database versions."""

from __future__ import annotations

import json
import os
import shutil
import subprocess

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


def scan_image(scanner: str, image: str, platform: str) -> dict:
    """Scan an image by digest straight from the registry. Databases must already be up to date.

    Both scanners catalog the image themselves. An earlier version scanned a shared Syft SBOM, but
    validation showed Trivy missed most OS findings in SBOMs of distroless images (2 vs 99 findings
    on gcr.io/distroless/nodejs22-debian12), so each tool now reads the image directly.
    """
    env = dict(os.environ)
    if scanner == "trivy":
        cmd = ["trivy", "image", "--format", "json", "--quiet", "--scanners", "vuln",
               "--skip-db-update", "--skip-java-db-update", "--image-src", "remote",
               "--platform", platform, image]
    elif scanner == "grype":
        env["GRYPE_DB_AUTO_UPDATE"] = "false"
        cmd = ["grype", f"registry:{image}", "--platform", platform, "-o", "json", "-q"]
    else:
        raise ValueError(f"unknown scanner {scanner}")
    r = _run(cmd, timeout=1800, env=env)
    if r.returncode != 0:
        raise ScanError(f"{scanner} failed: {r.stderr.strip()[-1500:]}")
    return json.loads(r.stdout)
