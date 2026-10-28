"""Generate one CycloneDX SBOM per (platform, digest) with Syft, straight from the registry.

Syft's registry: source pulls layers itself, so no Docker daemon is needed and
nothing is left on disk except the gzipped SBOM. Registry credentials come
from ~/.docker/config.json (run `docker login` locally; CI uses docker/login-action).
"""

from __future__ import annotations

import gzip
import shutil
import subprocess
import tempfile
from pathlib import Path

from .registry import parse_ref
from .util import data_dir, safe_name


def sbom_path(platform: str, digest: str) -> Path:
    return data_dir() / "sboms" / f"{safe_name(platform)}__{safe_name(digest)}.cdx.json.gz"


def build_sbom(ref: str, digest: str, platform: str, timeout: int = 1800) -> Path:
    """Create the SBOM if it does not exist yet. Returns its path."""
    out = sbom_path(platform, digest)
    if out.exists() and out.stat().st_size > 0:
        return out
    out.parent.mkdir(parents=True, exist_ok=True)
    source = "registry:" + parse_ref(ref).with_digest(digest)
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td) / "sbom.cdx.json"
        cmd = ["syft", "scan", source, "--platform", platform, "-o", f"cyclonedx-json={tmp}", "-q"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        if r.returncode != 0 or not tmp.exists():
            raise RuntimeError(f"syft failed for {ref}: {r.stderr.strip()[-1500:]}")
        partial = out.with_suffix(".partial")
        with tmp.open("rb") as src, gzip.open(partial, "wb") as dst:
            shutil.copyfileobj(src, dst)
        partial.replace(out)
    return out
