"""Load and validate config/images.yaml."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

VALID_ROLES = {"variant", "floating", "pinned", "eol"}
VALID_VARIANTS = {"default", "slim", "alpine", "distroless", "chainguard", "other"}


@dataclass(frozen=True)
class Target:
    app: str
    ref: str
    variant: str
    roles: tuple[str, ...]

    @property
    def roles_str(self) -> str:
        return "|".join(self.roles)


class ConfigError(ValueError):
    pass


def load_config(path: str | Path) -> tuple[str, list[Target]]:
    """Return (platform, targets). Raises ConfigError with a clear message on bad input."""
    data = yaml.safe_load(Path(path).read_text())
    if not isinstance(data, dict) or "apps" not in data:
        raise ConfigError("config must have a top level 'apps' mapping")
    platform = data.get("platform", "linux/amd64")
    targets: list[Target] = []
    seen: set[str] = set()
    for app, spec in data["apps"].items():
        tags = (spec or {}).get("tags") or []
        if not tags:
            raise ConfigError(f"app '{app}' has no tags")
        for i, t in enumerate(tags):
            where = f"apps.{app}.tags[{i}]"
            ref = t.get("ref")
            if not ref or "@" in ref:
                raise ConfigError(f"{where}: 'ref' is required and must be a tag, not a digest")
            variant = t.get("variant", "default")
            if variant not in VALID_VARIANTS:
                raise ConfigError(f"{where}: variant '{variant}' not in {sorted(VALID_VARIANTS)}")
            roles = tuple(t.get("roles") or [])
            bad = set(roles) - VALID_ROLES
            if not roles or bad:
                raise ConfigError(f"{where}: roles must be a non empty subset of {sorted(VALID_ROLES)}")
            if ref in seen:
                raise ConfigError(f"{where}: duplicate ref '{ref}'")
            seen.add(ref)
            targets.append(Target(app=app, ref=ref, variant=variant, roles=roles))
    return platform, targets
