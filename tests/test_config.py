from pathlib import Path

import pytest

from cvd.config import ConfigError, load_config

REPO = Path(__file__).resolve().parents[1]


def test_repo_config_is_valid():
    platform, targets = load_config(REPO / "config" / "images.yaml")
    assert platform == "linux/amd64"
    assert len(targets) >= 40
    roles = {r for t in targets for r in t.roles}
    assert roles == {"variant", "floating", "pinned", "eol"}
    # every app used for RQ2 has a default variant to compare against
    apps_with_variants = {t.app for t in targets if "variant" in t.roles}
    for app in apps_with_variants:
        assert any(t.app == app and t.variant == "default" and "variant" in t.roles for t in targets), app


def write(tmp_path, text):
    p = tmp_path / "c.yaml"
    p.write_text(text)
    return p


def test_rejects_duplicate_refs(tmp_path):
    p = write(tmp_path, """
apps:
  a: {tags: [{ref: "x:1", roles: [eol]}, {ref: "x:1", roles: [pinned]}]}
""")
    with pytest.raises(ConfigError, match="duplicate"):
        load_config(p)


def test_rejects_bad_role_and_digest(tmp_path):
    with pytest.raises(ConfigError, match="roles"):
        load_config(write(tmp_path, 'apps: {a: {tags: [{ref: "x:1", roles: [nope]}]}}'))
    with pytest.raises(ConfigError, match="digest"):
        load_config(write(tmp_path, 'apps: {a: {tags: [{ref: "x@sha256:1", roles: [eol]}]}}'))
