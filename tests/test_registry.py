import pytest

from cvd.registry import DOCKER_HUB, ImageRef, Resolver, parse_ref


@pytest.mark.parametrize(
    "ref, expected",
    [
        ("node:22", ImageRef(DOCKER_HUB, "library/node", "22")),
        ("nginx", ImageRef(DOCKER_HUB, "library/nginx", "latest")),
        ("bitnami/redis:7.2", ImageRef(DOCKER_HUB, "bitnami/redis", "7.2")),
        ("docker.io/library/python:3.12-slim", ImageRef(DOCKER_HUB, "library/python", "3.12-slim")),
        ("gcr.io/distroless/nodejs22-debian12", ImageRef("gcr.io", "distroless/nodejs22-debian12", "latest")),
        ("cgr.dev/chainguard/node:latest", ImageRef("cgr.dev", "chainguard/node", "latest")),
        ("localhost:5000/app:1", ImageRef("localhost:5000", "app", "1")),
    ],
)
def test_parse_ref(ref, expected):
    assert parse_ref(ref) == expected


def test_with_digest_uses_docker_io_name():
    assert parse_ref("node:22").with_digest("sha256:abc") == "docker.io/library/node@sha256:abc"
    assert parse_ref("gcr.io/distroless/static").with_digest("sha256:abc") == "gcr.io/distroless/static@sha256:abc"


def test_digest_refs_rejected():
    with pytest.raises(ValueError):
        parse_ref("node@sha256:abc")


class FakeResp:
    def __init__(self, status, headers=None, body=None):
        self.status_code, self.headers, self._body, self.content = status, headers or {}, body or {}, b"{}"

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(self.status_code)


class FakeSession:
    """Registry that demands a bearer token, then returns a digest on HEAD."""

    def __init__(self):
        self.calls = []

    def request(self, method, url, headers=None, timeout=None):
        self.calls.append((method, url, dict(headers or {})))
        if "missing" in url:
            return FakeResp(404)
        if "Authorization" not in (headers or {}):
            return FakeResp(401, {"WWW-Authenticate":
                                  'Bearer realm="https://auth.docker.io/token",service="registry.docker.io"'})
        return FakeResp(200, {"Docker-Content-Digest": "sha256:deadbeef"})

    def get(self, url, params=None, auth=None, timeout=None):
        assert params["scope"] == "repository:library/node:pull"
        return FakeResp(200, body={"token": "t0k"})


def test_resolver_token_flow_and_cache(monkeypatch):
    monkeypatch.delenv("DOCKERHUB_USERNAME", raising=False)
    s = FakeSession()
    r = Resolver(session=s)
    assert r.resolve("node:22") == "sha256:deadbeef"
    assert r.resolve("node:22-slim") == "sha256:deadbeef"
    # second resolve reuses the cached token: one 401 total
    assert sum(1 for c in s.calls if "Authorization" not in c[2]) == 1


def test_resolver_missing_tag():
    class S(FakeSession):
        def request(self, method, url, headers=None, timeout=None):
            return FakeResp(404)

    assert Resolver(session=S()).resolve("node:missing") is None
