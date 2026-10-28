"""Resolve image tags to digests through the OCI distribution API, without pulling.

A HEAD request on /v2/<repo>/manifests/<tag> returns the digest in the
Docker-Content-Digest header. Docker documents that HEAD requests do not count
toward Docker Hub pull limits, so resolving every tag every week is cheap.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from urllib.parse import urlparse

import requests

DOCKER_HUB = "registry-1.docker.io"

ACCEPT = ", ".join(
    [
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    ]
)


@dataclass(frozen=True)
class ImageRef:
    registry: str  # API host, e.g. registry-1.docker.io or gcr.io
    repository: str  # e.g. library/node or distroless/nodejs22-debian12
    tag: str

    @property
    def display_registry(self) -> str:
        return "docker.io" if self.registry == DOCKER_HUB else self.registry

    def with_digest(self, digest: str) -> str:
        """Reference understood by syft, trivy and grype, pinned to a digest."""
        return f"{self.display_registry}/{self.repository}@{digest}"


def parse_ref(ref: str) -> ImageRef:
    if "@" in ref:
        raise ValueError(f"expected a tag reference, got a digest: {ref}")
    first, _, rest = ref.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        registry, path = first, rest
    else:
        registry, path = DOCKER_HUB, ref
    name, sep, tag = path.rpartition(":")
    if not sep:
        name, tag = path, "latest"
    if registry in (DOCKER_HUB, "docker.io", "index.docker.io"):
        registry = DOCKER_HUB
        if "/" not in name:
            name = f"library/{name}"
    return ImageRef(registry=registry, repository=name, tag=tag)


_CHALLENGE_PARAM = re.compile(r'(\w+)="([^"]*)"')


class Resolver:
    """Resolves tags to digests, caching bearer tokens per repository."""

    def __init__(self, session: requests.Session | None = None, timeout: int = 30):
        self.session = session or requests.Session()
        self.timeout = timeout
        self._tokens: dict[tuple[str, str], str] = {}
        user, token = os.environ.get("DOCKERHUB_USERNAME"), os.environ.get("DOCKERHUB_TOKEN")
        self._hub_auth = (user, token) if user and token else None

    def _get_token(self, challenge: str, repository: str) -> str | None:
        if not challenge.lower().startswith("bearer"):
            return None
        params = dict(_CHALLENGE_PARAM.findall(challenge))
        realm = params.pop("realm", None)
        if not realm:
            return None
        params.setdefault("scope", f"repository:{repository}:pull")
        auth = self._hub_auth if urlparse(realm).hostname == "auth.docker.io" else None
        r = self.session.get(realm, params=params, auth=auth, timeout=self.timeout)
        r.raise_for_status()
        body = r.json()
        return body.get("token") or body.get("access_token")

    def _request(self, method: str, image: ImageRef) -> requests.Response:
        url = f"https://{image.registry}/v2/{image.repository}/manifests/{image.tag}"
        key = (image.registry, image.repository)
        headers = {"Accept": ACCEPT}
        if key in self._tokens:
            headers["Authorization"] = f"Bearer {self._tokens[key]}"
        r = self.session.request(method, url, headers=headers, timeout=self.timeout)
        if r.status_code == 401:
            token = self._get_token(r.headers.get("WWW-Authenticate", ""), image.repository)
            if token:
                self._tokens[key] = token
                headers["Authorization"] = f"Bearer {token}"
                r = self.session.request(method, url, headers=headers, timeout=self.timeout)
        return r

    def resolve(self, ref: str) -> str | None:
        """Return the tag's digest (sha256:...), or None if the tag does not exist."""
        image = parse_ref(ref)
        r = self._request("HEAD", image)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        digest = r.headers.get("Docker-Content-Digest")
        if digest:
            return digest
        # Some registries omit the header on HEAD; fall back to hashing the manifest body.
        r = self._request("GET", image)
        r.raise_for_status()
        return r.headers.get("Docker-Content-Digest") or "sha256:" + hashlib.sha256(r.content).hexdigest()
