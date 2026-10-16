# Copyright 2026-present Orbit Contributors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Google adapter resource mapping and sanitized error classification."""

import pytest
from orbit_secrets import SecretAccessDeniedError, SecretNotFoundError, SecretReference

from orbit_secrets_gcp import GCPSecretsProvider


class Payload:
    data = b"gcp-secret"


class Response:
    name = "projects/demo/secrets/orders/versions/27"
    payload = Payload()


class FakeClient:
    def __init__(self, response=None, error=None):
        self.response = response or Response()
        self.error = error
        self.request = None
        self.closed = False

    async def access_secret_version(self, *, request, timeout):
        self.request = (request, timeout)
        if self.error:
            raise self.error
        return self.response

    async def close(self):
        self.closed = True


@pytest.mark.asyncio
async def test_resolve_uses_async_client_and_returns_provider_version():
    client = FakeClient()
    provider = GCPSecretsProvider(client_factory=lambda: client)
    result = await provider.resolve(
        SecretReference(name="projects/demo/secrets/orders", version="27")
    )
    assert result.reveal() == b"gcp-secret"
    assert result.version == "27"
    assert client.request[0] == {"name": "projects/demo/secrets/orders/versions/27"}
    await provider.aclose()
    assert client.closed


@pytest.mark.asyncio
async def test_current_resolution_uses_latest_and_sanitizes_not_found():
    client = FakeClient()
    provider = GCPSecretsProvider(client_factory=lambda: client)
    await provider.resolve(SecretReference(name="projects/demo/secrets/orders"))
    assert client.request[0]["name"].endswith("/versions/latest")
    await provider.aclose()

    class NotFound(Exception):
        pass

    provider = GCPSecretsProvider(client_factory=lambda: FakeClient(error=NotFound("secret body")))
    with pytest.raises(SecretNotFoundError) as caught:
        await provider.resolve(SecretReference(name="projects/demo/secrets/orders"))
    assert "secret body" not in str(caught.value)
    await provider.aclose()


@pytest.mark.asyncio
async def test_permission_failure_is_sanitized():
    class PermissionDenied(Exception):
        pass

    provider = GCPSecretsProvider(
        client_factory=lambda: FakeClient(error=PermissionDenied("private payload"))
    )
    with pytest.raises(SecretAccessDeniedError) as caught:
        await provider.resolve(SecretReference(name="projects/demo/secrets/orders"))
    assert "private payload" not in str(caught.value)
    await provider.aclose()


@pytest.mark.asyncio
async def test_invalid_resource_syntax_fails_before_network():
    provider = GCPSecretsProvider(client_factory=lambda: pytest.fail("must not connect"))
    with pytest.raises(ValueError, match="projects"):
        await provider.resolve(SecretReference(name="not/a/secret"))
