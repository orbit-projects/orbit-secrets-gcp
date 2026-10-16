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
"""Async Google Secret Manager access with bounded values and safe provider errors."""

from __future__ import annotations

import asyncio
import inspect
import re
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any, Protocol, cast

from orbit_secrets import (
    MAX_SECRET_BYTES,
    SecretAccessDeniedError,
    SecretError,
    SecretNotFoundError,
    SecretOperationError,
    SecretProviderClosedError,
    SecretReference,
    SecretUnavailableError,
    SecretValue,
    SecretVersionNotFoundError,
)

from orbit_secrets_gcp.config import GCPSecretsConfig

_SECRET_NAME = re.compile(r"projects/[A-Za-z0-9][A-Za-z0-9.-]{0,62}/secrets/[A-Za-z0-9_-]{1,255}\Z")
_VERSION = re.compile(r"(?:latest|[1-9][0-9]{0,19})\Z")


class _GCPClient(Protocol):
    async def access_secret_version(self, *, request: dict[str, str], timeout: float) -> Any:
        """Return one Secret Manager version response for the named resource."""

    async def close(self) -> None:
        """Close the provider-owned async GAPIC transport."""


class GCPSecretsProvider:
    """Resolve current or pinned versions using Google Application Default Credentials.

    The async client is lazy, shared under a concurrency limit, and closed after in-flight calls
    drain. No secret cache is maintained, so ``refresh`` always performs a provider read.
    """

    def __init__(
        self,
        config: GCPSecretsConfig | None = None,
        *,
        client_factory: Callable[[], _GCPClient] | None = None,
    ) -> None:
        """Create a provider without acquiring ADC credentials or opening a transport."""
        self.config = config or GCPSecretsConfig()
        self._client_factory = client_factory or self._default_client_factory
        self._client: _GCPClient | None = None
        self._client_lock = asyncio.Lock()
        self._close_lock = asyncio.Lock()
        self._condition = asyncio.Condition()
        self._semaphore = asyncio.Semaphore(self.config.max_concurrency)
        self._active = 0
        self._closing = False
        self._closed = False

    @staticmethod
    def _default_client_factory() -> _GCPClient:
        """Construct the supported asynchronous Secret Manager client lazily."""
        from google.cloud import secretmanager_v1

        return cast(_GCPClient, secretmanager_v1.SecretManagerServiceAsyncClient())

    @asynccontextmanager
    async def _use_client(self) -> AsyncIterator[_GCPClient]:
        """Prevent new calls after close and share one client across bounded operations."""
        async with self._condition:
            if self._closing or self._closed:
                raise SecretProviderClosedError()
            self._active += 1
        try:
            async with self._semaphore:
                async with self._client_lock:
                    if self._client is None:
                        self._client = self._client_factory()
                    client = self._client
                yield client
        finally:
            async with self._condition:
                self._active -= 1
                self._condition.notify_all()

    async def resolve(self, reference: SecretReference) -> SecretValue:
        """Read one current or pinned Google secret version."""
        if not isinstance(reference, SecretReference):
            raise TypeError("reference must be a SecretReference.")
        if _SECRET_NAME.fullmatch(reference.name) is None:
            raise ValueError("GCP secret names must use projects/{project}/secrets/{secret}.")
        version = reference.version or "latest"
        if _VERSION.fullmatch(version) is None:
            raise ValueError("GCP secret versions must be latest or a positive version number.")
        resource_name = f"{reference.name}/versions/{version}"
        try:
            async with asyncio.timeout(self.config.request_timeout_seconds):
                async with self._use_client() as client:
                    response = await client.access_secret_version(
                        request={"name": resource_name},
                        timeout=self.config.request_timeout_seconds,
                    )
        except asyncio.CancelledError:
            raise
        except TimeoutError:
            raise SecretUnavailableError() from None
        except SecretError:
            raise
        except Exception as exc:
            raise _map_error(exc, pinned=reference.version is not None) from None
        return _decode_response(response, expected_prefix=f"{reference.name}/versions/")

    async def refresh(self, reference: SecretReference) -> SecretValue:
        """Fetch the provider's current version again, bypassing any adapter cache."""
        return await self.resolve(reference)

    async def aclose(self) -> None:
        """Stop new calls, drain active reads, and close the owned GAPIC transport."""
        async with self._close_lock:
            if self._closed:
                return
            async with self._condition:
                self._closing = True
                await self._condition.wait_for(lambda: self._active == 0)
            try:
                if self._client is not None:
                    result = self._client.close()
                    if inspect.isawaitable(result):
                        await result
            except asyncio.CancelledError:
                raise
            except Exception:
                raise SecretOperationError("client-close-failed") from None
            else:
                self._closed = True

    async def __aenter__(self) -> GCPSecretsProvider:
        """Return this provider for async context management."""
        if self._closing or self._closed:
            raise SecretProviderClosedError()
        return self

    async def __aexit__(self, *_: object) -> None:
        """Close the async client on context exit."""
        await self.aclose()


def _decode_response(response: Any, *, expected_prefix: str) -> SecretValue:
    """Extract only bounded payload bytes and the immutable version from a GAPIC response."""
    try:
        payload = response.payload.data
        resource_name = response.name
        if not isinstance(payload, bytes) or len(payload) > MAX_SECRET_BYTES:
            raise ValueError
        if not isinstance(resource_name, str) or not resource_name.startswith(expected_prefix):
            raise ValueError
        version = resource_name[len(expected_prefix) :]
        if _VERSION.fullmatch(version) is None or version == "latest":
            raise ValueError
        return SecretValue(payload, version)
    except (AttributeError, IndexError, TypeError, ValueError):
        raise SecretOperationError("invalid-provider-response") from None


def _map_error(exc: Exception, *, pinned: bool) -> Exception:
    """Translate SDK exception classes to stable categories without preserving messages."""
    name = exc.__class__.__name__
    if name == "NotFound":
        return SecretVersionNotFoundError() if pinned else SecretNotFoundError()
    if name in {"PermissionDenied", "Unauthenticated"}:
        return SecretAccessDeniedError()
    if name in {
        "ResourceExhausted",
        "DeadlineExceeded",
        "ServiceUnavailable",
        "InternalServerError",
    }:
        return SecretUnavailableError()
    return SecretOperationError("provider-failure")


__all__ = ["GCPSecretsProvider"]
