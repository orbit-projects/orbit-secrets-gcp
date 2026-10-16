# Google Cloud Secret Manager for Orbit Secrets

`orbit-secrets-gcp` implements the provider-neutral async `SecretProvider` contract from `orbit-secrets`. It owns the SecretManagerServiceAsyncClient, provider-specific identity, finite request timeout, bounded concurrency, safe error mapping, and client cleanup.

**Status:** unpublished v0.1.0-alpha adapter review candidate. Unit tests use fake clients; no live credentials or production cloud service are required for tests.

## Install

```bash
python -m pip install orbit-secrets orbit-secrets-gcp
```

## Resolve and refresh

```python
from orbit_secrets import SecretReference
from orbit_secrets_gcp import GCPSecretsConfig, GCPSecretsProvider

provider = GCPSecretsProvider(GCPSecretsConfig())
try:
    current = await provider.resolve(SecretReference(name="projects/acme-prod/secrets/orders-db"))
    password = current.reveal_text()
    # Use the value only for the immediate credential handoff.
    newest = await provider.refresh(SecretReference(name="..."))
finally:
    await provider.aclose()
```

SecretReference.name must be `projects/{project}/secrets/{secret}`. An explicit version is a positive numeric version; omitted versions resolve `latest`. Payload bytes and the exact returned version are retained.

## Identity and safety

Use Application Default Credentials, preferably workload identity. Do not pass long-lived credentials in source, CLI arguments, or application config. Requests have finite timeout and concurrency bounds. The adapter never caches resolved secret values, follows provider identity fallback only as defined by the official SDK, and never includes raw SDK messages, request bodies, or secret values in Orbit exceptions. Cancellation propagates.

`aclose()` stops new requests, drains active calls, and closes the client (and Azure credential where applicable). Register application shutdown to await it. Never log the returned value. Python cannot guarantee secret-memory zeroization.

## Verification

```bash
python -m pip install -e '.[dev]'
pytest
ruff check src tests
ruff format --check src tests
mypy
python -m build
```

Live provider checks remain a separate gate. Run them only in a dedicated non-production account with one test secret and least-privilege read permissions; record exact account, service, and SDK version evidence without recording secret contents.

## Documentation

Read [architecture](docs/architecture/overview.md), [operations](docs/operations/README.md), [security](docs/security/overview.md), and [development](docs/development/README.md). Licensed under Apache-2.0.
