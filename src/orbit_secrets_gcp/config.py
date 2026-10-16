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
"""Validated Google Cloud Secret Manager request limits."""

from pydantic import BaseModel, ConfigDict, Field, StrictInt


class GCPSecretsConfig(BaseModel):
    """Bound request time and concurrency for the async GAPIC secret client."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True, validate_default=True)

    request_timeout_seconds: float = Field(default=10.0, gt=0, le=120)
    max_concurrency: StrictInt = Field(default=8, ge=1, le=128)
