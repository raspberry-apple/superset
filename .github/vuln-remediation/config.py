# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""Configuration for the vulnerability remediation pipeline."""
from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class PipelineConfig:
    """Immutable configuration for the vulnerability remediation pipeline."""

    # GitHub
    github_token: str = field(
        default_factory=lambda: os.environ.get("GITHUB_TOKEN", "")
    )
    github_repo: str = field(
        default_factory=lambda: os.environ.get(
            "GITHUB_REPO", "raspberry-apple/superset"
        )
    )

    # Devin API
    devin_api_token: str = field(
        default_factory=lambda: os.environ.get("DEVIN_API_TOKEN", "")
    )
    devin_api_base: str = "https://api.devin.ai/v1"

    # Scanning
    python_requirements: str = "requirements/base.txt"
    frontend_dir: str = "superset-frontend"
    severity_threshold: str = "moderate"  # low, moderate, high, critical

    # Remediation
    max_concurrent_sessions: int = 3
    session_timeout_seconds: int = 1800  # 30 minutes
    auto_merge: bool = False  # require human approval

    # Labels
    issue_labels: list[str] = field(
        default_factory=lambda: ["security", "vulnerability", "automated"]
    )

    @property
    def github_api_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"token {self.github_token}",
            "Accept": "application/vnd.github.v3+json",
        }

    @property
    def devin_api_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.devin_api_token}",
            "Content-Type": "application/json",
        }
