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
"""Vulnerability scanner for Python (pip-audit) and npm (npm audit) dependencies."""
from __future__ import annotations

import json  # noqa: TID251
import logging
import subprocess
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class Severity(Enum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_string(cls, value: str) -> Severity:
        normalized = value.lower().strip()
        mapping = {
            "low": cls.LOW,
            "moderate": cls.MODERATE,
            "medium": cls.MODERATE,
            "high": cls.HIGH,
            "critical": cls.CRITICAL,
        }
        return mapping.get(normalized, cls.MODERATE)

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        order = [Severity.LOW, Severity.MODERATE, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) >= order.index(other)

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        order = [Severity.LOW, Severity.MODERATE, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) > order.index(other)


@dataclass
class Vulnerability:
    """A single vulnerability finding."""

    package: str
    current_version: str
    cve_id: str
    severity: Severity
    fix_versions: list[str] = field(default_factory=list)
    description: str = ""
    ecosystem: str = "python"  # python | npm
    aliases: list[str] = field(default_factory=list)

    @property
    def has_fix(self) -> bool:
        return len(self.fix_versions) > 0

    @property
    def recommended_fix_version(self) -> str | None:
        return self.fix_versions[0] if self.fix_versions else None

    @property
    def issue_title(self) -> str:
        fix_suffix = (
            f" → {self.recommended_fix_version}" if self.has_fix else " (no fix)"
        )
        return (
            f"[{self.cve_id}] {self.severity.value.upper()}: "
            f"Upgrade {self.package} from {self.current_version}{fix_suffix}"
        )

    @property
    def issue_body(self) -> str:
        aliases_str = ", ".join(self.aliases) if self.aliases else "None"
        fix_str = (
            ", ".join(self.fix_versions)
            if self.fix_versions
            else "No fix available"
        )
        return f"""## Vulnerability Details
- **Package:** `{self.package}`
- **Ecosystem:** {self.ecosystem}
- **Current Version:** `{self.current_version}`
- **Fixed Versions:** {fix_str}
- **CVE:** `{self.cve_id}`
- **Aliases:** {aliases_str}
- **Severity:** {self.severity.value.upper()}

## Description
{self.description[:1000]}

## Remediation
{self._remediation_text()}

## Automation
This issue is tracked by the Devin vulnerability remediation pipeline.
"""

    def _remediation_text(self) -> str:
        if self.has_fix:
            fix_ver = self.recommended_fix_version
            return (
                f"Upgrade `{self.package}` to "
                f"`>={fix_ver}` and verify no "
                "breaking changes in the test suite."
            )
        return (
            "No automated fix available. "
            "Manual review required."
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "package": self.package,
            "current_version": self.current_version,
            "cve_id": self.cve_id,
            "severity": self.severity.value,
            "fix_versions": self.fix_versions,
            "description": self.description[:500],
            "ecosystem": self.ecosystem,
            "aliases": self.aliases,
            "has_fix": self.has_fix,
        }


def scan_python_dependencies(requirements_path: str) -> list[Vulnerability]:
    """Run pip-audit against a requirements file and return vulnerabilities."""
    logger.info("Scanning Python dependencies: %s", requirements_path)
    try:
        cmd = [
            "pip-audit",
            "-r",
            requirements_path,
            "--format",
            "json",
        ]
        result = subprocess.run(  # noqa: S603, S607
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except FileNotFoundError:
        logger.error("pip-audit not installed. Run: pip install pip-audit")
        return []
    except subprocess.TimeoutExpired:
        logger.error("pip-audit timed out after 300s")
        return []

    # pip-audit returns exit code 1 when vulnerabilities are found
    output = result.stdout
    if not output:
        logger.warning("pip-audit produced no output (stderr: %s)", result.stderr[:500])
        return []

    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        logger.error("Failed to parse pip-audit JSON output")
        return []

    vulnerabilities: list[Vulnerability] = []
    for dep in data.get("dependencies", []):
        for vuln in dep.get("vulns", []):
            vulnerabilities.append(
                Vulnerability(
                    package=dep["name"],
                    current_version=dep["version"],
                    cve_id=vuln["id"],
                    severity=Severity.from_string(
                        vuln.get("severity", "moderate")
                    ),
                    fix_versions=vuln.get("fix_versions", []),
                    description=vuln.get("description", ""),
                    ecosystem="python",
                    aliases=vuln.get("aliases", []),
                )
            )

    logger.info("Found %d Python vulnerabilities", len(vulnerabilities))
    return vulnerabilities


def _run_npm_audit(
    frontend_dir: str,
) -> dict[str, object] | None:
    """Execute npm audit and return parsed JSON."""
    try:
        cmd = ["npm", "audit", "--json"]
        result = subprocess.run(  # noqa: S603, S607
            cmd,
            capture_output=True,
            text=True,
            cwd=frontend_dir,
            timeout=120,
        )
    except FileNotFoundError:
        logger.error("npm not found")
        return None
    except subprocess.TimeoutExpired:
        logger.error("npm audit timed out after 120s")
        return None

    output = result.stdout
    if not output:
        logger.warning("npm audit produced no output")
        return None

    try:
        return json.loads(output)  # noqa: TID251
    except json.JSONDecodeError:  # noqa: TID251
        logger.error("Failed to parse npm audit JSON")
        return None


def _parse_npm_vuln(
    name: str,
    info: dict[str, object],
) -> Vulnerability:
    """Parse a single npm audit vulnerability entry."""
    severity = Severity.from_string(
        str(info.get("severity", "moderate"))
    )
    via_entries: list[object] = info.get("via", [])  # type: ignore[assignment]
    description_parts: list[str] = []
    cve_ids: list[str] = []
    fix_version = info.get("fixAvailable", {})

    for via in via_entries:
        if isinstance(via, dict):
            description_parts.append(via.get("title", ""))
            url = via.get("url", "")
            if "CVE-" in url or "GHSA-" in url:
                cve_ids.append(url.split("/")[-1])
            elif via.get("cwe"):
                cve_ids.append(str(via["cwe"]))

    cve_id = cve_ids[0] if cve_ids else f"NPM-{name}"
    desc = (
        "; ".join(filter(None, description_parts))
        or f"Vulnerability in {name}"
    )

    fix_ver = ""
    if isinstance(fix_version, dict):
        fix_ver = fix_version.get("version", "")
    elif isinstance(fix_version, bool) and fix_version:
        fix_ver = "latest"

    return Vulnerability(
        package=name,
        current_version=str(info.get("range", "unknown")),
        cve_id=cve_id,
        severity=severity,
        fix_versions=[fix_ver] if fix_ver else [],
        description=desc,
        ecosystem="npm",
    )


def scan_npm_dependencies(
    frontend_dir: str,
) -> list[Vulnerability]:
    """Run npm audit and return vulnerabilities."""
    logger.info(
        "Scanning npm dependencies in: %s", frontend_dir
    )
    data = _run_npm_audit(frontend_dir)
    if data is None:
        return []

    vulns_dict: dict[str, object] = data.get(  # type: ignore[assignment]
        "vulnerabilities", {}
    )
    vulnerabilities = [
        _parse_npm_vuln(name, info)  # type: ignore[arg-type]
        for name, info in vulns_dict.items()
    ]

    logger.info(
        "Found %d npm vulnerabilities", len(vulnerabilities)
    )
    return vulnerabilities


def run_full_scan(
    python_requirements: str = "requirements/base.txt",
    frontend_dir: str = "superset-frontend",
    severity_threshold: str = "moderate",
) -> list[Vulnerability]:
    """Run all scanners and return combined, filtered, deduplicated results."""
    threshold = Severity.from_string(severity_threshold)

    all_vulns: list[Vulnerability] = []
    all_vulns.extend(scan_python_dependencies(python_requirements))
    all_vulns.extend(scan_npm_dependencies(frontend_dir))

    # Filter by severity threshold
    filtered = [v for v in all_vulns if v.severity >= threshold]

    # Deduplicate by (package, cve_id)
    seen: set[tuple[str, str]] = set()
    deduped: list[Vulnerability] = []
    for v in filtered:
        key = (v.package, v.cve_id)
        if key not in seen:
            seen.add(key)
            deduped.append(v)

    logger.info(
        "Scan complete: %d total, %d above threshold, %d unique",
        len(all_vulns),
        len(filtered),
        len(deduped),
    )
    return deduped


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    vulns = run_full_scan()
    print(json.dumps([v.to_dict() for v in vulns], indent=2))  # noqa: TID251
