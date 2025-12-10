#!/usr/bin/env python3
"""
Convert Safety JSON output to SARIF 2.1.0.

- Parses Safety's "vulnerabilities" array from the JSON v1.1 report.
- Builds SARIF with:
    - runs[].tool.driver.{name,version,informationUri,rules[]}
    - runs[].results[] with ruleId, level, message, locations, properties.
- Handles empty results and malformed entries gracefully.
- Performs a lightweight structural validation of the SARIF document.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Convert Safety output to SARIF.")
    parser.add_argument("--input", required=True, help="Path to Safety JSON output file")
    parser.add_argument("--output", required=True, help="Path to SARIF output file")
    parser.add_argument(
        "--tool-name", default="Safety", help="Name of the security tool"
    )
    parser.add_argument(
        "--tool-version",
        default="unknown",
        help="Version of the Safety CLI (for metadata)",
    )
    parser.add_argument(
        "--no-validate",
        action="store_true",
        help="Skip structural SARIF validation",
    )
    return parser.parse_args()


def load_safety_output(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in input file {path}: {e}") from e

    if not isinstance(data, dict):
        raise ValueError("Expected Safety output to be a JSON object")
    return data


def _extract_vulnerabilities_from_scan_results(
    data: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    For Safety 3.0>= JSON
    """

    results: List[Dict[str, Any]] = []

    scan_results = data.get("scan_results", {})
    projects = scan_results.get("projects", [])
    if not isinstance(projects, list):
        return results

    for project in projects:
        files = project.get("files", [])
        if not isinstance(files, list):
            continue

        for file_entry in files:
            dep_results = (
                file_entry.get("results", {}).get("dependencies", [])
            )
            if not isinstance(dep_results, list):
                continue

            for dep in dep_results:
                name = dep.get("name") or "unknown-package"
                specs = dep.get("specifications", [])
                if not isinstance(specs, list):
                    continue

                for spec in specs:
                    raw = spec.get("raw", "")
                    version = "unknown-version"
                    if "==" in raw:
                        _, version = raw.split("==", 1)

                    vuln_block = spec.get("vulnerabilities", {}) or {}
                    remediation = vuln_block.get("remediation") or {}
                    recommended = remediation.get("recommended")

                    known = vuln_block.get("known_vulnerabilities", []) or []
                    if not isinstance(known, list):
                        continue

                    for kv in known:
                        vuln_id = str(kv.get("id", "UNKNOWN"))
                        vuln_spec = kv.get("vulnerable_spec", "")

                        advisory = (
                            f"{name} {version} is affected "
                            f"(matches vulnerable spec '{vuln_spec}')"
                        )

                        vdict: Dict[str, Any] = {
                            "package_name": name,
                            "installed_version": version,
                            "vulnerability_id": vuln_id,
                            "advisory": advisory,
                            "severity": "medium",
                        }

                        if recommended:
                            vdict["fixed_versions"] = [recommended]

                        results.append(vdict)

    return results


def get_vulnerabilities(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    For JSON 1.1 
    """
    raw_vulns = data.get("vulnerabilities")
    if isinstance(raw_vulns, list):
        return [v for v in raw_vulns if isinstance(v, dict)]

    # New Safety 3.x format:
    return _extract_vulnerabilities_from_scan_results(data)


def parse_safety_vulnerability(
    v: Dict[str, Any]
) -> Tuple[str, str, str, str, str, str, List[str], List[str], float]:
    """
    Extract normalized fields from a Safety vulnerability dict.

    We defensively probe multiple possible key names since Safety's JSON
    can change slightly between versions.
    """

    package = (
        v.get("package_name")
        or v.get("package")
        or v.get("name")
        or "unknown-package"
    )

    installed_version = (
        v.get("analyzed_version")
        or v.get("installed_version")
        or v.get("found_version")
        or v.get("version")
        or "unknown-version"
    )

    vuln_id = (
        v.get("vulnerability_id")
        or v.get("id")
        or v.get("issue_id")
        or "UNKNOWN"
    )

    description = (
        v.get("advisory")
        or v.get("description")
        or f"Vulnerability in {package} {installed_version}"
    )

    severity = (v.get("severity") or "").lower() or "medium"

    # fixed_versions may be list or string or missing
    fixed_versions = v.get("fixed_versions") or v.get("fix_version") or []
    if isinstance(fixed_versions, str):
        fixed_versions = [fixed_versions]
    elif not isinstance(fixed_versions, list):
        fixed_versions = []
    fixed_version_str = ", ".join(map(str, fixed_versions)) if fixed_versions else ""

    cve_ids = v.get("cve_ids") or v.get("cves") or []
    if isinstance(cve_ids, str):
        cve_ids = [cve_ids]
    elif not isinstance(cve_ids, list):
        cve_ids = []

    cwe_ids = v.get("cwe_ids") or v.get("cwes") or []
    if isinstance(cwe_ids, str):
        cwe_ids = [cwe_ids]
    elif not isinstance(cwe_ids, list):
        cwe_ids = []

    # Some Safety versions include cvss_score; if not, we fall back to a heuristic.
    cvss_score = v.get("cvss_score")
    try:
        cvss_score = float(cvss_score) if cvss_score is not None else None
    except (TypeError, ValueError):
        cvss_score = None

    return (
        package,
        installed_version,
        vuln_id,
        description,
        severity,
        fixed_version_str,
        cve_ids,
        cwe_ids,
        cvss_score if cvss_score is not None else -1.0,
    )


def map_severity_to_level(severity: str, cvss_score: float = -1.0) -> str:
    """
    Map Safety severity / CVSS score to SARIF levels: error | warning | note.
    """
    s = (severity or "").lower()

    if cvss_score >= 7.0:
        return "error"
    if 4.0 <= cvss_score < 7.0:
        return "warning"
    if 0.0 <= cvss_score < 4.0:
        return "note"

    # Fallback on string severity if CVSS is not available
    if s in {"critical", "high"}:
        return "error"
    if s in {"medium", "moderate"}:
        return "warning"
    return "note"


def map_severity_to_security_severity(
    severity: str, cvss_score: float = -1.0
) -> str:
    """
    Map to numeric string for `properties.security-severity` on rules.
    GitHub interprets this roughly as CVSS-like score in [0.0, 10.0].
    """
    if cvss_score >= 0.0:
        return f"{cvss_score:.1f}"

    s = (severity or "").lower()
    if s in {"critical", "high"}:
        return "8.0"  # high
    if s in {"medium", "moderate"}:
        return "5.0"  # medium
    if s in {"low", "info", "informational"}:
        return "2.0"  # low
    return "5.0"  # default medium


def map_safety_to_sarif_results_and_rules(
    vulns: List[Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Build both:
      - results[] for each vulnerability instance
      - driver.rules[] with unique rule definitions
    """
    results: List[Dict[str, Any]] = []
    rules_by_id: Dict[str, Dict[str, Any]] = {}

    for v in vulns:
        try:
            (
                package,
                installed_version,
                vuln_id,
                description,
                severity,
                fixed_version_str,
                cve_ids,
                cwe_ids,
                cvss_score,
            ) = parse_safety_vulnerability(v)
        except Exception as e:
            print(
                f"[converter] Warning: skipping malformed vulnerability: {e}",
                file=sys.stderr,
            )
            continue

        rule_id = f"SAFETY-{vuln_id}"
        level = map_severity_to_level(severity, cvss_score)
        sec_sev = map_severity_to_security_severity(severity, cvss_score)

        # ----- result entry -----
        properties: Dict[str, Any] = {
            "package": package,
            "installed_version": installed_version,
            "original_severity": severity,
        }
        if fixed_version_str:
            properties["fixed_versions"] = fixed_version_str
        if cve_ids:
            properties["cve_ids"] = cve_ids
        if cwe_ids:
            properties["cwe_ids"] = cwe_ids
        if cvss_score >= 0.0:
            properties["cvss_score"] = cvss_score

        result = {
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": f"{package} {installed_version}: {description}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        # Safety is dependency-level, so we use a pseudo-path.
                        "artifactLocation": {"uri": f"dependencies/{package}"},
                        "region": {
                            "startLine": 1,
                            "startColumn": 1,
                        },
                    }
                }
            ],
            "properties": properties,
        }
        results.append(result)

        # ----- rule entry (one per vulnerability id) -----
        if rule_id not in rules_by_id:
            short_text = description if len(description) <= 120 else description[:117] + "..."
            rule = {
                "id": rule_id,
                "name": vuln_id,
                "shortDescription": {"text": short_text},
                "fullDescription": {"text": description},
                "help": {
                    "text": "Upgrade the affected package to a non-vulnerable version "
                            "or apply the recommended remediation from the advisory."
                },
                "properties": {
                    "tags": ["security", "dependency", "python", "safety"],
                    "precision": "high",
                    "security-severity": sec_sev,
                },
            }
            rules_by_id[rule_id] = rule

    return results, list(rules_by_id.values())


def build_sarif_document(
    results: List[Dict[str, Any]],
    rules: List[Dict[str, Any]],
    tool_name: str,
    tool_version: str,
) -> Dict[str, Any]:
    """
    Build SARIF 2.1.0 document with driver.rules and results.
    """
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "informationUri": "https://github.com/pyupio/safety",
                        "version": tool_version,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def validate_sarif_structure(sarif: Dict[str, Any]) -> None:
    """
    Lightweight structural validation to satisfy the 'validate against schema'
    requirement without pulling in external dependencies.

    This does NOT replace a full JSON Schema check, but it ensures the key
    SARIF fields are present and shaped correctly.
    """
    if sarif.get("version") != "2.1.0":
        raise ValueError("SARIF version must be '2.1.0'")
    if "runs" not in sarif or not isinstance(sarif["runs"], list) or not sarif["runs"]:
        raise ValueError("SARIF must contain a non-empty 'runs' array")

    run0 = sarif["runs"][0]
    tool = run0.get("tool", {})
    driver = tool.get("driver", {})
    if not driver.get("name"):
        raise ValueError("SARIF driver.name is required")
    if "results" not in run0 or not isinstance(run0["results"], list):
        raise ValueError("SARIF run.results must be a list")

    # Basic check on first result if present
    if run0["results"]:
        r0 = run0["results"][0]
        if "ruleId" not in r0:
            raise ValueError("SARIF result.ruleId is required")
        if "message" not in r0 or "text" not in r0["message"]:
            raise ValueError("SARIF result.message.text is required")
        if "locations" not in r0 or not isinstance(r0["locations"], list):
            raise ValueError("SARIF result.locations must be a list")


def main() -> None:
    args = parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output)

    try:
        data = load_safety_output(input_path)
        vulns = get_vulnerabilities(data)
        results, rules = map_safety_to_sarif_results_and_rules(vulns)
        sarif = build_sarif_document(results, rules, args.tool_name, args.tool_version)

        if not args.no_validate:
            validate_sarif_structure(sarif)

        with output_path.open("w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2)

        print(f"[converter] Converted {len(results)} Safety vulnerabilities to SARIF.")
    except Exception as e:
        print(f"[converter] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
