# Safety SARIF Converter - GitHub Action

This action converts [Safety](https://github.com/pyupio/safety) Python dependency scan output to [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) so that findings can be uploaded to GitHub Advanced Security (GHAS) Code Scanning.

## Inputs

- `input-file`: Path to the Safety JSON output file (e.g. `safety-report.json`).
- `output-file`: Path to the SARIF file to write (e.g. `safety-results.sarif`).
- `tool-version`: Safety CLI version (for metadata).

## Outputs

- `sarif-file`: Path to the generated SARIF file.
- `findings-count`: Number of Safety findings converted.

## Github Actions Usage (Recommended Workflow)

```yaml
name: safety-scan

on:
  push:
  pull_request:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
          pip install safety

      - name: Run Safety
        run: |
          safety check --file=requirements.txt --json > safety-report.json

      - name: Convert Safety output to SARIF
        uses: kramandr/safety-sarif-action@v1
        with:
          input-file: safety-report.json
          output-file: safety-results.sarif
          tool-version: "3.0.0"

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: safety-results.sarif
```

## Severity Mapping & Limitations

This action is designed to populate SARIF severity fields (`result.level` and
`rules[].properties["security-severity"]`) so that GitHub Code Scanning can
display High / Medium / Low alerts.

However, in the current version of the Safety CLI, the **JSON report does not
include per-vulnerability severity or CVSS scores**. The human-readable
terminal output mentions severities, but the machine-readable JSON does not.

To avoid inventing or guessing risk levels that the underlying tool did not
provide, this action takes the following approach:

- All findings are emitted with SARIF `level: "warning"`.
- `properties["security-severity"]` is set to a neutral “medium-like” value
  (e.g., `"5.0"`).
- `properties["original_severity"]` is set to `"unknown"` to reflect that
  Safety did not provide a structured severity value for this finding.

The mapping logic (`map_severity_to_level`, `map_severity_to_security_severity`)
is implemented and ready to consume real severity / CVSS data if Safety adds it
to the JSON in the future, but **we intentionally do not fabricate severities**
from text output or heuristics.

## Input Format Support (detailed)

### Safety JSON (3.x)
The converter accepts the modern Safety **`scan`** JSON format and expects the following structure:

```
scan_results
└── projects[]
    └── files[]
        └── results.dependencies[]
            └── specifications[]
                └── vulnerabilities.known_vulnerabilities[]
```

Key fields extracted:

- Package name  
- Vulnerable specification / installed version  
- Vulnerability ID  
- Advisory / description text  
- Remediation (recommended fixed version)  
- Optional metadata: CVSS score, CVE IDs, CWE IDs  

### Legacy Safety JSON (v1.1)
The converter also supports the older format where Safety emits:

```json
{
  "vulnerabilities": [
    {
      "package": "...",
      "installed_version": "...",
      "id": "...",
      "advisory": "...",
      "fixed_versions": [...],
      "cve_ids": [...],
      "cwe_ids": [...],
      "cvss_score": ...
    }
  ]
}
```

### Robustness
- Handles empty arrays without failing.  
- Malformed entries are **skipped with warnings**, allowing the rest of the report to convert successfully.

---

## Output Format (SARIF 2.1.0) (detailed)

The converter emits a fully structured **SARIF 2.1.0** document containing:

### Top-Level Structure
```
runs[0].tool.driver
    name
    version
    informationUri
    rules[]     # one rule per unique vulnerability ID

runs[0].results[]
```

### Result Mapping (Per Vulnerability)

Each Safety finding is converted into a SARIF `result` entry with:

| SARIF Field | Description |
|-------------|-------------|
| `ruleId` | `SAFETY-<vulnerability_id>` |
| `level` | Severity mapped from textual severity or CVSS (`error`, `warning`, `note`) |
| `message.text` | `<package> <version>: <advisory/description>` |
| `locations[0].physicalLocation.artifactLocation.uri` | `dependencies/<package>` (pseudo-path) |
| `properties` | Additional metadata: `package`, `installed_version`, `original_severity`, plus optional `fixed_versions`, `cve_ids`, `cwe_ids`, `cvss_score` |

### Rule Definitions

`driver.rules[]` contains one entry per unique vulnerability ID, including:

- Short and full descriptions  
- Recommended remediation guidance  
- `security-severity` (CVSS numeric string or mapped fallback)  
- Tags such as: `security`, `dependency`, `python`, `safety`  

