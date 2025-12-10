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
