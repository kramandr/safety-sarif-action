# Safety SARIF Converter GitHub Action

This action converts [Safety](https://github.com/pyupio/safety) Python dependency scan output to [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) so that findings can be uploaded to GitHub Advanced Security (GHAS) Code Scanning.

## Inputs

- `input-file` (required): Path to the Safety JSON output file (e.g. `safety-report.json`).
- `output-file` (required): Path to the SARIF file to write (e.g. `safety-results.sarif`).
- `tool-version` (optional): Safety CLI version (for metadata).

## Outputs

- `sarif-file`: Path to the generated SARIF file.
- `findings-count`: Number of Safety findings converted.

## Example usage

```yaml
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
