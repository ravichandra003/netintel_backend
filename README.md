# NetIntel CLI

IOC analysis tool that runs locally from the command line.

## What it accepts

- Plain text input
- File input via path:
  - `.txt`, `.log`, `.csv`
  - `.docx`
  - `.pdf`
  - `.xlsx`, `.xls`

## Local run

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
python backend/cli.py "Suspicious IP 8.8.8.8 and mail user@example.com"
```

## Input from file

```bash
python backend/cli.py --file ./sample.txt
python backend/cli.py --file ./intel.docx --out ./report.json
```

The command prints JSON to stdout unless `--out` is provided.
