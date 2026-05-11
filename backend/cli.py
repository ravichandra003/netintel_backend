from __future__ import annotations

import argparse
import json
from pathlib import Path

from main import analyze


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run NetIntel IOC analysis from the command line using raw text or file input "
            "(.txt, .log, .csv, .docx, .pdf, .xlsx, .xls)."
        )
    )
    parser.add_argument(
        "input",
        nargs="?",
        help="Plain text to analyze OR a path to an input file.",
    )
    parser.add_argument(
        "--file",
        dest="file_path",
        help="Path to input file (use this when your input text could be confused with a file path).",
    )
    parser.add_argument(
        "--out",
        dest="output_path",
        help="Optional path to save JSON output. If omitted, prints to stdout.",
    )
    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    source = args.file_path or args.input
    if not source:
        parser.error("Provide either positional input text/path or --file.")

    result = analyze(source)
    payload = json.dumps(result, indent=2)

    if args.output_path:
        out_path = Path(args.output_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(payload)
        print(f"Saved analysis report to {out_path}")
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
