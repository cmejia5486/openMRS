#!/usr/bin/env python3
"""
ai_correlate.py -- correlate security scan reports with a security requirements checklist

This utility is intended to run in a CI/CD environment after various
security scanning workflows have completed.  It reads a JSON-formatted
checklist of security requirements (e.g. `requirements/checklist.json`),
parses the results from multiple scan tools stored as JSON or SARIF
artifacts, and uses a Large Language Model (LLM) to correlate
findings to requirements and produce a natural language summary.

Usage:
    python ai_correlate.py --checklist requirements/checklist.json \
                           --reports reports \
                           --output report/ai_summary.md

Environment:
    OPENAI_API_KEY must be set to a valid OpenAI API key.  The script
    will use the GPT-4 model by default.

Note:
    The summary generation consumes tokens proportionally to the size of
    the checklist and scan results.  Consider truncating large scan
    reports or filtering only relevant fields before invoking the AI.
"""

import argparse
import json
import os
import sys
import glob
from typing import List, Dict, Any

try:
    import openai  # type: ignore
except ImportError:
    openai = None  # will raise later


def load_checklist(path: str) -> List[Dict[str, Any]]:
    """Load checklist JSON.  Supports either a list or an object with
    a top-level key (e.g. `{ "requisitos": [...] }`)."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    # unwrap simple wrapper keys
    if isinstance(data, dict) and len(data) == 1:
        first_key = next(iter(data))
        if isinstance(data[first_key], list):
            return data[first_key]
    if isinstance(data, list):
        return data
    raise ValueError(f"Unsupported checklist format in {path}")


def parse_reports(reports_dir: str) -> List[Any]:
    """Recursively load JSON reports from the given directory.

    This function ignores files that cannot be parsed as JSON.  For
    SARIF files, you may want to pre-convert them to JSON or only
    extract relevant sections.  Here we treat any `.json` file as
    potential input.
    """
    findings = []
    for root, _, files in os.walk(reports_dir):
        for fname in files:
            if fname.lower().endswith(".json"):
                path = os.path.join(root, fname)
                try:
                    with open(path, encoding="utf-8") as fh:
                        findings.append(json.load(fh))
                except Exception:
                    # ignore non-JSON or malformed files
                    continue
    return findings


def create_prompt(checklist: List[Dict[str, Any]], findings: List[Any]) -> str:
    """Construct a prompt for the AI model combining the checklist and findings.

    The prompt instructs the model to map scan findings to each
    requirement based on identifiers (e.g. CWE, CVE, rule names) and
    summarise the status of each requirement.
    """
    lines: List[str] = []
    lines.append(
        "You are a security analyst. Map the following scan findings to the security requirements provided. "
        "For each requirement, state whether it is satisfied, violated, or unknown based on the evidence. "
        "Provide a short explanation and reference relevant finding identifiers (CWE, CVE, rule names)."
    )
    lines.append("\n\nSecurity requirements:\n")
    for req in checklist:
        ident = req.get("id") or req.get("numero") or req.get("identifier") or ""
        desc = req.get("description") or req.get("descripcion") or req.get("name") or ""
        lines.append(f"- {ident}: {desc}")
    lines.append("\n\nScan findings (JSON excerpt):\n")
    # Flatten and truncate findings to avoid huge prompts.  Include at most 5000 characters.
    char_budget = 5000
    content = ""
    for report in findings:
        snippet = json.dumps(report, ensure_ascii=False)[:1000]
        if len(content) + len(snippet) > char_budget:
            break
        content += snippet + "\n"
    lines.append(content)
    lines.append(
        "\nPlease produce a report summarising compliance status per requirement."
    )
    return "\n".join(lines)


def call_openai(prompt: str, api_key: str) -> str:
    """Invoke the OpenAI ChatCompletion API with the given prompt."""
    if openai is None:
        raise RuntimeError(
            "openai Python package is not installed. Add it to your requirements."
        )
    openai.api_key = api_key
    response = openai.ChatCompletion.create(
        model="gpt-4",  # adjust to your subscribed model
        messages=[
            {"role": "system", "content": "You are a helpful security auditor."},
            {"role": "user", "content": prompt},
        ],
        max_tokens=1500,
        temperature=0.3,
    )
    # extract the assistant's reply
    return response["choices"][0]["message"]["content"].strip()


def main() -> None:
    parser = argparse.ArgumentParser(description="Correlate scan findings with security requirements using an AI model.")
    parser.add_argument("--checklist", required=True, help="Path to JSON checklist file")
    parser.add_argument("--reports", required=True, help="Directory containing scan report artifacts")
    parser.add_argument("--output", required=True, help="Path to write AI summary (Markdown)")
    args = parser.parse_args()

    checklist = load_checklist(args.checklist)
    findings = parse_reports(args.reports)
    prompt = create_prompt(checklist, findings)

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("OPENAI_API_KEY environment variable is not set", file=sys.stderr)
        sys.exit(1)
    try:
        summary = call_openai(prompt, api_key)
    except Exception as exc:
        print(f"Failed to call OpenAI API: {exc}", file=sys.stderr)
        sys.exit(1)
    # ensure output directory exists
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(summary)
    print(f"AI summary written to {args.output}")


if __name__ == "__main__":
    main()