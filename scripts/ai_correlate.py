#!/usr/bin/env python3
"""
ai_correlate.py -- correlate security scan reports with a security requirements checklist

This utility is intended to run in a CI/CD environment after various
security scanning workflows have completed. It reads a JSON-formatted
checklist of security requirements (e.g. `requirements/checklist.json`),
parses the results from multiple scan tools stored as JSON or SARIF
artifacts, and uses an OpenAI model to correlate findings to requirements
and produce a natural language summary.

Usage:
    python ai_correlate.py --checklist requirements/checklist.json \
                           --reports reports \
                           --output report/ai_summary.md

Environment:
    OPENAI_API_KEY must be set to a valid OpenAI API key.
    Optional:
      - OPENAI_MODEL (default: gpt-5-turbo)
      - OPENAI_REASONING_EFFORT (default: medium)  # one of: low|medium|high
      - OPENAI_MAX_OUTPUT_TOKENS (default: 1500)

Notes:
    - The summary generation consumes tokens proportionally to the size of
      the checklist and scan results. Consider truncating large scan reports
      or filtering only relevant fields before invoking the AI.
    - This script uses the OpenAI Python SDK >= 1.0 (Responses API).
"""

import argparse
import json
import os
import sys
from typing import List, Dict, Any

# OpenAI SDK >= 1.0
try:
    from openai import OpenAI
except Exception as e:
    print("Failed to import OpenAI SDK (openai>=1.0.0 required):", e, file=sys.stderr)
    sys.exit(1)


def load_checklist(path: str) -> List[Dict[str, Any]]:
    """Load checklist JSON. Supports either a list or an object with
    a single top-level key (e.g. `{ "requisitos": [...] }`)."""
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

    This function ignores files that cannot be parsed as JSON. For SARIF files,
    you may want to pre-convert them to JSON or only extract relevant sections.
    Here we treat any `.json` file as potential input.
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

    The prompt instructs the model to map scan findings to each requirement
    based on identifiers (e.g. CWE, CVE, rule names) and summarise the status
    of each requirement.
    """
    lines: List[str] = []
    lines.append(
        "You are a security analyst. Map the following scan findings to the security requirements provided. "
        "For each requirement, state whether it is satisfied, violated, or unknown based on the evidence. "
        "Provide a short explanation and reference relevant finding identifiers (CWE, CVE, rule names). "
        "Conclude with a concise overall risk summary."
    )
    lines.append("\n\nSecurity requirements:\n")
    for req in checklist:
        ident = req.get("id") or req.get("numero") or req.get("identifier") or ""
        desc = req.get("description") or req.get("descripcion") or req.get("name") or ""
        lines.append(f"- {ident}: {desc}")

    lines.append("\n\nScan findings (JSON excerpt):\n")
    # Flatten and truncate findings to avoid huge prompts. Include at most ~5000 characters.
    char_budget = 5000
    content = ""
    for report in findings:
        snippet = json.dumps(report, ensure_ascii=False)[:1000]
        if len(content) + len(snippet) > char_budget:
            break
        content += snippet + "\n"
    if not content:
        content = "(No findings JSON available in the provided reports directory.)\n"
    lines.append(content)

    lines.append(
        "\nPlease produce a Markdown report with a section per requirement (status + rationale) and an overall summary."
    )
    return "\n".join(lines)


def call_openai(prompt: str, api_key: str) -> str:
    """Invoke the OpenAI Responses API with the given prompt (SDK >= 1.0)."""
    model = os.getenv("OPENAI_MODEL", "gpt-5-turbo")
    effort = os.getenv("OPENAI_REASONING_EFFORT", "medium")
    try:
        max_output_tokens = int(os.getenv("OPENAI_MAX_OUTPUT_TOKENS", "1500"))
    except ValueError:
        max_output_tokens = 1500

    client = OpenAI(api_key=api_key)

    # You can pass either a single string or a list of chat-like messages to `input`.
    resp = client.responses.create(
        model=model,
        input=[
            {"role": "system", "content": "You are a helpful security auditor."},
            {"role": "user", "content": prompt},
        ],
        reasoning={"effort": effort},
        max_output_tokens=max_output_tokens,
        temperature=0.3,
    )

    # Prefer the convenience field output_text; fall back to assembling content.
    text = getattr(resp, "output_text", None)
    if not text:
        # Fallback: try to stitch text from the content parts if needed.
        try:
            parts = []
            for item in getattr(resp, "output", []) or []:
                for c in getattr(item, "content", []) or []:
                    if getattr(c, "type", None) == "output_text" or "text" in c.__dict__:
                        parts.append(getattr(c, "text", "") or "")
            text = "\n".join(p for p in parts if p).strip()
        except Exception:
            text = ""
    if not text:
        raise RuntimeError("OpenAI response did not contain text output.")
    return text


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Correlate scan findings with security requirements using an AI model."
    )
    parser.add_argument("--checklist", required=True, help="Path to JSON checklist file")
    parser.add_argument("--reports", required=True, help="Directory containing scan report artifacts")
    parser.add_argument("--output", required=True, help="Path to write AI summary (Markdown)")
    args = parser.parse_args()

    try:
        checklist = load_checklist(args.checklist)
    except Exception as e:
        print(f"Failed to load checklist: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        findings = parse_reports(args.reports)
    except Exception as e:
        print(f"Failed to parse reports: {e}", file=sys.stderr)
        sys.exit(1)

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
