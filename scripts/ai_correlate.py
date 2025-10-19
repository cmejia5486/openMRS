#!/usr/bin/env python3
"""
ai_correlate.py -- correlate security scan reports with a security requirements checklist


Runs in CI after security scans complete. It reads a JSON checklist,
parses JSON reports, and asks an OpenAI model to correlate findings
to requirements and produce a Markdown summary.

Usage:
  python ai_correlate.py --checklist requirements/checklist.json \
                         --reports reports \
                         --output report/ai_summary.md

Environment:
  OPENAI_API_KEY  (required)
  OPENAI_MODEL                  (optional; default: o4-mini for reasoning; fallback: gpt-4o)
  OPENAI_REASONING_EFFORT       (optional; SDK>=1.x only; default: medium)  # low|medium|high
  OPENAI_MAX_OUTPUT_TOKENS      (optional; default: 1500)
"""

import argparse
import json
import os
import sys
from typing import List, Dict, Any

# --- Detect OpenAI SDK: prefer >=1.x (Responses/Chat Completions); fallback to legacy 0.27/0.28 ---
HAVE_NEW_SDK = False
OpenAIClient = None
openai_legacy = None
try:
    from openai import OpenAI as OpenAIClient  # SDK >= 1.x
    HAVE_NEW_SDK = True
except Exception:
    try:
        import openai as openai_legacy  # SDK 0.27/0.28
        HAVE_NEW_SDK = False
    except Exception as e:
        print("ERROR: Could not import OpenAI SDK. Install either 'openai>=1.0.0' or 'openai==0.28'.", file=sys.stderr)
        print(f"Detail: {e}", file=sys.stderr)
        sys.exit(1)

# Models where temperature is NOT supported (reasoning models).
REASONING_MODELS = {"o4", "o4-mini", "o3", "o3-mini"}


def load_checklist(path: str) -> List[Dict[str, Any]]:
    """Load checklist JSON. Supports either a list or an object with one top-level key."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict) and len(data) == 1:
        first_key = next(iter(data))
        if isinstance(data[first_key], list):
            return data[first_key]
    if isinstance(data, list):
        return data
    raise ValueError(f"Unsupported checklist format in {path}")


def parse_reports(reports_dir: str) -> List[Any]:
    """Recursively load JSON reports from the given directory (only *.json)."""
    if not os.path.isdir(reports_dir):
        # No reports directory—return empty list; the prompt will handle it.
        return []
    findings = []
    for root, _, files in os.walk(reports_dir):
        for fname in files:
            if fname.lower().endswith(".json"):
                path = os.path.join(root, fname)
                try:
                    with open(path, encoding="utf-8") as fh:
                        findings.append(json.load(fh))
                except Exception:
                    # ignore unreadable/malformed files
                    continue
    return findings


def create_prompt(checklist: List[Dict[str, Any]], findings: List[Any]) -> str:
    """Build the analysis prompt combining checklist + compacted findings."""
    lines: List[str] = []
    lines.append(
        "You are a security analyst. Map the following scan findings to the security requirements provided. "
        "For each requirement, state whether it is satisfied, violated, or unknown based on the evidence. "
        "Provide a short explanation and reference relevant identifiers (CWE, CVE, rule names). "
        "Conclude with a concise overall risk summary."
    )
    lines.append("\n\nSecurity requirements:\n")
    for req in checklist:
        ident = req.get("id") or req.get("numero") or req.get("identifier") or ""
        desc = req.get("description") or req.get("descripcion") or req.get("name") or ""
        lines.append(f"- {ident}: {desc}")

    lines.append("\n\nScan findings (JSON excerpt):\n")
    # Truncate to keep prompt bounded (~5000 chars)
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


def _call_openai_new_sdk(prompt: str, api_key: str, model: str, max_output_tokens: int, effort: str) -> str:
    """
    Preferred path for SDK >= 1.x.
    - For reasoning models (o4, o4-mini, o3, ...): use Responses WITHOUT temperature.
    - For general models (gpt-4o, gpt-4o-mini, ...): use Responses WITH temperature and allow Chat fallback.
    """
    client = OpenAIClient(api_key=api_key)
    is_reasoning = model in REASONING_MODELS

    system_preamble = "You are a helpful security auditor."
    unified_input = system_preamble + "\n\n" + prompt

    # --- Responses API (primary path) ---
    try:
        kwargs = dict(
            model=model,
            input=unified_input,
            max_output_tokens=max_output_tokens,
        )
        if is_reasoning:
            # Reasoning models don't accept temperature; include effort.
            kwargs["reasoning"] = {"effort": effort}
        else:
            # Non-reasoning models can accept temperature.
            kwargs["temperature"] = 0.3

        resp = client.responses.create(**kwargs)
        text = getattr(resp, "output_text", None)
        if not text:
            # Best-effort stitching if output_text is missing
            try:
                parts = []
                for item in getattr(resp, "output", []) or []:
                    for c in getattr(item, "content", []) or []:
                        t = getattr(c, "text", None)
                        if isinstance(t, str):
                            parts.append(t)
                text = "\n".join(p for p in parts if p).strip()
            except Exception:
                text = ""
        if text:
            return text.strip()
        responses_err = RuntimeError("Empty response text from Responses API.")
    except Exception as e_responses:
        responses_err = e_responses

    # If it's a reasoning model, don't fallback to Chat (muchas veces no existe el alias en Chat).
    if is_reasoning:
        raise RuntimeError(f"Responses failed for reasoning model '{model}': {responses_err}")

    # --- Fallback: Chat Completions (solo para modelos no-reasoning, p.ej. gpt-4o) ---
    try:
        resp2 = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a helpful security auditor."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=max_output_tokens,
            temperature=0.3,
        )
        return resp2.choices[0].message.content.strip()
    except Exception as e_chat:
        raise RuntimeError(f"Both Responses and Chat Completions failed. Responses error: {responses_err}; Chat error: {e_chat}")


def _call_openai_legacy(prompt: str, api_key: str, model: str, max_output_tokens: int) -> str:
    """Legacy path for SDK 0.27/0.28 (openai.ChatCompletion)."""
    openai_legacy.api_key = api_key
    resp = openai_legacy.ChatCompletion.create(
        model=model,
        messages=[
            {"role": "system", "content": "You are a helpful security auditor."},
            {"role": "user", "content": prompt},
        ],
        max_tokens=max_output_tokens,
        temperature=0.3,
    )
    return resp["choices"][0]["message"]["content"].strip()


def call_openai(prompt: str, api_key: str) -> str:
    """Dispatch to new SDK (Responses primary; Chat fallback only if non-reasoning) or legacy SDK."""
    try:
        max_output_tokens = int(os.getenv("OPENAI_MAX_OUTPUT_TOKENS", "1500"))
    except ValueError:
        max_output_tokens = 1500

    # Default to a reasoning model if none provided.
    model = os.getenv("OPENAI_MODEL", "o4-mini")
    effort = os.getenv("OPENAI_REASONING_EFFORT", "medium")

    if HAVE_NEW_SDK and OpenAIClient is not None:
        return _call_openai_new_sdk(prompt, api_key, model, max_output_tokens, effort)

    # Legacy default (si alguien fija openai==0.28)
    if openai_legacy is None:
        raise RuntimeError("Legacy OpenAI SDK not available and new SDK import failed.")
    legacy_model = os.getenv("OPENAI_MODEL", "gpt-4")
    return _call_openai_legacy(prompt, api_key, legacy_model, max_output_tokens)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Correlate scan findings with security requirements using an AI model."
    )
    parser.add_argument("--checklist", required=True, help="Path to JSON checklist file")
    parser.add_argument("--reports", required=True, help="Directory containing scan report artifacts")
    parser.add_argument("--output", required=True, help="Path to write AI summary (Markdown)")
    args = parser.parse_args()

    # Load inputs
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

    # API key
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("OPENAI_API_KEY environment variable is not set", file=sys.stderr)
        sys.exit(1)

    # Call model
    try:
        summary = call_openai(prompt, api_key)
    except Exception as exc:
        print(f"Failed to call OpenAI API: {exc}", file=sys.stderr)
        sys.exit(1)

    # Ensure output directory
    out_path = os.path.abspath(args.output)
    out_dir = os.path.dirname(out_path)
    if out_dir and not os.path.isdir(out_dir):
        os.makedirs(out_dir, exist_ok=True)

    # Write output
    try:
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(summary)
    except Exception as e:
        print(f"Failed to write output file '{out_path}': {e}", file=sys.stderr)
        sys.exit(1)

    print(f"AI summary written to {out_path}")


if __name__ == "__main__":
    main()
