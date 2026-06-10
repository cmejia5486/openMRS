#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validate the centralized prompt registry and LLM-call coverage.

This validator is intentionally strict for active prompt contracts. It checks
that every active LLM prompt contract has a stable identifier, script identifier,
transcript, output schema, control clauses, validation mechanisms, and metrics.
It also scans scripts/ and .github/ for common LLM-call patterns so direct prompt
calls are not introduced without registry coverage.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

REQUIRED_ACTIVE_FIELDS = [
    "prompt_id",
    "script_id",
    "prompt_name",
    "prompt_scope",
    "prompt_category",
    "is_auxiliary",
    "is_active",
    "source_file",
    "source_function",
    "system_prompt",
    "user_payload_contract",
    "required_output_schema",
    "control_clauses",
    "validation_mechanisms",
    "metrics",
]

LLM_CALL_PATTERNS = [
    r"responses\.create\s*\(",
    r"responses\.parse\s*\(",
    r"runtime\.create\s*\(",
    r"runtime\.parse\s*\(",
    r"client\.chat\.completions\.create\s*\(",
    r"\bcompletion\s*\(",
]

ALLOWED_RUNTIME_FILES = {
    "scripts/lib/ai_runtime.py",
}


def _load_json(path: Path) -> Dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"[ERROR] Could not parse {path}: {exc}")
    if not isinstance(data, dict):
        raise SystemExit(f"[ERROR] {path} must be a JSON object")
    return data


def _is_empty(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) == 0
    return False


def _validate_contracts(repo_root: Path, registry: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    contracts = registry.get("contracts")
    if not isinstance(contracts, list):
        return ["prompt_contracts.json must contain a contracts array"]

    seen_prompt_ids = set()
    active_count = 0
    for idx, contract in enumerate(contracts, start=1):
        if not isinstance(contract, dict):
            errors.append(f"contracts[{idx}] must be an object")
            continue
        pid = str(contract.get("prompt_id") or "").strip()
        if not pid:
            errors.append(f"contracts[{idx}] missing prompt_id")
            continue
        if pid in seen_prompt_ids:
            errors.append(f"duplicate prompt_id: {pid}")
        seen_prompt_ids.add(pid)
        if bool(contract.get("is_active", True)):
            active_count += 1
            for field in REQUIRED_ACTIVE_FIELDS:
                if field not in contract or _is_empty(contract.get(field)):
                    errors.append(f"{pid}: active contract missing {field}")
            sf = str(contract.get("source_file") or "")
            if sf and not (repo_root / sf).is_file():
                errors.append(f"{pid}: source_file does not exist: {sf}")
            clauses = contract.get("control_clauses")
            if isinstance(clauses, list):
                for cidx, clause in enumerate(clauses, start=1):
                    if not isinstance(clause, dict):
                        errors.append(f"{pid}: control_clauses[{cidx}] must be an object")
                        continue
                    for key in ("control_id", "control_name", "clause", "validation_mechanism", "metric"):
                        if _is_empty(clause.get(key)):
                            errors.append(f"{pid}: control_clauses[{cidx}] missing {key}")
            else:
                errors.append(f"{pid}: control_clauses must be a list")
    if active_count == 0:
        errors.append("No active prompt contracts found")
    return errors


def _scan_llm_calls(repo_root: Path) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    files = []
    for base in (repo_root / "scripts", repo_root / ".github"):
        if base.exists():
            files.extend([p for p in base.rglob("*") if p.is_file() and p.suffix.lower() in {".py", ".yml", ".yaml", ".json"}])
    hits: List[Dict[str, Any]] = []
    unregistered: List[Dict[str, Any]] = []
    for path in sorted(files):
        rel = path.relative_to(repo_root).as_posix()
        if "__pycache__" in rel or rel.endswith(".pyc"):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        found_patterns = []
        for pattern in LLM_CALL_PATTERNS:
            if re.search(pattern, text):
                found_patterns.append(pattern)
        if not found_patterns:
            continue
        covered = (
            rel in ALLOWED_RUNTIME_FILES
            or "record_prompt_call" in text
            or "contract_for_section" in text
            or "get_prompt_contract" in text
        )
        item = {"file": rel, "patterns": ", ".join(found_patterns), "covered_by_prompt_contract": covered}
        hits.append(item)
        if not covered:
            unregistered.append(item)
    return hits, unregistered


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate prompt_contracts.json and LLM call coverage.")
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--registry", default="scripts/prompt_contracts.json")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    registry_path = (repo_root / args.registry).resolve()
    registry = _load_json(registry_path)
    errors = _validate_contracts(repo_root, registry)
    hits, unregistered = _scan_llm_calls(repo_root)

    print(f"[PROMPT_REGISTRY] registry={registry_path}")
    print(f"[PROMPT_REGISTRY] contract_count={len(registry.get('contracts') or [])}")
    print(f"[PROMPT_REGISTRY] llm_call_files={len(hits)}")
    for item in hits:
        status = "covered" if item["covered_by_prompt_contract"] else "unregistered"
        print(f"[PROMPT_REGISTRY] {status}: {item['file']} | {item['patterns']}")
    for item in unregistered:
        errors.append(f"LLM call file is not covered by prompt telemetry/registry: {item['file']}")

    if errors:
        print("[PROMPT_REGISTRY][FAIL]")
        for error in errors:
            print(f"  - {error}")
        return 1 if args.strict else 0
    print("[PROMPT_REGISTRY][OK]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
