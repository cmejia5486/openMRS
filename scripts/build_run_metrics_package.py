#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build the reviewer-ready run-metrics evidence package.

This script consolidates per-run workbook telemetry, prompt telemetry emitted by
AI-enabled stages, technical input hashes, package metadata, a workbook manifest,
and a formal methodology PDF. It is intentionally evidence-preserving: it never
changes yes/no/n/a adjudication and never rewrites audit findings.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import shutil
import textwrap
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import openpyxl
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.worksheet.table import Table, TableStyleInfo
from openpyxl.utils import get_column_letter

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        Image,
        KeepTogether,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table as RLTable,
        TableStyle,
    )
except Exception as exc:  # pragma: no cover
    raise SystemExit("reportlab is required to build the methodology PDF. Install reportlab>=4.0.0") from exc

try:
    from lib.prompt_telemetry import PROMPT_CONTRACTS, registered_prompt_inventory, stable_json_hash
except Exception:  # pragma: no cover
    PROMPT_CONTRACTS: Dict[str, Dict[str, Any]] = {}

    def stable_json_hash(value: Any) -> str:
        try:
            payload = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
        except Exception:
            payload = str(value)
        return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()

    def registered_prompt_inventory() -> List[Dict[str, Any]]:
        return []

RUN_METRICS_XLSX = "run-metrics.xlsx"
RUN_METRICS_PDF = "run-metrics-methodology.pdf"
RUN_METRICS_MANIFEST = "run-metrics-manifest.json"

THEME_NAVY = "17365D"
THEME_BLUE = "D9EAF7"
THEME_LIGHT_BLUE = "EEF5FB"
THEME_LIGHT = "F7F9FC"
THEME_TEXT = "1F2933"
THEME_GREEN = "E2F0D9"
THEME_RED = "FCE4D6"
THEME_ORANGE = "FCE4D6"
THEME_GRAY = "EDEDED"

CONTROL_FIELDS = [
    "json_required_detected",
    "schema_required_detected",
    "identifier_preservation_detected",
    "grounding_required_detected",
    "no_invent_evidence_detected",
    "no_change_result_detected",
    "english_only_detected",
    "repair_or_retry_detected",
]

CONTROL_LABELS = {
    "json_required_detected": "JSON-only output control",
    "schema_required_detected": "Expected output schema control",
    "identifier_preservation_detected": "Identifier preservation control",
    "grounding_required_detected": "Evidence-grounding control",
    "no_invent_evidence_detected": "No-invention control",
    "no_change_result_detected": "No result-change control",
    "english_only_detected": "English-only report text control",
    "repair_or_retry_detected": "Retry or repair control",
}

PROMPT_ROLE_DESCRIPTIONS = {
    "P-AIX-001": "Generates one short English justification for each precomputed requirement result. It does not compute or modify yes/no/n/a outcomes.",
    "P-AS2-001": "Generates the executive summary section from supplied workbook metrics and technical evidence.",
    "P-AS2-002": "Generates positive-control narrative statements from supplied compliant-control evidence.",
    "P-AS2-003": "Generates technical narrative sections from normalized Trivy, MobSF, SAST, Vision360, and workbook context.",
    "P-AS2-004": "Generates weakness-pattern writeups, expected states, impacts, recommendations, and closure criteria from supplied evidence.",
    "P-AS2-005": "Generates treatment-plan fields for non-compliant requirement-level control items.",
    "P-AS2-006": "Generates treatment-plan fields for technical findings such as dependency, SAST, and MobSF-derived items.",
    "A-AS2-001": "Auxiliary prompt used only to complete missing structured fields for control-treatment items after validation detects gaps.",
    "A-AS2-002": "Auxiliary prompt used only to complete missing structured fields for technical-treatment items after validation detects gaps.",
}

PROMPT_CONTROL_DESCRIPTIONS = {
    "P-AIX-001": "Requires raw JSON, exact PUID identifiers, supplied context only, no invented evidence or flags, English output, and no change to the precomputed requirement result. Invalid or missing items receive deterministic fallback justifications.",
    "P-AS2-001": "Requires JSON section output grounded in supplied audit metrics and evidence. The section validator rejects invalid JSON and can retry when disallowed report wording is detected.",
    "P-AS2-002": "Requires JSON output grounded in supplied positive-control evidence. Missing or unacceptable generated statements are excluded rather than replaced with invented prose.",
    "P-AS2-003": "Requires JSON output grounded in supplied technical evidence and guardrails. The prompt is constrained not to invent scanner findings, files, CVEs, packages, or metrics.",
    "P-AS2-004": "Requires exact pattern names and evidence-grounded recommendations, impacts, expected states, and closure criteria. Generic boilerplate and unsupported scanner claims are disallowed.",
    "P-AS2-005": "Requires treatment fields for exact input item_id values. It must not invent PUIDs, flags, files, CVEs, scanner findings, or package versions.",
    "P-AS2-006": "Requires treatment fields for exact technical item_id values. It must use supplied finding metadata and avoid inventing additional files, line numbers, packages, or versions.",
    "A-AS2-001": "Runs only when control-treatment validation detects missing required fields. It receives only the incomplete items and missing field names.",
    "A-AS2-002": "Runs only when technical-treatment validation detects missing required fields. It receives only the incomplete items and missing field names.",
}

REGISTERED_CONTROL_EXPECTATIONS = {
    "P-AIX-001": dict(json_required_detected=True, schema_required_detected=True, identifier_preservation_detected=True, grounding_required_detected=True, no_invent_evidence_detected=True, no_change_result_detected=True, english_only_detected=True, repair_or_retry_detected=True),
    "P-AS2-001": dict(json_required_detected=True, schema_required_detected=True, identifier_preservation_detected=False, grounding_required_detected=True, no_invent_evidence_detected=True, no_change_result_detected=False, english_only_detected=True, repair_or_retry_detected=True),
    "P-AS2-002": dict(json_required_detected=True, schema_required_detected=True, identifier_preservation_detected=True, grounding_required_detected=True, no_invent_evidence_detected=True, no_change_result_detected=False, english_only_detected=True, repair_or_retry_detected=True),
    "P-AS2-003": dict(json_required_detected=True, schema_required_detected=True, identifier_preservation_detected=False, grounding_required_detected=True, no_invent_evidence_detected=True, no_change_result_detected=False, english_only_detected=True, repair_or_retry_detected=True),
    "P-AS2-004": dict(json_required_detected=True, schema_required_detected=True, identifier_preservation_detected=True, grounding_required_detected=True, no_invent_evidence_detected=True, no_change_result_detected=False, english_only_detected=True, repair_or_retry_detected=True),
    "P-AS2-005": dict(json_required_detected=True, schema_required_detected=True, identifier_preservation_detected=True, grounding_required_detected=True, no_invent_evidence_detected=True, no_change_result_detected=False, english_only_detected=True, repair_or_retry_detected=True),
    "P-AS2-006": dict(json_required_detected=True, schema_required_detected=True, identifier_preservation_detected=True, grounding_required_detected=True, no_invent_evidence_detected=True, no_change_result_detected=False, english_only_detected=True, repair_or_retry_detected=True),
    "A-AS2-001": dict(json_required_detected=True, schema_required_detected=True, identifier_preservation_detected=True, grounding_required_detected=True, no_invent_evidence_detected=True, no_change_result_detected=False, english_only_detected=True, repair_or_retry_detected=True),
    "A-AS2-002": dict(json_required_detected=True, schema_required_detected=True, identifier_preservation_detected=True, grounding_required_detected=True, no_invent_evidence_detected=True, no_change_result_detected=False, english_only_detected=True, repair_or_retry_detected=True),
}

METRIC_DEFINITIONS = [
    {
        "metric": "num_requirements",
        "purpose": "Records the number of requirements evaluated in this run.",
        "formula": "COUNTROWS(compliance_export)",
        "numerator": "Rows in compliance_export",
        "denominator": "Not applicable",
        "source_sheet": "compliance_export",
        "interpretation": "Used to verify that repeated runs evaluated the same requirement population.",
        "used_for_stability_analysis": "yes",
    },
    {
        "metric": "compliance_matrix_hash",
        "purpose": "Fingerprint of the complete yes/no/n/a result matrix by PUID.",
        "formula": "SHA-256 of ordered requirement row hashes",
        "numerator": "Not applicable",
        "denominator": "Not applicable",
        "source_sheet": "run_summary, compliance_export",
        "interpretation": "Identical hashes across repeated runs indicate exact matrix agreement.",
        "used_for_stability_analysis": "yes",
    },
    {
        "metric": "llm_config_hash",
        "purpose": "Fingerprint of the LLM runtime configuration used in the run.",
        "formula": "SHA-256 of normalized LLM configuration snapshot",
        "numerator": "Not applicable",
        "denominator": "Not applicable",
        "source_sheet": "run_summary",
        "interpretation": "Repeated-run comparison is valid only when the configuration is stable or differences are explicitly justified.",
        "used_for_stability_analysis": "yes",
    },
    {
        "metric": "json_valid_rate",
        "purpose": "Measures whether LLM calls returned parseable JSON.",
        "formula": "json_valid_count / num_llm_calls",
        "numerator": "LLM calls with json_valid=true",
        "denominator": "All LLM calls recorded in llm_calls",
        "source_sheet": "llm_calls",
        "interpretation": "A low value means the model did not consistently follow the raw JSON contract.",
        "used_for_stability_analysis": "yes",
    },
    {
        "metric": "schema_valid_rate",
        "purpose": "Measures whether LLM responses satisfied the expected structured fields.",
        "formula": "schema_valid_count / num_llm_calls",
        "numerator": "LLM calls with schema_valid=true",
        "denominator": "All LLM calls recorded in llm_calls",
        "source_sheet": "llm_calls",
        "interpretation": "A low value indicates the output structure required repair, retry, or fallback.",
        "used_for_stability_analysis": "yes",
    },
    {
        "metric": "completion_rate",
        "purpose": "Measures whether the model returned the expected number of items.",
        "formula": "received_items / expected_items",
        "numerator": "Received LLM items",
        "denominator": "Expected LLM items",
        "source_sheet": "llm_calls",
        "interpretation": "Below 100% means at least one expected item was not accepted from the LLM output.",
        "used_for_stability_analysis": "yes",
    },
    {
        "metric": "traceability_ok_rate",
        "purpose": "Measures whether accepted LLM items preserved expected identifiers such as PUID or item_id.",
        "formula": "traceability_ok_items / traceability_expected_items",
        "numerator": "Items with traceability_ok=true",
        "denominator": "Items expected from the LLM",
        "source_sheet": "llm_items, prompt_calls",
        "interpretation": "A low value indicates identifier drift and should block acceptance of the affected generated text.",
        "used_for_stability_analysis": "yes",
    },
    {
        "metric": "fallback_rate",
        "purpose": "Measures how often deterministic fallback replaced missing or rejected LLM output.",
        "formula": "fallback_items / num_requirements",
        "numerator": "Items with fallback_used=true",
        "denominator": "Requirements evaluated",
        "source_sheet": "llm_items",
        "interpretation": "Fallback preserves deterministic audit results when LLM output is absent, incomplete, or invalid.",
        "used_for_stability_analysis": "yes",
    },
    {
        "metric": "retry_rate",
        "purpose": "Measures operational retry pressure on LLM calls.",
        "formula": "retry_count / num_llm_calls",
        "numerator": "Total retry count across LLM calls",
        "denominator": "All LLM calls recorded in llm_calls",
        "source_sheet": "llm_calls",
        "interpretation": "A high value suggests model output or endpoint reliability issues.",
        "used_for_stability_analysis": "yes",
    },
    {
        "metric": "prompt_success_rate",
        "purpose": "Measures accepted prompt-call output for each prompt contract.",
        "formula": "successful_prompt_calls / executed_prompt_calls",
        "numerator": "Prompt calls with JSON valid, schema valid, no traceability failure, and no fallback rejection",
        "denominator": "Executed prompt calls for the prompt_id",
        "source_sheet": "prompt_calls",
        "interpretation": "Provides the reviewer a prompt-level success view for the current run.",
        "used_for_stability_analysis": "yes",
    },
    {
        "metric": "prompt_inventory_hash",
        "purpose": "Fingerprint of registered prompt contracts and observed prompt calls.",
        "formula": "SHA-256 of normalized prompt inventory rows and prompt hashes",
        "numerator": "Not applicable",
        "denominator": "Not applicable",
        "source_sheet": "prompt_inventory",
        "interpretation": "Used to verify that repeated runs used the same prompt contract set.",
        "used_for_stability_analysis": "yes",
    },
]

PACKAGE_COMPONENT_DESCRIPTIONS = {
    "run-metrics.xlsx": "Main per-execution workbook with run metadata, input hashes, compliance export, LLM calls, prompt inventory, prompt controls, validation summaries, and package manifest.",
    "run-metrics-methodology.pdf": "Formal methodology report explaining the package contents, metric formulas, prompt roles, output controls, validation results, and repeated-run stability design.",
    "run-metrics-manifest.json": "Machine-readable package manifest containing file names, roles, SHA-256 hashes, timestamps, repository, commit, and run identifiers.",
    "telemetry/prompt-telemetry-ai-requirements.jsonl": "Raw prompt-call telemetry emitted by the requirement-level audit matrix stage. Used to reconstruct prompt_calls and prompt control evidence.",
    "telemetry/prompt-telemetry-audit-summary.jsonl": "Raw prompt-call telemetry emitted by the Audit Summary stage. Used to document which report-generation prompts executed and how their outputs were validated.",
}

# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def _now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8", errors="replace")).hexdigest()


def _sha256_file(path: Path) -> str:
    try:
        if not path.is_file():
            return ""
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def _sha256_dir(path: Path) -> Tuple[str, int]:
    if not path.is_dir():
        return "", 0
    h = hashlib.sha256()
    count = 0
    for file_path in sorted([p for p in path.rglob("*") if p.is_file()], key=lambda p: str(p.relative_to(path)).lower()):
        rel = str(file_path.relative_to(path)).replace("\\", "/")
        file_hash = _sha256_file(file_path)
        h.update(rel.encode("utf-8", errors="replace"))
        h.update(b"\0")
        h.update(file_hash.encode("ascii", errors="ignore"))
        h.update(b"\n")
        count += 1
    return (h.hexdigest() if count else ""), count


def _artifact_hash(path: Path) -> Tuple[str, str, int]:
    if path.is_file():
        return "file", _sha256_file(path), 1
    if path.is_dir():
        sha, count = _sha256_dir(path)
        return "directory", sha, count
    return "missing", "", 0


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        if value in (None, ""):
            return default
        if isinstance(value, bool):
            return int(value)
        return int(float(str(value).strip()))
    except Exception:
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value in (None, ""):
            return default
        if isinstance(value, bool):
            return float(int(value))
        return float(str(value).strip())
    except Exception:
        return default


def _to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on", "verdadero", "si", "sí"}


def _bool_text(value: Any) -> str:
    if value in ("", None):
        return ""
    return "true" if _to_bool(value) else "false"


def _rate(numerator: float, denominator: float) -> float:
    return 0.0 if denominator <= 0 else round(float(numerator) / float(denominator), 6)


def _pct(value: Any) -> str:
    return f"{_safe_float(value):.1%}"


def _short_text(value: Any, limit: int = 220) -> str:
    text = str(value or "").replace("\n", " ").strip()
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + " [text shortened]"


def _wrap_text(text: Any, width: int = 88) -> str:
    return "\n".join(textwrap.wrap(str(text or ""), width=width, break_long_words=False, replace_whitespace=False))


def _safe_sheet_name(name: str) -> str:
    bad = '[]:*?/\\'
    out = "".join("_" if ch in bad else ch for ch in str(name or "Sheet"))[:31]
    return out or "Sheet"


def _sheet_dicts(ws: Any) -> List[Dict[str, Any]]:
    rows = list(ws.iter_rows(values_only=True))
    if not rows:
        return []
    headers = [str(h or "").strip() for h in rows[0]]
    out: List[Dict[str, Any]] = []
    for row in rows[1:]:
        item: Dict[str, Any] = {}
        for idx, header in enumerate(headers):
            if header:
                item[header] = row[idx] if idx < len(row) else None
        if any(v not in (None, "") for v in item.values()):
            out.append(item)
    return out


def _read_sheet_as_dicts(wb: Any, sheet_name: str) -> List[Dict[str, Any]]:
    if sheet_name not in wb.sheetnames:
        return []
    return _sheet_dicts(wb[sheet_name])


def _read_kv_sheet(wb: Any, sheet_name: str) -> Dict[str, Any]:
    rows = _read_sheet_as_dicts(wb, sheet_name)
    return {str(r.get("key") or ""): r.get("value") for r in rows if r.get("key") not in (None, "")}


def _replace_sheet(wb: Any, name: str) -> Any:
    safe = _safe_sheet_name(name)
    if safe in wb.sheetnames:
        del wb[safe]
    return wb.create_sheet(safe)


def _append_dict_rows(ws: Any, rows: List[Dict[str, Any]], headers: List[str]) -> None:
    ws.append(headers)
    for row in rows:
        ws.append([row.get(h, "") for h in headers])


def _append_kv_rows(ws: Any, rows: List[Tuple[str, Any]]) -> None:
    ws.append(["key", "value"])
    for key, value in rows:
        ws.append([key, value])


def _normalize_workbook_for_export(wb: Any) -> None:
    for ws in wb.worksheets:
        for row in ws.iter_rows():
            for cell in row:
                if isinstance(cell.value, bool):
                    cell.value = "true" if cell.value else "false"
                elif isinstance(cell.value, str):
                    low = cell.value.strip().lower()
                    if low in {"verdadero", "true"}:
                        cell.value = "true"
                    elif low in {"falso", "false"}:
                        cell.value = "false"


def _safe_table_name(sheet_name: str, existing: set[str]) -> str:
    base = "tbl_" + "".join(ch if ch.isalnum() else "_" for ch in sheet_name.lower())
    base = base[:200] or "tbl_sheet"
    name = base
    idx = 2
    while name in existing:
        suffix = f"_{idx}"
        name = base[: 240 - len(suffix)] + suffix
        idx += 1
    existing.add(name)
    return name


def _style_workbook(wb: Any) -> None:
    wb.properties.title = "Run Metrics"
    wb.properties.subject = "Reviewer-ready per-execution audit telemetry"
    wb.properties.creator = "mSEC-AM workflow"
    wb.properties.keywords = "audit, metrics, reproducibility, LLM validation, prompt contracts"

    header_fill = PatternFill("solid", fgColor=THEME_NAVY)
    header_font = Font(name="Arial", bold=True, color="FFFFFF", size=10)
    body_font = Font(name="Arial", color=THEME_TEXT, size=9)
    key_fill = PatternFill("solid", fgColor=THEME_LIGHT_BLUE)
    alt_fill = PatternFill("solid", fgColor=THEME_LIGHT)
    side = Side(style="thin", color="D0D7DE")
    border = Border(left=side, right=side, top=side, bottom=side)
    tab_colors = {
        "run_summary": THEME_NAVY,
        "package_contents": "8064A2",
        "input_hashes": "5B9BD5",
        "compliance_export": "70AD47",
        "llm_calls": "ED7D31",
        "llm_items": "A5A5A5",
        "llm_validation_summary": "F4B183",
        "prompt_inventory": "4472C4",
        "prompt_calls": "70AD47",
        "prompt_controls": "5B9BD5",
        "prompt_success_summary": "70AD47",
        "prompt_contract_summary": "8064A2",
        "prompt_discovery_events": "C00000",
        "metric_definitions": "A5A5A5",
        "package_manifest": "8064A2",
    }
    table_names: set[str] = set()
    for ws in wb.worksheets:
        ws.sheet_view.showGridLines = False
        ws.freeze_panes = "A2"
        ws.sheet_properties.tabColor = tab_colors.get(ws.title, THEME_NAVY)
        max_row, max_col = ws.max_row, ws.max_column
        if max_row < 1 or max_col < 1:
            continue
        for cell in ws[1]:
            cell.fill = header_fill
            cell.font = header_font
            cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
            cell.border = border
        ws.row_dimensions[1].height = 25
        for row_idx in range(2, max_row + 1):
            for col_idx in range(1, max_col + 1):
                cell = ws.cell(row_idx, col_idx)
                cell.font = body_font
                cell.alignment = Alignment(vertical="top", wrap_text=True)
                cell.border = border
                if ws.title == "run_summary" and col_idx == 1:
                    cell.fill = key_fill
                    cell.font = Font(name="Arial", bold=True, color=THEME_TEXT, size=9)
                elif row_idx % 2 == 0:
                    cell.fill = alt_fill
                if isinstance(cell.value, (int, float)) and not isinstance(cell.value, bool):
                    cell.number_format = "0.000" if isinstance(cell.value, float) and not math.isclose(cell.value, round(cell.value)) else "0"
        try:
            ref = f"A1:{get_column_letter(max_col)}{max_row}"
            table = Table(displayName=_safe_table_name(ws.title, table_names), ref=ref)
            table.tableStyleInfo = TableStyleInfo(name="TableStyleMedium2", showFirstColumn=False, showLastColumn=False, showRowStripes=True, showColumnStripes=False)
            ws.add_table(table)
        except Exception:
            pass
        ws.auto_filter.ref = ws.dimensions
        for col_idx in range(1, max_col + 1):
            header = str(ws.cell(1, col_idx).value or "").lower()
            max_len = len(str(ws.cell(1, col_idx).value or ""))
            for row_idx in range(2, min(max_row, 150) + 1):
                max_len = max(max_len, len(str(ws.cell(row_idx, col_idx).value or "")))
            if "hash" in header or "sha" in header:
                width = 36
            elif "description" in header or "interpretation" in header or "purpose" in header or "formula" in header or "error" in header or "control" in header:
                width = 44
            elif "path" in header or "flags" in header or "payload" in header:
                width = 42
            elif "puid" in header or header.endswith("id") or "prompt_id" in header:
                width = 24
            else:
                width = min(max(max_len + 2, 12), 30)
            ws.column_dimensions[get_column_letter(col_idx)].width = width

# ---------------------------------------------------------------------------
# Metrics and telemetry
# ---------------------------------------------------------------------------

def _compute_base_metrics(wb: Any) -> Dict[str, Any]:
    summary = _read_kv_sheet(wb, "run_summary")
    compliance = _read_sheet_as_dicts(wb, "compliance_export")
    llm_calls = _read_sheet_as_dicts(wb, "llm_calls")
    llm_items = _read_sheet_as_dicts(wb, "llm_items")
    counts = {"yes": 0, "no": 0, "n/a": 0}
    for row in compliance:
        result = str(row.get("result") or "").strip().lower()
        if result in counts:
            counts[result] += 1
    num_requirements = len(compliance) or _safe_int(summary.get("num_requirements"), 0)
    num_llm_calls = len(llm_calls)
    json_valid_count = sum(1 for r in llm_calls if _to_bool(r.get("json_valid")))
    schema_valid_count = sum(1 for r in llm_calls if _to_bool(r.get("schema_valid")))
    retry_count = sum(_safe_int(r.get("retry_count"), 0) for r in llm_calls)
    expected_items = sum(_safe_int(r.get("expected_items"), 0) for r in llm_calls)
    received_items = sum(_safe_int(r.get("received_items"), 0) for r in llm_calls)
    traceability_expected = sum(1 for r in llm_items if _to_bool(r.get("expected_by_llm")))
    traceability_ok = sum(1 for r in llm_items if _to_bool(r.get("traceability_ok")))
    fallback_count = sum(1 for r in llm_items if _to_bool(r.get("fallback_used")))
    return {
        "summary": summary,
        "compliance_rows": compliance,
        "llm_calls": llm_calls,
        "llm_items": llm_items,
        "counts": counts,
        "num_requirements": num_requirements,
        "num_llm_calls": num_llm_calls,
        "json_valid_count": json_valid_count,
        "schema_valid_count": schema_valid_count,
        "retry_count": retry_count,
        "expected_items": expected_items,
        "received_items": received_items,
        "traceability_expected": traceability_expected,
        "traceability_ok": traceability_ok,
        "fallback_count": fallback_count,
        "failed_call_count": sum(1 for r in llm_calls if not _to_bool(r.get("json_valid")) or not _to_bool(r.get("schema_valid"))),
        "retry_call_count": sum(1 for r in llm_calls if _safe_int(r.get("retry_count"), 0) > 0),
        "json_valid_rate": _rate(json_valid_count, num_llm_calls),
        "schema_valid_rate": _rate(schema_valid_count, num_llm_calls),
        "completion_rate": _rate(received_items, expected_items),
        "traceability_ok_rate": _rate(traceability_ok, traceability_expected),
        "fallback_rate": _rate(fallback_count, num_requirements),
        "retry_rate": _rate(retry_count, num_llm_calls),
    }


def _derive_stage_from_path(path: Path, index: int) -> str:
    s = str(path).lower().replace("\\", "/")
    if "audit-summary" in s or "audit_summary" in s:
        return "audit_summary"
    if "ai-requirements" in s or "ai_requirements" in s or "ai-requirements" in path.name.lower():
        return "ai_requirements"
    if "prompt-telemetry" in s and index == 1:
        return "ai_requirements"
    if "prompt-telemetry" in s and index == 2:
        return "audit_summary"
    return f"telemetry_{index}"


def _telemetry_dest_name(stage: str, source: Path, used: set[str]) -> str:
    if stage == "ai_requirements":
        name = "prompt-telemetry-ai-requirements.jsonl"
    elif stage == "audit_summary":
        name = "prompt-telemetry-audit-summary.jsonl"
    else:
        name = source.name or f"prompt-telemetry-{stage}.jsonl"
    if name in used:
        stem = Path(name).stem
        suffix = Path(name).suffix
        i = 2
        while f"{stem}-{i}{suffix}" in used:
            i += 1
        name = f"{stem}-{i}{suffix}"
    used.add(name)
    return name


def _load_prompt_telemetry(paths: List[str], out_dir: Path) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    events: List[Dict[str, Any]] = []
    copied: List[Dict[str, Any]] = []
    telemetry_dir = out_dir / "telemetry"
    telemetry_dir.mkdir(parents=True, exist_ok=True)
    used_names: set[str] = set()
    for idx, raw in enumerate([p for p in paths if str(p or "").strip()], start=1):
        src = Path(raw).expanduser()
        stage = _derive_stage_from_path(src, idx)
        if not src.is_file():
            copied.append({"component": f"telemetry/{src.name or ('missing-' + str(idx))}", "source_path": str(src), "status": "missing", "telemetry_stage": stage, "event_count": 0, "sha256": ""})
            continue
        dest_name = _telemetry_dest_name(stage, src, used_names)
        dest = telemetry_dir / dest_name
        try:
            shutil.copy2(src, dest)
        except Exception:
            pass
        stage_events = 0
        with src.open("r", encoding="utf-8", errors="replace") as fh:
            for line_no, line in enumerate(fh, start=1):
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    events.append({
                        "event_type": "prompt_discovery",
                        "severity": "warning",
                        "telemetry_stage": stage,
                        "source_path": str(src),
                        "line_no": line_no,
                        "message": "Invalid JSONL telemetry line ignored.",
                    })
                    continue
                if isinstance(obj, dict):
                    obj = dict(obj)
                    obj["telemetry_stage"] = stage
                    obj["telemetry_source_path"] = str(src)
                    obj["telemetry_source_file"] = dest_name
                    events.append(obj)
                    if obj.get("event_type") == "prompt_call":
                        stage_events += 1
        copied.append({"component": f"telemetry/{dest_name}", "source_path": str(src), "status": "included", "telemetry_stage": stage, "event_count": stage_events, "sha256": _sha256_file(dest)})
    return events, copied


def _events_from_existing_workbook(wb: Any) -> List[Dict[str, Any]]:
    calls = _read_sheet_as_dicts(wb, "prompt_calls")
    events: List[Dict[str, Any]] = []
    for row in calls:
        item = dict(row)
        item.setdefault("event_type", "prompt_call")
        item.setdefault("telemetry_stage", "workbook_existing")
        events.append(item)
    return events


def _prompt_call_rows(events: List[Dict[str, Any]], fallback_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    source_events = [e for e in events if e.get("event_type") == "prompt_call"]
    if not source_events:
        source_events = [e for e in fallback_events if e.get("event_type") == "prompt_call"]
    rows: List[Dict[str, Any]] = []
    seen: set[Tuple[str, str, str]] = set()
    for e in source_events:
        original_id = str(e.get("prompt_call_id") or "")
        stage = str(e.get("telemetry_stage") or "")
        prompt_id = str(e.get("prompt_id") or "")
        key = (stage, original_id, prompt_id)
        if key in seen:
            continue
        seen.add(key)
        global_id = f"{stage.upper().replace('-', '_')}-{original_id}" if stage and original_id else original_id
        trace_value = e.get("traceability_ok", "")
        trace_ok = "" if trace_value in (None, "") else _bool_text(trace_value)
        success = _to_bool(e.get("json_valid")) and _to_bool(e.get("schema_valid")) and trace_ok != "false" and not _to_bool(e.get("fallback_used"))
        rows.append({
            "global_prompt_call_id": global_id,
            "prompt_call_id": original_id,
            "telemetry_stage": stage,
            "prompt_id": prompt_id,
            "prompt_name": e.get("prompt_name", ""),
            "prompt_scope": e.get("prompt_scope", ""),
            "prompt_category": e.get("prompt_category", ""),
            "section_name": e.get("section_name", ""),
            "source_file": e.get("source_file", ""),
            "source_function": e.get("source_function", ""),
            "model": e.get("model", ""),
            "provider": e.get("provider", ""),
            "max_output_tokens": e.get("max_output_tokens", ""),
            "reasoning_effort": e.get("reasoning_effort", ""),
            "attempt_count": _safe_int(e.get("attempt_count"), 0),
            "retry_count": _safe_int(e.get("retry_count"), 0),
            "expected_items": _safe_int(e.get("expected_items"), 0),
            "received_items": _safe_int(e.get("received_items"), 0),
            "json_valid": _bool_text(e.get("json_valid")),
            "schema_valid": _bool_text(e.get("schema_valid")),
            "traceability_ok": trace_ok,
            "repair_used": _bool_text(e.get("repair_used")),
            "fallback_used": _bool_text(e.get("fallback_used")),
            "prompt_success": "true" if success else "false",
            "prompt_hash": e.get("prompt_hash", ""),
            "schema_hash": e.get("schema_hash", ""),
            "payload_hash": e.get("payload_hash", ""),
            "controls_hash": e.get("controls_hash", ""),
            "contract_score": e.get("contract_score", ""),
            "elapsed_s": e.get("elapsed_s", ""),
            "registration_status": e.get("registration_status", "registered"),
            "error": e.get("error", ""),
            **{field: _bool_text(e.get(field)) for field in CONTROL_FIELDS if field in e},
        })
    return rows


def _registered_inventory_rows() -> List[Dict[str, Any]]:
    rows = registered_prompt_inventory()
    if rows:
        return rows
    out = []
    for pid, contract in PROMPT_CONTRACTS.items():
        row = dict(contract)
        row["prompt_id"] = pid
        row.setdefault("registration_status", "registered")
        out.append(row)
    return out


def _build_prompt_inventory(prompt_calls: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    registered = {str(row.get("prompt_id") or ""): dict(row) for row in _registered_inventory_rows() if row.get("prompt_id")}
    by_prompt: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for call in prompt_calls:
        by_prompt[str(call.get("prompt_id") or "")].append(call)
        if call.get("prompt_id") and call.get("prompt_id") not in registered:
            registered[str(call.get("prompt_id"))] = {
                "prompt_id": call.get("prompt_id"),
                "prompt_name": call.get("prompt_name", "Unregistered runtime prompt"),
                "prompt_scope": call.get("prompt_scope", "unregistered"),
                "prompt_category": call.get("prompt_category", "unregistered_candidate"),
                "is_primary": False,
                "is_auxiliary": False,
                "source_file": call.get("source_file", ""),
                "source_function": call.get("source_function", ""),
                "registration_status": "unregistered",
            }
    inventory_rows: List[Dict[str, Any]] = []
    control_rows: List[Dict[str, Any]] = []
    success_rows: List[Dict[str, Any]] = []
    discovery_rows: List[Dict[str, Any]] = []
    for prompt_id in sorted(registered):
        contract = registered[prompt_id]
        calls = by_prompt.get(prompt_id, [])
        call_count = len(calls)
        success_count = sum(1 for c in calls if _to_bool(c.get("prompt_success")))
        failed_count = call_count - success_count
        expected_items = sum(_safe_int(c.get("expected_items"), 0) for c in calls)
        received_items = sum(_safe_int(c.get("received_items"), 0) for c in calls)
        retry_count = sum(_safe_int(c.get("retry_count"), 0) for c in calls)
        fallback_count = sum(1 for c in calls if _to_bool(c.get("fallback_used")))
        json_count = sum(1 for c in calls if _to_bool(c.get("json_valid")))
        schema_count = sum(1 for c in calls if _to_bool(c.get("schema_valid")))
        trace_values = [c.get("traceability_ok") for c in calls if c.get("traceability_ok") not in (None, "")]
        trace_ok_count = sum(1 for v in trace_values if _to_bool(v))
        hashes = sorted({str(c.get("prompt_hash") or "") for c in calls if c.get("prompt_hash")})
        inventory_rows.append({
            "prompt_id": prompt_id,
            "prompt_name": contract.get("prompt_name", ""),
            "prompt_scope": contract.get("prompt_scope", ""),
            "prompt_category": contract.get("prompt_category", ""),
            "is_primary": _bool_text(contract.get("is_primary")),
            "is_auxiliary": _bool_text(contract.get("is_auxiliary")),
            "source_file": contract.get("source_file", ""),
            "source_function": contract.get("source_function", ""),
            "registration_status": contract.get("registration_status", "registered"),
            "executed_in_this_run": "true" if call_count else "false",
            "call_count": call_count,
            "successful_call_count": success_count,
            "failed_call_count": failed_count,
            "prompt_success_rate": _rate(success_count, call_count),
            "prompt_hashes_observed": ", ".join(hashes),
            "prompt_hashes_observed_count": len(hashes),
            "role_description": PROMPT_ROLE_DESCRIPTIONS.get(prompt_id, "Runtime prompt registered by the workflow." if prompt_id.startswith("AUTO-") else "Registered prompt contract."),
            "output_control_summary": PROMPT_CONTROL_DESCRIPTIONS.get(prompt_id, "Output controls are derived from runtime prompt telemetry when this prompt executes."),
        })
        control_values: Dict[str, str] = {}
        control_sources: Dict[str, str] = {}
        for field in CONTROL_FIELDS:
            observed = [c.get(field) for c in calls if c.get(field) not in (None, "")]
            if observed:
                value = any(_to_bool(v) for v in observed)
                control_sources[field] = "runtime_observed"
            else:
                value = REGISTERED_CONTROL_EXPECTATIONS.get(prompt_id, {}).get(field, False)
                control_sources[field] = "registered_contract_expected" if prompt_id in REGISTERED_CONTROL_EXPECTATIONS else "not_available"
            control_values[field] = "true" if value else "false"
        applicable = list(control_values.values())
        score = _rate(sum(1 for v in applicable if v == "true"), len(applicable))
        control_rows.append({
            "prompt_id": prompt_id,
            "prompt_name": contract.get("prompt_name", ""),
            "executed_in_this_run": "true" if call_count else "false",
            "control_source": "runtime_observed" if call_count else "registered_contract_expected",
            **control_values,
            "contract_score": score,
            "control_summary": PROMPT_CONTROL_DESCRIPTIONS.get(prompt_id, "No registered control summary available."),
        })
        success_rows.append({
            "prompt_id": prompt_id,
            "prompt_name": contract.get("prompt_name", ""),
            "prompt_scope": contract.get("prompt_scope", ""),
            "prompt_category": contract.get("prompt_category", ""),
            "executed_in_this_run": "true" if call_count else "false",
            "call_count": call_count,
            "successful_call_count": success_count,
            "failed_call_count": failed_count,
            "prompt_success_rate": _rate(success_count, call_count),
            "json_valid_rate": _rate(json_count, call_count),
            "schema_valid_rate": _rate(schema_count, call_count),
            "traceability_ok_rate": _rate(trace_ok_count, len(trace_values)),
            "completion_rate": _rate(received_items, expected_items),
            "retry_count": retry_count,
            "fallback_call_count": fallback_count,
            "expected_items": expected_items,
            "received_items": received_items,
            "run_conclusion": "not executed in this run" if call_count == 0 else ("accepted without rejected prompt calls" if failed_count == 0 else "one or more prompt calls required fallback, retry, or were rejected"),
        })
        if contract.get("registration_status") == "unregistered":
            discovery_rows.append({
                "event_type": "unregistered_prompt_call",
                "severity": "warning",
                "prompt_id": prompt_id,
                "source_file": contract.get("source_file", ""),
                "source_function": contract.get("source_function", ""),
                "message": "Runtime prompt call was not present in the registered prompt inventory.",
            })
    return inventory_rows, control_rows, success_rows, discovery_rows


def _build_contract_summary(prompt_inventory: List[Dict[str, Any]], prompt_calls: List[Dict[str, Any]], control_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    total_registered = sum(1 for r in prompt_inventory if r.get("registration_status") == "registered")
    primary = sum(1 for r in prompt_inventory if _to_bool(r.get("is_primary")))
    auxiliary = sum(1 for r in prompt_inventory if _to_bool(r.get("is_auxiliary")))
    executed = sum(1 for r in prompt_inventory if _to_bool(r.get("executed_in_this_run")))
    calls = len(prompt_calls)
    success = sum(1 for c in prompt_calls if _to_bool(c.get("prompt_success")))
    avg_score = _rate(sum(_safe_float(r.get("contract_score"), 0) for r in control_rows), len(control_rows))
    unregistered = sum(1 for r in prompt_inventory if r.get("registration_status") != "registered")
    inventory_hash = stable_json_hash([{k: r.get(k, "") for k in ("prompt_id", "prompt_hashes_observed", "call_count", "registration_status")} for r in prompt_inventory])
    return [
        {"metric": "registered_prompt_contract_count", "value": total_registered, "interpretation": "Registered prompt contracts known to the workflow."},
        {"metric": "primary_audit_related_prompt_count", "value": primary, "interpretation": "Primary prompts related to audit matrix or Audit Summary generation."},
        {"metric": "auxiliary_repair_prompt_count", "value": auxiliary, "interpretation": "Auxiliary repair prompts used only after validation detects missing structured treatment fields."},
        {"metric": "executed_prompt_contract_count", "value": executed, "interpretation": "Registered or discovered prompt contracts actually called in this run."},
        {"metric": "prompt_call_count", "value": calls, "interpretation": "Runtime prompt calls observed in telemetry."},
        {"metric": "successful_prompt_call_count", "value": success, "interpretation": "Prompt calls accepted after JSON, schema, traceability, and fallback checks."},
        {"metric": "prompt_success_rate", "value": _rate(success, calls), "interpretation": "Accepted prompt calls divided by all observed prompt calls."},
        {"metric": "average_prompt_contract_score", "value": avg_score, "interpretation": "Average of documented prompt control flags across registered and observed prompts."},
        {"metric": "unregistered_prompt_count", "value": unregistered, "interpretation": "Prompt calls not matched to a registered contract. Expected value is 0."},
        {"metric": "prompt_inventory_hash", "value": inventory_hash, "interpretation": "Fingerprint of prompt registration and execution state for repeated-run comparison."},
    ]


def _build_validation_summary(metrics: Dict[str, Any], prompt_success_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    prompt_calls = sum(_safe_int(r.get("call_count"), 0) for r in prompt_success_rows)
    prompt_success = sum(_safe_int(r.get("successful_call_count"), 0) for r in prompt_success_rows)
    return [
        {"metric": "json_valid_rate", "numerator": metrics["json_valid_count"], "denominator": metrics["num_llm_calls"], "rate": metrics["json_valid_rate"], "source": "llm_calls", "current_run_interpretation": "Rate of LLM calls with parseable JSON output."},
        {"metric": "schema_valid_rate", "numerator": metrics["schema_valid_count"], "denominator": metrics["num_llm_calls"], "rate": metrics["schema_valid_rate"], "source": "llm_calls", "current_run_interpretation": "Rate of LLM calls matching expected structured fields."},
        {"metric": "completion_rate", "numerator": metrics["received_items"], "denominator": metrics["expected_items"], "rate": metrics["completion_rate"], "source": "llm_calls", "current_run_interpretation": "Accepted items divided by expected items."},
        {"metric": "traceability_ok_rate", "numerator": metrics["traceability_ok"], "denominator": metrics["traceability_expected"], "rate": metrics["traceability_ok_rate"], "source": "llm_items", "current_run_interpretation": "Items preserving expected PUID or item_id identifiers."},
        {"metric": "fallback_rate", "numerator": metrics["fallback_count"], "denominator": metrics["num_requirements"], "rate": metrics["fallback_rate"], "source": "llm_items", "current_run_interpretation": "Deterministic fallback use for requirement-level justifications."},
        {"metric": "retry_rate", "numerator": metrics["retry_count"], "denominator": metrics["num_llm_calls"], "rate": metrics["retry_rate"], "source": "llm_calls", "current_run_interpretation": "Retry pressure on LLM calls."},
        {"metric": "prompt_success_rate", "numerator": prompt_success, "denominator": prompt_calls, "rate": _rate(prompt_success, prompt_calls), "source": "prompt_calls", "current_run_interpretation": "Prompt calls accepted after all available validations."},
    ]

# ---------------------------------------------------------------------------
# Inputs, manifests, package contents
# ---------------------------------------------------------------------------

def _base_input_rows(wb: Any) -> List[Dict[str, Any]]:
    rows = _read_sheet_as_dicts(wb, "input_hashes")
    out: List[Dict[str, Any]] = []
    for row in rows:
        name = str(row.get("input_name") or row.get("artifact") or "").strip()
        if not name:
            continue
        out.append({
            "input_name": name,
            "component_group": "ai_requirements_excel",
            "artifact_type": "file",
            "path": row.get("path", ""),
            "file_count": 1 if row.get("sha256") else 0,
            "sha256": row.get("sha256", ""),
            "availability": "recorded_by_source_workbook",
            "purpose": "Input recorded by the requirement-level metrics workbook.",
        })
    return out


def _add_input_row(rows_by_name: Dict[str, Dict[str, Any]], name: str, group: str, path: str, purpose: str) -> None:
    if not path:
        return
    p = Path(path).expanduser()
    typ, sha, count = _artifact_hash(p)
    rows_by_name[name] = {
        "input_name": name,
        "component_group": group,
        "artifact_type": typ,
        "path": str(p),
        "file_count": count,
        "sha256": sha,
        "availability": "available" if typ != "missing" else "missing_at_package_build_time",
        "purpose": purpose,
    }


def _collect_input_hash_rows(wb: Any, args: argparse.Namespace, telemetry_components: List[Dict[str, Any]], output_xlsx: Path, output_pdf: Path, manifest_path: Path) -> List[Dict[str, Any]]:
    rows_by_name: Dict[str, Dict[str, Any]] = {}
    for row in _base_input_rows(wb):
        rows_by_name[str(row["input_name"])] = row
    _add_input_row(rows_by_name, "raw_metrics_source", "run_metrics", args.raw_metrics, "Raw per-run workbook before package normalization.")
    _add_input_row(rows_by_name, "run_metrics_workbook", "run_metrics", str(output_xlsx), "Consolidated run-metrics workbook generated by this package step.")
    _add_input_row(rows_by_name, "run_metrics_methodology_pdf", "run_metrics", str(output_pdf), "Methodology PDF generated by this package step.")
    _add_input_row(rows_by_name, "run_metrics_manifest", "run_metrics", str(manifest_path), "Package manifest generated by this package step.")
    _add_input_row(rows_by_name, "audit_summary_analysis_pack", "audit_summary", args.analysis_pack, "Stage 1 normalized analysis pack used by Audit Summary generation.")
    _add_input_row(rows_by_name, "audit_summary_literals", "audit_summary", args.audit_config, "Runtime report metadata and actors configuration.")
    _add_input_row(rows_by_name, "audit_summary_docx", "audit_summary", args.audit_summary_docx, "Generated Audit Summary DOCX, when available at package build time.")
    _add_input_row(rows_by_name, "audit_summary_pdf", "audit_summary", args.audit_summary_pdf, "Generated Audit Summary PDF, when available at package build time.")
    _add_input_row(rows_by_name, "technical_inputs_root", "technical_evidence", args.technical_root, "Root directory containing downloaded technical evidence artifacts.")
    _add_input_row(rows_by_name, "vision360_bundle", "technical_evidence", args.vision360_bundle, "Vision360 normalized evidence bundle used as technical traceability input.")
    _add_input_row(rows_by_name, "trivy_payload", "technical_evidence", args.trivy_payload, "Trivy dependency and SCA evidence artifact.")
    _add_input_row(rows_by_name, "mobsf_report", "technical_evidence", args.mobsf_report, "MobSF static analysis evidence artifact.")
    _add_input_row(rows_by_name, "mobsf_dynamic_report", "technical_evidence", args.mobsf_dynamic_report, "MobSF dynamic/runtime evidence artifact.")
    _add_input_row(rows_by_name, "sast_findings", "technical_evidence", args.sast_findings, "SAST findings artifact, including CodeQL, Semgrep, Detekt, or merged SARIF where provided.")
    for comp in telemetry_components:
        component = str(comp.get("component") or "")
        name = component.replace("telemetry/", "prompt_telemetry_").replace(".jsonl", "").replace("-", "_")
        rows_by_name[name] = {
            "input_name": name,
            "component_group": "prompt_telemetry",
            "artifact_type": "file" if comp.get("status") == "included" else "missing",
            "path": comp.get("source_path", ""),
            "file_count": 1 if comp.get("status") == "included" else 0,
            "sha256": comp.get("sha256", ""),
            "availability": comp.get("status", ""),
            "purpose": "Raw prompt telemetry used to build prompt_calls, prompt_controls, and prompt_success_summary.",
        }
    return [rows_by_name[k] for k in sorted(rows_by_name)]


def _package_contents_rows(telemetry_components: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    required_components = [RUN_METRICS_XLSX, RUN_METRICS_PDF, RUN_METRICS_MANIFEST]
    for component in required_components:
        rows.append({
            "component": component,
            "component_type": "primary" if component in {RUN_METRICS_XLSX, RUN_METRICS_PDF} else "integrity_manifest",
            "included": "true",
            "reviewer_relevance": "primary reviewer-facing evidence" if component in {RUN_METRICS_XLSX, RUN_METRICS_PDF} else "technical integrity evidence",
            "purpose": PACKAGE_COMPONENT_DESCRIPTIONS[component],
            "duplication_policy": "authoritative component, not duplicated elsewhere",
        })
    for comp in telemetry_components:
        component = comp.get("component", "")
        rows.append({
            "component": component,
            "component_type": "raw_telemetry",
            "included": "true" if comp.get("status") == "included" else "false",
            "reviewer_relevance": "supporting technical evidence; summarized in run-metrics.xlsx",
            "purpose": PACKAGE_COMPONENT_DESCRIPTIONS.get(component, "Raw telemetry supporting the consolidated workbook."),
            "duplication_policy": "raw source retained for auditability; summarized in prompt sheets to avoid reader-facing duplication",
        })
    return rows


def _write_manifest_json(path: Path, out_dir: Path, summary: Dict[str, Any], package_contents: List[Dict[str, Any]]) -> None:
    files: List[Dict[str, Any]] = []
    for p in sorted([x for x in out_dir.rglob("*") if x.is_file()], key=lambda x: str(x.relative_to(out_dir)).lower()):
        if p.name == RUN_METRICS_MANIFEST:
            continue
        rel = str(p.relative_to(out_dir)).replace("\\", "/")
        files.append({
            "path": rel,
            "sha256": _sha256_file(p),
            "size_bytes": p.stat().st_size,
            "role": next((r.get("component_type", "") for r in package_contents if r.get("component") == rel), "supporting_file"),
        })
    manifest = {
        "manifest_version": "1.0",
        "generated_at_utc": _now_utc(),
        "package_name": "run-metrics",
        "repository": summary.get("repository", ""),
        "commit_sha": summary.get("commit_sha", ""),
        "run_id": summary.get("run_id", ""),
        "workflow": summary.get("workflow", ""),
        "files": files,
    }
    path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")


def _package_manifest_rows(out_dir: Path, raw_path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for p in sorted([x for x in out_dir.rglob("*") if x.is_file()], key=lambda x: str(x.relative_to(out_dir)).lower()):
        rel = str(p.relative_to(out_dir)).replace("\\", "/")
        rows.append({
            "artifact": rel,
            "path": str(p),
            "sha256": _sha256_file(p),
            "size_bytes": p.stat().st_size,
        })
    rows.append({"artifact": "raw_metrics_source", "path": str(raw_path), "sha256": _sha256_file(raw_path), "size_bytes": raw_path.stat().st_size if raw_path.is_file() else 0})
    rows.append({"artifact": "package_generated_at_utc", "path": _now_utc(), "sha256": "", "size_bytes": ""})
    return rows

# ---------------------------------------------------------------------------
# PDF rendering
# ---------------------------------------------------------------------------

class PDFBuilder:
    def __init__(self, path: Path, metrics: Dict[str, Any]):
        self.path = path
        self.metrics = metrics
        self.story: List[Any] = []
        self.table_no = 0
        self.figure_no = 0
        self.styles = getSampleStyleSheet()
        self.styles.add(ParagraphStyle(name="CoverTitle", fontName="Helvetica-Bold", fontSize=22, leading=26, alignment=TA_CENTER, textColor=colors.HexColor("#17365D"), spaceAfter=18))
        self.styles.add(ParagraphStyle(name="CoverSub", fontName="Helvetica", fontSize=11, leading=14, alignment=TA_CENTER, textColor=colors.HexColor("#4B5563"), spaceAfter=12))
        self.styles.add(ParagraphStyle(name="H1x", fontName="Helvetica-Bold", fontSize=14, leading=18, textColor=colors.HexColor("#17365D"), spaceBefore=8, spaceAfter=6))
        self.styles.add(ParagraphStyle(name="H2x", fontName="Helvetica-Bold", fontSize=11, leading=14, textColor=colors.HexColor("#17365D"), spaceBefore=7, spaceAfter=4))
        self.styles.add(ParagraphStyle(name="Bodyx", fontName="Helvetica", fontSize=8.7, leading=11.2, textColor=colors.HexColor("#1F2933"), spaceAfter=5))
        self.styles.add(ParagraphStyle(name="Smallx", fontName="Helvetica", fontSize=7.3, leading=9.2, textColor=colors.HexColor("#4B5563"), spaceAfter=4))
        self.styles.add(ParagraphStyle(name="Captionx", fontName="Helvetica-Oblique", fontSize=7.3, leading=9.2, textColor=colors.HexColor("#4B5563"), spaceBefore=3, spaceAfter=8))
        self.styles.add(ParagraphStyle(name="TableCell", fontName="Helvetica", fontSize=6.7, leading=8.2, textColor=colors.HexColor("#1F2933")))
        self.styles.add(ParagraphStyle(name="TableHead", fontName="Helvetica-Bold", fontSize=6.8, leading=8.4, textColor=colors.white, alignment=TA_CENTER))

    def p(self, text: str, style: str = "Bodyx") -> None:
        self.story.append(Paragraph(str(text or ""), self.styles[style]))

    def h1(self, text: str) -> None:
        self.story.append(Paragraph(str(text), self.styles["H1x"]))

    def h2(self, text: str) -> None:
        self.story.append(Paragraph(str(text), self.styles["H2x"]))

    def spacer(self, h: float = 0.08) -> None:
        self.story.append(Spacer(1, h * inch))

    def table(self, title: str, headers: List[str], rows: List[List[Any]], widths: Optional[List[float]] = None, max_rows: Optional[int] = None) -> None:
        self.table_no += 1
        caption = f"Table {self.table_no}. {title}"
        data_rows = rows[:max_rows] if max_rows else rows
        if not data_rows:
            data_rows = [["No rows recorded"] + [""] * (len(headers) - 1)]
        self.story.append(Paragraph(caption, self.styles["Captionx"]))
        available_width = A4[0] - 0.9 * inch
        if widths is None:
            widths = [1.0 / len(headers)] * len(headers)
        total = sum(widths) or 1.0
        col_widths = [available_width * (w / total) for w in widths]

        def cell(v: Any, head: bool = False) -> Paragraph:
            txt = str(v if v is not None else "")
            txt = txt.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            return Paragraph(txt, self.styles["TableHead" if head else "TableCell"])

        table_data = [[cell(h, True) for h in headers]]
        for row in data_rows:
            values = list(row)[: len(headers)] + [""] * max(0, len(headers) - len(row))
            table_data.append([cell(v) for v in values[: len(headers)]])
        t = RLTable(table_data, colWidths=col_widths, repeatRows=1, hAlign="LEFT")
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17365D")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#D0D7DE")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 3),
            ("RIGHTPADDING", (0, 0), (-1, -1), 3),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F7F9FC")]),
        ]))
        self.story.append(t)
        self.spacer(0.08)
        if max_rows and len(rows) > max_rows:
            self.p(f"Table continues in the workbook. Displayed rows: {max_rows} of {len(rows)}.", "Smallx")

    def figure(self, title: str, image_path: Path, caption: str, width: float = 6.2) -> None:
        self.figure_no += 1
        from reportlab.lib.utils import ImageReader
        reader = ImageReader(str(image_path))
        img_w, img_h = reader.getSize()
        draw_w = width * inch
        draw_h = draw_w * (float(img_h) / float(img_w or 1))
        max_h = 4.0 * inch
        if draw_h > max_h:
            scale = max_h / draw_h
            draw_w *= scale
            draw_h *= scale
        img = Image(str(image_path), width=draw_w, height=draw_h)
        img.hAlign = "CENTER"
        block = [
            Paragraph(f"Figure {self.figure_no}. {title}", self.styles["Captionx"]),
            img,
            Paragraph(caption, self.styles["Captionx"]),
        ]
        self.story.append(KeepTogether(block))

    def build(self) -> None:
        doc = SimpleDocTemplate(str(self.path), pagesize=A4, rightMargin=0.45 * inch, leftMargin=0.45 * inch, topMargin=0.48 * inch, bottomMargin=0.48 * inch)
        doc.build(self.story, onFirstPage=self._page_footer, onLaterPages=self._page_footer)

    def _page_footer(self, canvas: Any, doc: Any) -> None:
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#4B5563"))
        canvas.drawString(0.45 * inch, 0.28 * inch, "mSEC-AM Run Metrics Methodology")
        canvas.drawRightString(A4[0] - 0.45 * inch, 0.28 * inch, f"Page {doc.page}")
        canvas.restoreState()


def _plot_bar(path: Path, labels: List[str], values: List[float], title: str, ylabel: str, percent: bool = False) -> None:
    fig, ax = plt.subplots(figsize=(7.2, 3.8), constrained_layout=True)
    bars = ax.bar(labels, values)
    ax.set_title(title, fontsize=12, fontweight="bold", pad=12)
    ax.set_ylabel(ylabel)
    ax.grid(axis="y", linestyle="--", linewidth=0.5, alpha=0.45)
    if percent:
        ax.set_ylim(0, 1.16)
        ax.yaxis.set_major_formatter(lambda x, pos: f"{x:.0%}")
        labels_text = [f"{v:.1%}" for v in values]
    else:
        ymax = max(values + [1])
        ax.set_ylim(0, ymax * 1.18)
        labels_text = [str(int(v)) for v in values]
    for bar, txt in zip(bars, labels_text):
        offset = 0.035 if percent else max(values + [1]) * 0.03
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + offset, txt, ha="center", va="bottom", fontsize=8)
    ax.tick_params(axis="x", labelsize=8)
    ax.tick_params(axis="y", labelsize=8)
    fig.savefig(path, dpi=200, bbox_inches="tight", pad_inches=0.18)
    plt.close(fig)


def _plot_scope(path: Path, prompt_calls: List[Dict[str, Any]]) -> None:
    counts = Counter(str(r.get("prompt_scope") or "unknown") for r in prompt_calls)
    labels = list(counts.keys()) or ["none"]
    values = [counts[k] for k in labels] or [0]
    _plot_bar(path, labels, values, "Prompt calls by scope", "Prompt calls", percent=False)


def _first_rows(rows: List[Dict[str, Any]], keys: List[str], limit: int) -> List[List[Any]]:
    return [[_short_text(r.get(k, ""), 180) for k in keys] for r in rows[:limit]]


def _generate_methodology_pdf(output_pdf: Path, metrics: Dict[str, Any], workbook_rows: Dict[str, List[Dict[str, Any]]], chart_dir: Path) -> None:
    output_pdf.parent.mkdir(parents=True, exist_ok=True)
    chart_dir.mkdir(parents=True, exist_ok=True)
    compliance_chart = chart_dir / "figure-01-compliance-distribution.png"
    validation_chart = chart_dir / "figure-02-llm-validation-rates.png"
    prompt_scope_chart = chart_dir / "figure-03-prompt-scope.png"
    fallback_chart = chart_dir / "figure-04-fallback-retry.png"
    _plot_bar(compliance_chart, ["yes", "no", "n/a"], [metrics["counts"].get("yes", 0), metrics["counts"].get("no", 0), metrics["counts"].get("n/a", 0)], "Compliance result distribution", "Requirement count")
    _plot_bar(validation_chart, ["JSON", "schema", "completion", "traceability"], [metrics["json_valid_rate"], metrics["schema_valid_rate"], metrics["completion_rate"], metrics["traceability_ok_rate"]], "LLM output validation rates", "Rate", percent=True)
    _plot_scope(prompt_scope_chart, workbook_rows.get("prompt_calls", []))
    _plot_bar(fallback_chart, ["fallback", "retry"], [metrics["fallback_rate"], metrics["retry_rate"]], "Fallback and retry rates", "Rate", percent=True)

    b = PDFBuilder(output_pdf, metrics)
    summary = metrics.get("summary", {})
    b.story.append(Spacer(1, 0.8 * inch))
    b.story.append(Paragraph("Run Metrics Methodology", b.styles["CoverTitle"]))
    b.story.append(Paragraph("Reviewer-ready evidence package for LLM-controlled audit reproducibility", b.styles["CoverSub"]))
    cover_rows = [
        ["Run ID", summary.get("run_id", "")],
        ["Repository", summary.get("repository", "")],
        ["Commit SHA", summary.get("commit_sha", "")],
        ["Workflow", summary.get("workflow", "")],
        ["Generated at", summary.get("generated_at_utc", _now_utc())],
        ["LLM configuration hash", _short_text(summary.get("llm_config_hash", ""), 90)],
        ["Compliance matrix hash", _short_text(summary.get("compliance_matrix_hash", ""), 90)],
    ]
    b.table("Execution identity", ["Field", "Value"], cover_rows, widths=[0.28, 0.72])
    b.p("This PDF explains what each component in run-metrics.zip does, how the workbook metrics are calculated, how LLM prompt outputs are controlled and validated in this execution, and how five run-metrics workbooks can later be aggregated into a stability-analysis workbook.")
    b.story.append(PageBreak())

    b.h1("1. Purpose and scope")
    b.p("The run-metrics package documents one audit execution. It is not a separate audit engine and it does not replace the audit workbook or Audit Summary report. Its purpose is to record the inputs, deterministic results, LLM prompt calls, validation outcomes, fallback behavior, hashes, and package integrity evidence needed to explain and reproduce the run.")
    b.p("The compliance results yes, no, and n/a are recorded from the audit workflow. The LLM-related metrics document controlled text generation and validation. They do not grant the LLM authority to change deterministic compliance outcomes.")
    b.table("Run Metrics package contents", ["Component", "Type", "Included", "Purpose"], _first_rows(workbook_rows.get("package_contents", []), ["component", "component_type", "included", "purpose"], 10), widths=[0.23, 0.16, 0.10, 0.51])

    b.h1("2. Workbook structure and evidence coverage")
    sheet_rows = [
        ["run_summary", "Run identity, counts, configuration hash, compliance matrix hash, and workflow metadata."],
        ["package_contents", "Human-readable inventory of files included in run-metrics.zip and their role."],
        ["input_hashes", "SHA-256 hashes for audit inputs, technical evidence artifacts, telemetry, and generated package files when available."],
        ["compliance_export", "One row per requirement with PUID, result, flags used, justification length, and row hash."],
        ["llm_calls", "Operational LLM-call metrics recorded by the requirement-level audit stage."],
        ["llm_items", "PUID-level LLM item validation and fallback evidence."],
        ["llm_validation_summary", "Aggregated validation metrics for JSON, schema, completion, traceability, fallback, retry, and prompt success."],
        ["prompt_inventory", "Registered and discovered prompt contracts, role descriptions, execution counts, success rates, and observed prompt hashes."],
        ["prompt_calls", "One row per observed runtime prompt invocation with hashes, validation flags, and prompt success status."],
        ["prompt_controls", "One row per prompt_id describing output controls and whether the prompt was executed in the run."],
        ["prompt_success_summary", "Prompt-level success, JSON validity, schema validity, traceability, completion, retry, and fallback summary."],
        ["metric_definitions", "Metric formulas, numerators, denominators, source sheets, and interpretation."],
        ["package_manifest", "File-level hashes and sizes for package integrity."],
    ]
    b.table("Workbook sheets and purpose", ["Sheet", "Purpose"], sheet_rows, widths=[0.24, 0.76])
    b.table("Audit input evidence and hash controls", ["Input", "Group", "Type", "Availability", "SHA-256"], _first_rows(workbook_rows.get("input_hashes", []), ["input_name", "component_group", "artifact_type", "availability", "sha256"], 18), widths=[0.22, 0.19, 0.13, 0.18, 0.28])

    b.h1("3. Role of the LLM and prompt contracts")
    b.p("The workflow separates deterministic audit adjudication from LLM-assisted text generation. Requirement outcomes are computed by existing audit logic and exported to the workbook. LLM prompts are used to draft justifications, executive narrative, technical narrative, pattern writeups, and treatment-plan text from supplied evidence. Auxiliary repair prompts are used only when validation detects missing structured fields.")
    b.p("Every registered prompt has a stable prompt_id. Each runtime invocation receives a prompt_call_id. Runtime telemetry records prompt scope, category, source function, model, prompt hash, schema hash, payload hash, validation flags, retry count, repair usage, fallback usage, and errors when present.")
    b.table("Prompt roles and current-run execution", ["Prompt", "Scope", "Category", "Calls", "Success rate", "Role"], _first_rows(workbook_rows.get("prompt_inventory", []), ["prompt_id", "prompt_scope", "prompt_category", "call_count", "prompt_success_rate", "role_description"], 20), widths=[0.12, 0.15, 0.18, 0.08, 0.10, 0.37])
    b.table("Prompt output controls", ["Prompt", "Executed", "JSON", "Schema", "Identifier", "Grounding", "No invention", "No result change", "Control summary"], _first_rows(workbook_rows.get("prompt_controls", []), ["prompt_id", "executed_in_this_run", "json_required_detected", "schema_required_detected", "identifier_preservation_detected", "grounding_required_detected", "no_invent_evidence_detected", "no_change_result_detected", "control_summary"], 20), widths=[0.10, 0.08, 0.07, 0.07, 0.09, 0.09, 0.09, 0.09, 0.32])

    b.h1("4. Current-run prompt validation and success")
    b.p("The following summary is calculated from the observed prompt calls for this execution. A prompt call is counted as successful when it produced JSON-valid and schema-valid output, had no traceability failure, and was not rejected into fallback. Prompts not invoked in this run remain documented in the inventory but are explicitly marked as not executed.")
    b.table("Prompt success summary for this run", ["Prompt", "Executed", "Calls", "Success", "JSON", "Schema", "Traceability", "Fallback", "Conclusion"], _first_rows(workbook_rows.get("prompt_success_summary", []), ["prompt_id", "executed_in_this_run", "call_count", "prompt_success_rate", "json_valid_rate", "schema_valid_rate", "traceability_ok_rate", "fallback_call_count", "run_conclusion"], 20), widths=[0.11, 0.08, 0.07, 0.08, 0.08, 0.08, 0.10, 0.08, 0.32])
    b.table("LLM validation metrics for this run", ["Metric", "Numerator", "Denominator", "Rate", "Interpretation"], _first_rows(workbook_rows.get("llm_validation_summary", []), ["metric", "numerator", "denominator", "rate", "current_run_interpretation"], 12), widths=[0.21, 0.12, 0.12, 0.10, 0.45])

    b.h1("5. Visual current-run summary")
    b.figure("Compliance result distribution", compliance_chart, "This figure summarizes the deterministic compliance result distribution recorded in compliance_export. It does not recalculate or reinterpret audit outcomes.")
    b.figure("LLM output validation rates", validation_chart, "This figure shows JSON validity, schema validity, item completion, and identifier traceability for accepted LLM-controlled outputs in the current execution.")
    b.figure("Prompt calls by scope", prompt_scope_chart, "This figure shows which prompt scopes were actually executed in the current run. Prompt contracts that were registered but not called remain visible in prompt_inventory.")
    b.figure("Fallback and retry rates", fallback_chart, "Fallback indicates deterministic replacement of missing or invalid LLM-generated justification items. Retry indicates operational recovery attempts before accepting or rejecting model output.")

    b.h1("6. Metric definitions")
    b.table("Metric formulas and interpretation", ["Metric", "Formula", "Source", "Interpretation"], _first_rows(workbook_rows.get("metric_definitions", []), ["metric", "formula", "source_sheet", "interpretation"], 20), widths=[0.20, 0.24, 0.18, 0.38])

    b.h1("7. Repeated-run stability design")
    b.p("This package represents one execution. To address consistency between executions, at least five run-metrics workbooks for the same software should be collected under fixed inputs, fixed commit, fixed prompt inventory, fixed LLM configuration, and fixed audit logic. Those workbooks are then aggregated into stability-analysis.xlsx.")
    stability_rows = [
        ["exact_matrix_agreement_rate", "Share of repeated runs with the same compliance_matrix_hash."],
        ["requirement_result_agreement_rate", "Agreement of yes/no/n/a result per PUID across repeated runs."],
        ["changed_requirement_count", "Number of PUIDs whose result changed across repeated runs."],
        ["yes/no/n/a count standard deviation", "Variation in aggregate result counts across repeated runs."],
        ["Fleiss_kappa or Krippendorff_alpha", "Statistical agreement of categorical results across five or more executions."],
        ["prompt_inventory_stability", "Whether prompt_inventory_hash remained fixed across repeated runs."],
        ["llm_config_stability", "Whether llm_config_hash remained fixed across repeated runs."],
    ]
    b.table("Stability-analysis metrics derived from five run-metrics workbooks", ["Metric", "Purpose"], stability_rows, widths=[0.34, 0.66])
    b.p("Runs should be excluded from stability comparison when their input hashes, commit SHA, prompt inventory hash, or LLM configuration hash differ, unless the difference is intentionally part of the experiment.")

    b.h1("8. Interpretation limits")
    b.p("The package records what the workflow actually observed. Missing technical artifacts are marked as missing rather than inferred. Prompts not executed in the run are documented as registered but not executed. The PDF does not invent scanner findings, prompt calls, success values, or stability statistics. Stability statistics require multiple completed run-metrics workbooks and are not calculated from a single execution.")
    b.build()

# ---------------------------------------------------------------------------
# Build orchestration
# ---------------------------------------------------------------------------

def _write_rows_sheet(wb: Any, name: str, rows: List[Dict[str, Any]], headers: List[str]) -> None:
    ws = _replace_sheet(wb, name)
    _append_dict_rows(ws, rows, headers)


def _write_all_sheets(wb: Any, rows: Dict[str, List[Dict[str, Any]]], metrics: Dict[str, Any], summary_extra: List[Tuple[str, Any]]) -> None:
    # Update run_summary in place with consolidated hashes and explanatory counters.
    summary = metrics.get("summary", {})
    existing_pairs = [(str(k), v) for k, v in summary.items() if str(k)]
    # Preserve insertion order from existing sheet when possible.
    if "run_summary" in wb.sheetnames:
        old_rows = _read_sheet_as_dicts(wb, "run_summary")
        existing_pairs = [(str(r.get("key") or ""), r.get("value")) for r in old_rows if r.get("key") not in (None, "")]
    merged: Dict[str, Any] = {k: v for k, v in existing_pairs}
    for key, value in summary_extra:
        merged[key] = value
    ws = _replace_sheet(wb, "run_summary")
    _append_kv_rows(ws, list(merged.items()))

    _write_rows_sheet(wb, "package_contents", rows["package_contents"], ["component", "component_type", "included", "reviewer_relevance", "purpose", "duplication_policy"])
    _write_rows_sheet(wb, "input_hashes", rows["input_hashes"], ["input_name", "component_group", "artifact_type", "path", "file_count", "sha256", "availability", "purpose"])
    _write_rows_sheet(wb, "llm_validation_summary", rows["llm_validation_summary"], ["metric", "numerator", "denominator", "rate", "source", "current_run_interpretation"])
    _write_rows_sheet(wb, "prompt_inventory", rows["prompt_inventory"], ["prompt_id", "prompt_name", "prompt_scope", "prompt_category", "is_primary", "is_auxiliary", "source_file", "source_function", "registration_status", "executed_in_this_run", "call_count", "successful_call_count", "failed_call_count", "prompt_success_rate", "prompt_hashes_observed", "prompt_hashes_observed_count", "role_description", "output_control_summary"])
    _write_rows_sheet(wb, "prompt_calls", rows["prompt_calls"], ["global_prompt_call_id", "prompt_call_id", "telemetry_stage", "prompt_id", "prompt_name", "prompt_scope", "prompt_category", "section_name", "source_file", "source_function", "model", "provider", "max_output_tokens", "reasoning_effort", "attempt_count", "retry_count", "expected_items", "received_items", "json_valid", "schema_valid", "traceability_ok", "repair_used", "fallback_used", "prompt_success", "prompt_hash", "schema_hash", "payload_hash", "controls_hash", "contract_score", "elapsed_s", "registration_status", "error"])
    _write_rows_sheet(wb, "prompt_controls", rows["prompt_controls"], ["prompt_id", "prompt_name", "executed_in_this_run", "control_source", *CONTROL_FIELDS, "contract_score", "control_summary"])
    _write_rows_sheet(wb, "prompt_success_summary", rows["prompt_success_summary"], ["prompt_id", "prompt_name", "prompt_scope", "prompt_category", "executed_in_this_run", "call_count", "successful_call_count", "failed_call_count", "prompt_success_rate", "json_valid_rate", "schema_valid_rate", "traceability_ok_rate", "completion_rate", "retry_count", "fallback_call_count", "expected_items", "received_items", "run_conclusion"])
    _write_rows_sheet(wb, "prompt_contract_summary", rows["prompt_contract_summary"], ["metric", "value", "interpretation"])
    _write_rows_sheet(wb, "prompt_discovery_events", rows["prompt_discovery_events"], ["event_type", "severity", "telemetry_stage", "prompt_call_id", "prompt_id", "source_file", "source_function", "message"])
    _write_rows_sheet(wb, "metric_definitions", METRIC_DEFINITIONS, ["metric", "purpose", "formula", "numerator", "denominator", "source_sheet", "interpretation", "used_for_stability_analysis"])


def build(args: argparse.Namespace) -> None:
    out_dir = Path(args.out_dir).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)
    raw_path = Path(args.raw_metrics).expanduser()
    if not raw_path.is_file():
        raise SystemExit(f"Missing run metrics workbook: {raw_path}")
    output_xlsx = out_dir / RUN_METRICS_XLSX
    output_pdf = out_dir / RUN_METRICS_PDF
    manifest_path = out_dir / RUN_METRICS_MANIFEST
    chart_dir = out_dir / "_methodology_charts"

    if raw_path.resolve() != output_xlsx.resolve():
        shutil.copy2(raw_path, output_xlsx)

    wb = openpyxl.load_workbook(output_xlsx)
    metrics = _compute_base_metrics(wb)
    telemetry_events, telemetry_components = _load_prompt_telemetry(args.prompt_telemetry or [], out_dir)
    fallback_events = _events_from_existing_workbook(wb)
    prompt_calls = _prompt_call_rows(telemetry_events, fallback_events)
    prompt_inventory, prompt_controls, prompt_success_summary, discovery_rows = _build_prompt_inventory(prompt_calls)
    telemetry_discovery = [e for e in telemetry_events if e.get("event_type") != "prompt_call"]
    prompt_discovery_events = discovery_rows + [
        {
            "event_type": e.get("event_type", "prompt_discovery"),
            "severity": e.get("severity", "info"),
            "telemetry_stage": e.get("telemetry_stage", ""),
            "prompt_call_id": e.get("prompt_call_id", ""),
            "prompt_id": e.get("prompt_id", ""),
            "source_file": e.get("source_file", ""),
            "source_function": e.get("source_function", ""),
            "message": e.get("message", ""),
        }
        for e in telemetry_discovery
    ]
    prompt_contract_summary = _build_contract_summary(prompt_inventory, prompt_calls, prompt_controls)
    llm_validation_summary = _build_validation_summary(metrics, prompt_success_summary)

    # Create provisional package contents and manifest before final workbook hash pass.
    package_contents = _package_contents_rows(telemetry_components)
    _write_manifest_json(manifest_path, out_dir, metrics.get("summary", {}), package_contents)
    input_hashes = _collect_input_hash_rows(wb, args, telemetry_components, output_xlsx, output_pdf, manifest_path)

    rows = {
        "package_contents": package_contents,
        "input_hashes": input_hashes,
        "llm_validation_summary": llm_validation_summary,
        "prompt_inventory": prompt_inventory,
        "prompt_calls": prompt_calls,
        "prompt_controls": prompt_controls,
        "prompt_success_summary": prompt_success_summary,
        "prompt_contract_summary": prompt_contract_summary,
        "prompt_discovery_events": prompt_discovery_events,
        "metric_definitions": METRIC_DEFINITIONS,
    }
    prompt_inventory_hash = next((r.get("value") for r in prompt_contract_summary if r.get("metric") == "prompt_inventory_hash"), "")
    summary_extra = [
        ("package_generated_at_utc", _now_utc()),
        ("prompt_inventory_hash", prompt_inventory_hash),
        ("prompt_call_count", len(prompt_calls)),
        ("executed_prompt_contract_count", sum(1 for r in prompt_inventory if _to_bool(r.get("executed_in_this_run")))),
        ("successful_prompt_call_count", sum(1 for r in prompt_calls if _to_bool(r.get("prompt_success")))),
        ("run_metrics_package_contents_count", len(package_contents)),
    ]
    _write_all_sheets(wb, rows, metrics, summary_extra)
    _normalize_workbook_for_export(wb)
    _style_workbook(wb)
    wb.save(output_xlsx)

    # Refresh metrics and hashes after the consolidated workbook exists.
    wb = openpyxl.load_workbook(output_xlsx)
    metrics = _compute_base_metrics(wb)
    _generate_methodology_pdf(output_pdf, metrics, rows, chart_dir)
    shutil.rmtree(chart_dir, ignore_errors=True)
    _write_manifest_json(manifest_path, out_dir, metrics.get("summary", {}), package_contents)

    # Final manifest sheet now that every output exists.
    wb = openpyxl.load_workbook(output_xlsx)
    package_manifest = _package_manifest_rows(out_dir, raw_path)
    _write_rows_sheet(wb, "package_manifest", package_manifest, ["artifact", "path", "sha256", "size_bytes"])
    input_hashes = _collect_input_hash_rows(wb, args, telemetry_components, output_xlsx, output_pdf, manifest_path)
    rows["input_hashes"] = input_hashes
    _write_rows_sheet(wb, "input_hashes", input_hashes, ["input_name", "component_group", "artifact_type", "path", "file_count", "sha256", "availability", "purpose"])
    _normalize_workbook_for_export(wb)
    _style_workbook(wb)
    wb.save(output_xlsx)

    print(f"[OK] Run metrics workbook: {output_xlsx}")
    print(f"[OK] Run metrics methodology PDF: {output_pdf}")
    print(f"[OK] Run metrics manifest: {manifest_path}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a reviewer-ready run-metrics package.")
    parser.add_argument("--raw-metrics", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--prompt-telemetry", action="append", default=[], help="Prompt telemetry JSONL file. Can be supplied more than once.")
    parser.add_argument("--analysis-pack", required=False, default="")
    parser.add_argument("--audit-config", required=False, default="")
    parser.add_argument("--audit-summary-docx", required=False, default="")
    parser.add_argument("--audit-summary-pdf", required=False, default="")
    parser.add_argument("--technical-root", required=False, default="")
    parser.add_argument("--vision360-bundle", required=False, default="")
    parser.add_argument("--trivy-payload", required=False, default="")
    parser.add_argument("--mobsf-report", required=False, default="")
    parser.add_argument("--mobsf-dynamic-report", required=False, default="")
    parser.add_argument("--sast-findings", required=False, default="")
    return parser.parse_args()


if __name__ == "__main__":
    build(parse_args())
