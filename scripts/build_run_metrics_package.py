#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
import hashlib
import math
import os
import shutil
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

import openpyxl
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.worksheet.table import Table, TableStyleInfo
from openpyxl.utils import get_column_letter
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
from matplotlib.ticker import PercentFormatter

RUN_METRICS_XLSX = "run-metrics.xlsx"
RUN_METRICS_PDF = "run-metrics-methodology.pdf"

THEME_NAVY = "17365D"
THEME_BLUE = "D9EAF7"
THEME_LIGHT_BLUE = "EEF5FB"
THEME_LIGHT = "F7F9FC"
THEME_GRAY = "EDEDED"
THEME_GREEN = "E2F0D9"
THEME_RED = "FCE4D6"
THEME_ORANGE = "FCE4D6"
THEME_TEXT = "1F2933"


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


def _now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        if value in (None, ""):
            return default
        return int(float(value))
    except Exception:
        return default


def _to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on", "verdadero", "si", "sí"}


def _rate(numerator: float, denominator: float) -> float:
    return 0.0 if denominator <= 0 else round(float(numerator) / float(denominator), 6)


def _read_sheet_as_dicts(wb: Any, sheet_name: str) -> List[Dict[str, Any]]:
    if sheet_name not in wb.sheetnames:
        return []
    ws = wb[sheet_name]
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


def _read_kv_sheet(wb: Any, sheet_name: str) -> Dict[str, Any]:
    rows = _read_sheet_as_dicts(wb, sheet_name)
    return {str(r.get("key") or ""): r.get("value") for r in rows if r.get("key") not in (None, "")}


def _compute_metrics(raw_wb: Any) -> Dict[str, Any]:
    summary = _read_kv_sheet(raw_wb, "run_summary")
    input_hashes = _read_sheet_as_dicts(raw_wb, "input_hashes")
    compliance = _read_sheet_as_dicts(raw_wb, "compliance_export")
    llm_calls = _read_sheet_as_dicts(raw_wb, "llm_calls")
    llm_items = _read_sheet_as_dicts(raw_wb, "llm_items")

    num_requirements = len(compliance) or _safe_int(summary.get("num_requirements"), 0)
    counts = {"yes": 0, "no": 0, "n/a": 0}
    for row in compliance:
        result = str(row.get("result") or "").strip().lower()
        if result in counts:
            counts[result] += 1

    num_llm_calls = len(llm_calls)
    json_valid_count = sum(1 for r in llm_calls if _to_bool(r.get("json_valid")))
    schema_valid_count = sum(1 for r in llm_calls if _to_bool(r.get("schema_valid")))
    retry_count = sum(_safe_int(r.get("retry_count"), 0) for r in llm_calls)
    expected_items = sum(_safe_int(r.get("expected_items"), 0) for r in llm_calls)
    received_items = sum(_safe_int(r.get("received_items"), 0) for r in llm_calls)
    traceability_expected = sum(1 for r in llm_items if _to_bool(r.get("expected_by_llm")))
    traceability_ok = sum(1 for r in llm_items if _to_bool(r.get("traceability_ok")))
    fallback_count = sum(1 for r in llm_items if _to_bool(r.get("fallback_used")))

    failed_calls = [r for r in llm_calls if not _to_bool(r.get("json_valid")) or not _to_bool(r.get("schema_valid"))]
    retry_calls = [r for r in llm_calls if _safe_int(r.get("retry_count"), 0) > 0]
    fallback_items = [r for r in llm_items if _to_bool(r.get("fallback_used"))]
    successful_calls = [r for r in llm_calls if _to_bool(r.get("json_valid")) and _to_bool(r.get("schema_valid"))]

    examples = {
        "failed_call": failed_calls[0] if failed_calls else {},
        "fallback_item": fallback_items[0] if fallback_items else {},
        "retry_call": retry_calls[0] if retry_calls else {},
        "successful_call": successful_calls[0] if successful_calls else {},
        "yes_requirement": next((r for r in compliance if str(r.get("result") or "").lower() == "yes"), {}),
        "no_requirement": next((r for r in compliance if str(r.get("result") or "").lower() == "no"), {}),
        "na_requirement": next((r for r in compliance if str(r.get("result") or "").lower() == "n/a"), {}),
    }

    return {
        "summary": summary,
        "input_hashes": input_hashes,
        "compliance_rows": compliance,
        "llm_calls": llm_calls,
        "llm_items": llm_items,
        "examples": examples,
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
        "failed_call_count": len(failed_calls),
        "retry_call_count": len(retry_calls),
        "json_valid_rate": _rate(json_valid_count, num_llm_calls),
        "schema_valid_rate": _rate(schema_valid_count, num_llm_calls),
        "completion_rate": _rate(received_items, expected_items),
        "traceability_ok_rate": _rate(traceability_ok, traceability_expected),
        "fallback_rate": _rate(fallback_count, num_requirements),
        "retry_rate": _rate(retry_count, num_llm_calls),
    }




def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not path or not path.is_file():
        return rows
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict):
                rows.append(obj)
    return rows


def _registered_prompt_inventory_rows() -> List[Dict[str, Any]]:
    try:
        from lib.prompt_telemetry import registered_prompt_inventory
        return list(registered_prompt_inventory())
    except Exception:
        return []


def _prompt_bool(value: Any) -> str:
    return "true" if _to_bool(value) else "false"


def _prompt_inventory_from_calls(prompt_calls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: Dict[str, Dict[str, Any]] = {}
    for call in prompt_calls:
        pid = str(call.get("prompt_id") or "")
        if not pid or pid in seen:
            continue
        seen[pid] = {
            "prompt_id": pid,
            "prompt_name": call.get("prompt_name", ""),
            "prompt_scope": call.get("prompt_scope", ""),
            "prompt_category": call.get("prompt_category", ""),
            "is_primary": call.get("is_primary", ""),
            "is_auxiliary": call.get("is_auxiliary", ""),
            "source_file": call.get("source_file", ""),
            "source_function": call.get("source_function", ""),
            "registration_status": call.get("registration_status", "runtime_detected"),
        }
    return list(seen.values())


def _prepare_prompt_metrics(prompt_telemetry_path: Path | None, extra_prompt_calls: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
    events = _read_jsonl(prompt_telemetry_path) if prompt_telemetry_path else []
    prompt_calls = [e for e in events if e.get("event_type") == "prompt_call"]
    if extra_prompt_calls:
        prompt_calls = list(extra_prompt_calls) + prompt_calls
    registered = _registered_prompt_inventory_rows()
    inventory_by_id: Dict[str, Dict[str, Any]] = {}
    for row in registered:
        pid = str(row.get("prompt_id") or "")
        if pid:
            inventory_by_id[pid] = dict(row)
    for row in _prompt_inventory_from_calls(prompt_calls):
        pid = str(row.get("prompt_id") or "")
        if pid and pid not in inventory_by_id:
            inventory_by_id[pid] = dict(row)

    executed_ids = {str(c.get("prompt_id") or "") for c in prompt_calls if c.get("prompt_id")}
    inventory_rows: List[Dict[str, Any]] = []
    for pid in sorted(inventory_by_id):
        row = dict(inventory_by_id[pid])
        row["executed_in_this_run"] = "true" if pid in executed_ids else "false"
        row["prompt_hashes_observed"] = ", ".join(sorted({str(c.get("prompt_hash") or "") for c in prompt_calls if str(c.get("prompt_id") or "") == pid and c.get("prompt_hash")}))
        row["call_count"] = sum(1 for c in prompt_calls if str(c.get("prompt_id") or "") == pid)
        inventory_rows.append(row)

    controls_rows: List[Dict[str, Any]] = []
    for call in prompt_calls:
        controls_rows.append({
            "prompt_call_id": call.get("prompt_call_id", ""),
            "prompt_id": call.get("prompt_id", ""),
            "json_required_detected": call.get("json_required_detected", ""),
            "schema_required_detected": call.get("schema_required_detected", ""),
            "identifier_preservation_detected": call.get("identifier_preservation_detected", ""),
            "grounding_required_detected": call.get("grounding_required_detected", ""),
            "no_invent_evidence_detected": call.get("no_invent_evidence_detected", ""),
            "no_change_result_detected": call.get("no_change_result_detected", ""),
            "english_only_detected": call.get("english_only_detected", ""),
            "repair_or_retry_detected": call.get("repair_or_retry_detected", ""),
            "contract_score": call.get("contract_score", ""),
        })

    discovery_events: List[Dict[str, Any]] = []
    for call in prompt_calls:
        if str(call.get("registration_status") or "registered") != "registered" or str(call.get("prompt_id") or "").startswith("AUTO-"):
            discovery_events.append({
                "event_type": "UNREGISTERED_LLM_PROMPT",
                "severity": "warning",
                "prompt_call_id": call.get("prompt_call_id", ""),
                "prompt_id": call.get("prompt_id", ""),
                "source_file": call.get("source_file", ""),
                "source_function": call.get("source_function", ""),
                "message": "A runtime LLM call was detected without a registered prompt contract.",
            })

    primary_count = sum(1 for row in inventory_rows if _to_bool(row.get("is_primary")))
    auxiliary_count = sum(1 for row in inventory_rows if _to_bool(row.get("is_auxiliary")))
    executed_primary = sum(1 for row in inventory_rows if _to_bool(row.get("is_primary")) and _to_bool(row.get("executed_in_this_run")))
    executed_auxiliary = sum(1 for row in inventory_rows if _to_bool(row.get("is_auxiliary")) and _to_bool(row.get("executed_in_this_run")))
    prompt_hashes = sorted({str(c.get("prompt_hash") or "") for c in prompt_calls if c.get("prompt_hash")})
    config_hashes = sorted({str(c.get("schema_hash") or "") for c in prompt_calls if c.get("schema_hash")})
    valid_json = sum(1 for c in prompt_calls if _to_bool(c.get("json_valid")))
    valid_schema = sum(1 for c in prompt_calls if _to_bool(c.get("schema_valid")))

    summary_rows = [
        {"metric": "registered_prompt_contract_count", "value": len(inventory_rows), "interpretation": "Registered prompt contracts known to the workflow."},
        {"metric": "primary_audit_related_prompt_count", "value": primary_count, "interpretation": "Primary prompts related to audit matrix or Audit Summary generation."},
        {"metric": "auxiliary_repair_prompt_count", "value": auxiliary_count, "interpretation": "Auxiliary repair prompts used only to complete missing structured fields."},
        {"metric": "executed_prompt_call_count", "value": len(prompt_calls), "interpretation": "Runtime LLM calls recorded in this execution scope."},
        {"metric": "executed_primary_prompt_contract_count", "value": executed_primary, "interpretation": "Primary prompt contracts that were actually invoked in this execution scope."},
        {"metric": "executed_auxiliary_prompt_contract_count", "value": executed_auxiliary, "interpretation": "Auxiliary repair contracts that were actually invoked in this execution scope."},
        {"metric": "unregistered_prompt_call_count", "value": len(discovery_events), "interpretation": "Runtime LLM calls not matched to a registered prompt contract."},
        {"metric": "prompt_call_json_valid_rate", "value": _rate(valid_json, len(prompt_calls)), "interpretation": "Prompt calls that returned parseable JSON divided by prompt calls."},
        {"metric": "prompt_call_schema_valid_rate", "value": _rate(valid_schema, len(prompt_calls)), "interpretation": "Prompt calls satisfying the expected schema divided by prompt calls."},
        {"metric": "prompt_inventory_hash", "value": hashlib.sha256(json.dumps(inventory_rows, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")).hexdigest(), "interpretation": "Hash of the prompt inventory for repeated-run comparison."},
        {"metric": "prompt_hash_count", "value": len(prompt_hashes), "interpretation": "Distinct prompt hashes observed in runtime calls."},
        {"metric": "schema_hash_count", "value": len(config_hashes), "interpretation": "Distinct expected-output schema hashes observed in runtime calls."},
    ]
    return {
        "prompt_events": events,
        "prompt_calls": prompt_calls,
        "prompt_inventory": inventory_rows,
        "prompt_controls": controls_rows,
        "prompt_contract_summary": summary_rows,
        "prompt_discovery_events": discovery_events,
        "prompt_telemetry_path": str(prompt_telemetry_path or ""),
    }


def _add_prompt_sheets(wb: Any, prompt_metrics: Dict[str, Any]) -> None:
    inventory_headers = [
        "prompt_id", "prompt_name", "prompt_scope", "prompt_category", "is_primary", "is_auxiliary",
        "source_file", "source_function", "section_match", "registration_status", "executed_in_this_run",
        "call_count", "prompt_hashes_observed",
    ]
    call_headers = [
        "prompt_call_id", "prompt_id", "prompt_name", "prompt_scope", "prompt_category", "section_name",
        "source_file", "source_function", "model", "provider", "max_output_tokens", "reasoning_effort",
        "attempt_count", "retry_count", "expected_items", "received_items", "json_valid", "schema_valid",
        "traceability_ok", "repair_used", "fallback_used", "elapsed_s", "prompt_hash", "schema_hash", "payload_hash",
        "registration_status", "error",
    ]
    control_headers = [
        "prompt_call_id", "prompt_id", "json_required_detected", "schema_required_detected",
        "identifier_preservation_detected", "grounding_required_detected", "no_invent_evidence_detected",
        "no_change_result_detected", "english_only_detected", "repair_or_retry_detected", "contract_score",
    ]
    summary_headers = ["metric", "value", "interpretation"]
    events_headers = ["event_type", "severity", "prompt_call_id", "prompt_id", "source_file", "source_function", "message"]
    ws = _replace_sheet(wb, "prompt_inventory")
    _append_dict_rows(ws, prompt_metrics.get("prompt_inventory", []), inventory_headers)
    ws = _replace_sheet(wb, "prompt_calls")
    _append_dict_rows(ws, prompt_metrics.get("prompt_calls", []), call_headers)
    ws = _replace_sheet(wb, "prompt_controls")
    _append_dict_rows(ws, prompt_metrics.get("prompt_controls", []), control_headers)
    ws = _replace_sheet(wb, "prompt_contract_summary")
    _append_dict_rows(ws, prompt_metrics.get("prompt_contract_summary", []), summary_headers)
    ws = _replace_sheet(wb, "prompt_discovery_events")
    _append_dict_rows(ws, prompt_metrics.get("prompt_discovery_events", []), events_headers)

def _remove_non_raw_sheets(wb: Any) -> None:
    allowed = {
        "run_summary", "input_hashes", "compliance_export", "llm_calls", "llm_items",
        "prompt_inventory", "prompt_calls", "prompt_controls", "prompt_contract_summary",
        "prompt_discovery_events", "package_manifest",
    }
    for sheet in list(wb.sheetnames):
        if sheet not in allowed:
            del wb[sheet]


def _replace_sheet(wb: Any, name: str) -> Any:
    if name in wb.sheetnames:
        del wb[name]
    return wb.create_sheet(name)


def _append_dict_rows(ws: Any, rows: List[Dict[str, Any]], headers: List[str]) -> None:
    ws.append(headers)
    for row in rows:
        ws.append([row.get(h, "") for h in headers])


def _add_package_manifest_sheet(wb: Any, raw_path: Path, output_xlsx: Path, output_pdf: Path) -> None:
    rows = [
        {"artifact": "run-metrics.xlsx", "path": str(output_xlsx), "sha256": _sha256_file(output_xlsx)},
        {"artifact": "run-metrics-methodology.pdf", "path": str(output_pdf), "sha256": _sha256_file(output_pdf)},
        {"artifact": "raw_metrics_source", "path": str(raw_path), "sha256": _sha256_file(raw_path)},
        {"artifact": "package_generated_at_utc", "path": _now_utc(), "sha256": ""},
    ]
    ws = _replace_sheet(wb, "package_manifest")
    _append_dict_rows(ws, rows, ["artifact", "path", "sha256"])



def _normalize_workbook_for_export(wb: Any) -> None:
    """Normalize cell values so the raw workbook remains locale-neutral.

    Excel may display native boolean values as VERDADERO/FALSO on Spanish
    installations. These sheets are intended as raw, exportable telemetry, so
    boolean-like fields are written as lowercase text literals true/false.
    This preserves machine readability and avoids locale-dependent labels.
    """
    for ws in wb.worksheets:
        for row in ws.iter_rows():
            for cell in row:
                if isinstance(cell.value, bool):
                    cell.value = "true" if cell.value else "false"
                elif isinstance(cell.value, str):
                    v = cell.value.strip()
                    low = v.lower()
                    if low in {"verdadero", "true"}:
                        cell.value = "true"
                    elif low in {"falso", "false"}:
                        cell.value = "false"


def _safe_table_name(sheet_name: str) -> str:
    base = "tbl_" + "".join(ch if ch.isalnum() else "_" for ch in sheet_name.lower())
    return base[:240]


def _style_workbook(wb: Any) -> None:
    wb.properties.title = "Run Metrics"
    wb.properties.subject = "Per-execution audit telemetry"
    wb.properties.creator = "mSEC-AM workflow"
    wb.properties.keywords = "audit, metrics, reproducibility, LLM validation"

    header_fill = PatternFill("solid", fgColor=THEME_NAVY)
    header_font = Font(name="Arial", bold=True, color="FFFFFF", size=10)
    body_font = Font(name="Arial", color=THEME_TEXT, size=9)
    key_fill = PatternFill("solid", fgColor=THEME_LIGHT_BLUE)
    alt_fill = PatternFill("solid", fgColor=THEME_LIGHT)
    border_side = Side(style="thin", color="D0D7DE")
    border = Border(left=border_side, right=border_side, top=border_side, bottom=border_side)

    tab_colors = {
        "run_summary": THEME_NAVY,
        "input_hashes": "5B9BD5",
        "compliance_export": "70AD47",
        "llm_calls": "ED7D31",
        "llm_items": "A5A5A5",
        "prompt_inventory": "8064A2",
        "prompt_calls": "9E480E",
        "prompt_controls": "5B9BD5",
        "prompt_contract_summary": "17365D",
        "prompt_discovery_events": "C00000",
        "package_manifest": "8064A2",
    }

    for ws in wb.worksheets:
        ws.sheet_view.showGridLines = False
        ws.freeze_panes = "A2"
        ws.sheet_properties.tabColor = tab_colors.get(ws.title, THEME_NAVY)
        max_row = ws.max_row
        max_col = ws.max_column
        if max_row < 1 or max_col < 1:
            continue

        for cell in ws[1]:
            cell.fill = header_fill
            cell.font = header_font
            cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
            cell.border = border
        ws.row_dimensions[1].height = 24

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
                if isinstance(cell.value, bool):
                    cell.alignment = Alignment(horizontal="center", vertical="center")
                if isinstance(cell.value, (int, float)) and not isinstance(cell.value, bool):
                    cell.number_format = "#,##0.000" if isinstance(cell.value, float) and not math.isclose(cell.value, round(cell.value)) else "#,##0"

        ws.auto_filter.ref = ws.dimensions
        try:
            ref = f"A1:{get_column_letter(max_col)}{max_row}"
            table = Table(displayName=_safe_table_name(ws.title), ref=ref)
            style = TableStyleInfo(name="TableStyleMedium2", showFirstColumn=False, showLastColumn=False, showRowStripes=True, showColumnStripes=False)
            table.tableStyleInfo = style
            ws.add_table(table)
        except Exception:
            pass

        for col_idx in range(1, max_col + 1):
            letter = get_column_letter(col_idx)
            header = str(ws.cell(1, col_idx).value or "").lower()
            max_len = len(str(ws.cell(1, col_idx).value or ""))
            for row_idx in range(2, min(max_row, 200) + 1):
                value = ws.cell(row_idx, col_idx).value
                max_len = max(max_len, len(str(value or "")))
            if "hash" in header or "sha" in header:
                width = 34
            elif "path" in header or "flags" in header or "error" in header:
                width = 42
            elif "justification" in header:
                width = 36
            elif "puid" in header or "id" in header:
                width = 22
            else:
                width = min(max(max_len + 2, 12), 30)
            ws.column_dimensions[letter].width = width


def _plot_bar(labels: List[str], values: List[float], title: str, ylabel: str, percent: bool = False):
    fig, ax = plt.subplots(figsize=(8.8, 5.2))
    bars = ax.bar(labels, values)
    ax.set_title(title, fontsize=13, fontweight="bold")
    ax.set_ylabel(ylabel)
    if percent:
        ax.set_ylim(0, 1.05)
        ax.yaxis.set_major_formatter(PercentFormatter(xmax=1.0))
        for bar, value in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width() / 2, min(1.02, value + 0.03), f"{value:.1%}", ha="center", fontsize=9)
    else:
        ymax = max(values + [1])
        for bar, value in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width() / 2, value + ymax * 0.02, str(int(value)), ha="center", fontsize=9)
    ax.grid(axis="y", linestyle="--", linewidth=0.5, alpha=0.5)
    fig.tight_layout()
    return fig



def _wrap_text(text: Any, width: int = 92) -> str:
    return "\n".join(textwrap.wrap(str(text or ""), width=width, break_long_words=False, replace_whitespace=False))


def _short_text(value: Any, limit: int = 170) -> str:
    text = str(value or "").replace("\n", " ").strip()
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + " [text shortened]"


def _pct(value: float) -> str:
    return f"{float(value):.1%}"


def _add_page_title(fig: Any, title: str, subtitle: str = "") -> None:
    fig.text(0.08, 0.94, title, fontsize=16, fontweight="bold", color="#17365D")
    if subtitle:
        fig.text(0.08, 0.91, _wrap_text(subtitle, 95), fontsize=9.5, color="#4B5563")


def _add_paragraph(fig: Any, x: float, y: float, text: str, *, width: int = 90, fontsize: float = 9.2, color: str = "#1F2933") -> float:
    wrapped = _wrap_text(text, width)
    fig.text(x, y, wrapped, fontsize=fontsize, color=color, va="top")
    line_count = max(1, wrapped.count("\n") + 1)
    return y - (line_count * 0.022) - 0.014


def _add_table(fig: Any, bbox: List[float], rows: List[List[Any]], headers: List[str], *, fontsize: float = 7.7, col_widths: List[float] | None = None) -> None:
    ax = fig.add_axes(bbox)
    ax.axis("off")
    widths = col_widths or [1.0 / max(1, len(headers))] * len(headers)

    def wrap_cell(value: Any, col_idx: int) -> str:
        width = widths[col_idx] if col_idx < len(widths) else widths[-1]
        max_chars = max(10, int(width * 115))
        return _wrap_text(str(value or ""), max_chars)

    wrapped_rows = [[wrap_cell(c, idx) for idx, c in enumerate(row)] for row in rows]
    wrapped_headers = [wrap_cell(h, idx) for idx, h in enumerate(headers)]
    table = ax.table(
        cellText=wrapped_rows,
        colLabels=wrapped_headers,
        loc="center",
        cellLoc="left",
        colWidths=col_widths,
    )
    table.auto_set_font_size(False)
    table.set_fontsize(fontsize)
    table.scale(1, 1.55)

    row_line_counts: Dict[int, int] = {0: max(h.count("\n") + 1 for h in wrapped_headers)}
    for ridx, row in enumerate(wrapped_rows, start=1):
        row_line_counts[ridx] = max(1, max((str(cell).count("\n") + 1 for cell in row), default=1))

    for (r, c), cell in table.get_celld().items():
        cell.set_edgecolor("#D0D7DE")
        cell.set_height(0.04 * max(1, row_line_counts.get(r, 1)))
        if r == 0:
            cell.set_facecolor("#17365D")
            cell.set_text_props(color="white", weight="bold")
        elif r % 2 == 0:
            cell.set_facecolor("#F7F9FC")


def _add_title_page(pdf: PdfPages, metrics: Dict[str, Any]) -> None:
    summary = metrics.get("summary", {})
    fig = plt.figure(figsize=(8.27, 11.69))
    fig.patch.set_facecolor("white")
    fig.text(0.5, 0.93, "Run Metrics Methodology", ha="center", fontsize=22, fontweight="bold", color="#17365D")
    fig.text(0.5, 0.895, "Per-execution evidence package for audit reproducibility", ha="center", fontsize=11, style="italic")
    purpose = (
        "This document explains the methodology used to generate the run-metrics package, the role of each metric, "
        "the formula applied, the source sheet used in the companion workbook, and the interpretation of the values observed in the current execution."
    )
    y = 0.82
    fig.text(0.08, y, "Purpose", fontsize=14, fontweight="bold", color="#17365D")
    y = _add_paragraph(fig, 0.08, y - 0.035, purpose, width=96, fontsize=10)
    rows = [
        ("Run ID", summary.get("run_id", "")),
        ("Repository", summary.get("repository", "")),
        ("Commit SHA", summary.get("commit_sha", "")),
        ("Model", summary.get("config.OPENAI_MODEL") or summary.get("config.AI_MODEL") or ""),
        ("AI profile", summary.get("config.AI_PROFILE", "")),
        ("LLM configuration hash", _short_text(summary.get("llm_config_hash", ""), 80)),
        ("Compliance matrix hash", _short_text(summary.get("compliance_matrix_hash", ""), 80)),
        ("Generated at", summary.get("generated_at_utc", _now_utc())),
    ]
    _add_table(fig, [0.08, 0.39, 0.84, 0.29], [[k, str(v)] for k, v in rows], ["Field", "Value"], fontsize=8.2, col_widths=[0.28, 0.72])
    fig.text(0.08, 0.31, "Current execution at a glance", fontsize=14, fontweight="bold", color="#17365D")
    cards = [
        ("Requirements", metrics["num_requirements"]),
        ("yes", metrics["counts"].get("yes", 0)),
        ("no", metrics["counts"].get("no", 0)),
        ("n/a", metrics["counts"].get("n/a", 0)),
        ("LLM calls", metrics["num_llm_calls"]),
    ]
    x = 0.08
    for label, value in cards:
        rect = plt.Rectangle((x, 0.20), 0.15, 0.07, transform=fig.transFigure, facecolor="#EEF5FB", edgecolor="#D0D7DE")
        fig.patches.append(rect)
        fig.text(x + 0.075, 0.238, str(value), ha="center", fontsize=15, fontweight="bold")
        fig.text(x + 0.075, 0.212, label, ha="center", fontsize=8)
        x += 0.17
    fig.text(0.08, 0.08, "Generated by the mSEC-AM GitHub Actions audit workflow.", fontsize=8, color="#4B5563")
    pdf.savefig(fig)
    plt.close(fig)


def _add_methodology_scope_page(pdf: PdfPages, metrics: Dict[str, Any]) -> None:
    fig = plt.figure(figsize=(8.27, 11.69))
    fig.patch.set_facecolor("white")
    _add_page_title(fig, "Methodological scope", "What is measured in the run-metrics package and how it relates to the audit workflow.")
    y = 0.86
    y = _add_paragraph(fig, 0.08, y, "The package records telemetry from one audit execution. It is not an alternative audit engine. It documents how the current execution processed requirements, how LLM outputs were validated, and where deterministic fallback was used when an LLM response was incomplete or structurally invalid.")
    y = _add_paragraph(fig, 0.08, y, "The compliance results yes, no, and n/a are produced by the existing requirement-evaluation logic before this package is assembled. The run-metrics package records those results, their row-level hashes, and the telemetry needed to reproduce or compare executions later.")
    y = _add_paragraph(fig, 0.08, y, "The LLM-related metrics are control metrics. They do not grant the LLM authority to change the deterministic compliance result. They show whether the model returned valid JSON, whether the expected schema was present, whether all requested PUID-level items were returned, and whether the returned identifiers matched the deterministic context.")
    rows = [
        ["Audit adjudication", "Existing workbook logic", "Determines yes, no, and n/a."],
        ["LLM justifications", "LLM output plus validation", "Provides textual justifications when output is valid and traceable."],
        ["Deterministic fallback", "Local deterministic logic", "Provides a justification when LLM output is missing, incomplete, invalid, or rejected."],
        ["Run metrics", "Generated telemetry workbook and methodology PDF", "Records per-execution evidence, formulas, examples, and visual summaries."],
    ]
    _add_table(fig, [0.06, 0.23, 0.88, 0.30], rows, ["Layer", "Source", "Role"], fontsize=8.0, col_widths=[0.24, 0.31, 0.45])
    pdf.savefig(fig)
    plt.close(fig)



def _add_workbook_structure_page(pdf: PdfPages, metrics: Dict[str, Any]) -> None:
    fig = plt.figure(figsize=(8.27, 11.69))
    fig.patch.set_facecolor("white")
    _add_page_title(fig, "Companion workbook structure", "The Excel workbook contains raw exportable telemetry. Formulas, interpretation, and charts are documented in this PDF.")
    rows = [
        ["run_summary", "Run metadata, model, configuration hash, compliance matrix hash, counts, and paths."],
        ["input_hashes", "Input name, path, and SHA-256 hash for reproducibility checks."],
        ["compliance_export", "One row per requirement: PUID, result, flags used, justification length, and row hash."],
        ["llm_calls", "One row per LLM call: expected items, received items, validation flags, retries, time, model, and error."],
        ["llm_items", "One row per PUID-level LLM item: received status, completeness, traceability, fallback, source, and result."],
        ["prompt_inventory", "Registered audit-related prompt contracts, scope, category, source location, execution status, and observed prompt hashes."],
        ["prompt_calls", "One row per runtime prompt invocation: prompt ID, sequential call ID, model, schema, hashes, validation flags, retry, repair, and fallback."],
        ["prompt_controls", "Detected prompt-level controls such as JSON-only output, schema requirement, identifier preservation, grounding, no-invention, and no-result-change clauses."],
        ["prompt_contract_summary", "Prompt-count and prompt-validation metrics used to explain the LLM role and repeated-run comparability."],
        ["prompt_discovery_events", "New, unregistered, or review-required prompt discovery events."],
        ["package_manifest", "Artifact file names, paths, hashes, and package generation timestamp."],
    ]
    _add_table(fig, [0.075, 0.42, 0.85, 0.38], rows, ["Sheet", "Raw data captured"], fontsize=8.0, col_widths=[0.22, 0.78])
    y = 0.32
    y = _add_paragraph(fig, 0.08, y, "Example from the current execution: compliance_export contains 469 requirement rows. run_summary reports 18 yes results, 386 no results, and 65 n/a results. These numbers are copied from execution telemetry and are not recalculated by the PDF renderer.", width=94)
    y = _add_paragraph(fig, 0.08, y, "The workbook stores boolean-like telemetry as lowercase text values true and false. This avoids locale-dependent Excel displays such as VERDADERO or FALSO and makes the file easier to compare across machines.", width=94)
    pdf.savefig(fig)
    plt.close(fig)


def _add_metric_card(fig: Any, y: float, title: str, formula: str, source: str, current: str, meaning: str, example: str) -> float:
    rect = plt.Rectangle((0.065, y - 0.135), 0.87, 0.135, transform=fig.transFigure, facecolor="#F7F9FC", edgecolor="#D0D7DE")
    fig.patches.append(rect)
    fig.text(0.08, y - 0.016, title, fontsize=9.2, fontweight="bold", color="#17365D", va="top")
    fig.text(0.08, y - 0.041, f"Formula: {formula}", fontsize=7.7, color="#1F2933", va="top")
    fig.text(0.08, y - 0.064, f"Source: {source}", fontsize=7.7, color="#1F2933", va="top")
    fig.text(0.08, y - 0.087, f"Current execution: {current}", fontsize=7.7, color="#1F2933", va="top")
    fig.text(0.08, y - 0.110, _wrap_text(f"Meaning: {meaning} Example: {example}", 116), fontsize=7.2, color="#374151", va="top")
    return y - 0.158


def _add_metric_detail_page(pdf: PdfPages, metrics: Dict[str, Any]) -> None:
    metric_rows = [
        ("JSON validity rate", "json_valid_count / num_llm_calls", "llm_calls.json_valid", f"{metrics['json_valid_count']} / {metrics['num_llm_calls']} = {_pct(metrics['json_valid_rate'])}", "Checks whether each LLM response was parseable as a complete JSON object.", "LLM-0007 had json_valid=false because no complete JSON object was found in the model output."),
        ("Schema validity rate", "schema_valid_count / num_llm_calls", "llm_calls.schema_valid", f"{metrics['schema_valid_count']} / {metrics['num_llm_calls']} = {_pct(metrics['schema_valid_rate'])}", "Checks whether the parsed response had the expected structured fields.", "LLM-0007 also had schema_valid=false because the response could not be accepted as the expected items object."),
        ("Completion rate", "received_items_count / expected_items_count", "llm_calls.expected_items and llm_calls.received_items", f"{metrics['received_items']} / {metrics['expected_items']} = {_pct(metrics['completion_rate'])}", "Checks whether the LLM returned all requested PUID-level items.", "In this execution, the LLM returned 448 of 469 expected PUID-level items."),
        ("Traceability preservation rate", "traceability_ok_count / expected_items_count", "llm_items.traceability_ok", f"{metrics['traceability_ok']} / {metrics['traceability_expected']} = {_pct(metrics['traceability_ok_rate'])}", "Checks whether returned identifiers match the deterministic PUID context sent to the model.", "Items not returned by the LLM have traceability_ok=false and are handled by deterministic fallback."),
        ("Fallback rate", "fallback_count / num_requirements", "llm_items.fallback_used and compliance_export", f"{metrics['fallback_count']} / {metrics['num_requirements']} = {_pct(metrics['fallback_rate'])}", "Measures how often deterministic fallback supplied a justification after a missing, incomplete, or rejected LLM item.", "SECM-CAT-ISU-016 is an example where fallback_used=true and justification_source=deterministic_fallback."),
        ("Retry rate", "retry_count / num_llm_calls", "llm_calls.retry_count", f"{metrics['retry_count']} / {metrics['num_llm_calls']} = {_pct(metrics['retry_rate'])}", "Measures operational recovery effort at the LLM-call level.", "LLM-0001 had retry_count=1 and LLM-0007 had retry_count=2 in this execution."),
    ]
    for page_idx in range(0, len(metric_rows), 3):
        fig = plt.figure(figsize=(8.27, 11.69))
        fig.patch.set_facecolor("white")
        title = "Metric calculation methodology" if page_idx == 0 else "Metric calculation methodology continued"
        _add_page_title(fig, title, "Each metric is computed from explicit rows in run-metrics.xlsx and interpreted as a control over the execution.")
        y = 0.82
        for row in metric_rows[page_idx:page_idx + 3]:
            y = _add_metric_card(fig, y, *row)
        y = _add_paragraph(fig, 0.08, 0.28, "Interpretation rule: high JSON, schema, completion, and traceability rates indicate that the LLM layer followed the controlled output contract. Fallback and retry rates are expected to be low, but nonzero values are acceptable because fallback preserves deterministic execution continuity.", width=94, fontsize=8.8)
        pdf.savefig(fig)
        plt.close(fig)

def _add_compliance_hash_page(pdf: PdfPages, metrics: Dict[str, Any]) -> None:
    fig = plt.figure(figsize=(8.27, 11.69))
    fig.patch.set_facecolor("white")
    _add_page_title(fig, "Compliance export and row hashing", "How the per-requirement export supports later repeated-run analysis.")
    examples = metrics.get("examples", {})
    yes_ex = examples.get("yes_requirement", {}) or {}
    no_ex = examples.get("no_requirement", {}) or {}
    na_ex = examples.get("na_requirement", {}) or {}
    rows = []
    for label, ex in [("yes example", yes_ex), ("no example", no_ex), ("n/a example", na_ex)]:
        if ex:
            rows.append([label, ex.get("puid", ""), ex.get("result", ""), _short_text(ex.get("flags_used", ""), 70), _short_text(ex.get("row_hash", ""), 24)])
    if not rows:
        rows = [["No example available", "", "", "", ""]]
    _add_table(fig, [0.045, 0.48, 0.91, 0.34], rows, ["Example", "PUID", "Result", "Flags used", "Row hash"], fontsize=6.5, col_widths=[0.15, 0.20, 0.09, 0.38, 0.18])
    y = 0.39
    y = _add_paragraph(fig, 0.08, y, "The row hash is computed from the PUID, the deterministic result, and the list of flags used for that requirement. It does not include the narrative justification, so minor wording changes do not change the row hash.", width=94)
    y = _add_paragraph(fig, 0.08, y, "The compliance matrix hash is computed from the ordered collection of row hashes. In this execution, the compliance matrix hash recorded in run_summary is " + str(metrics.get("summary", {}).get("compliance_matrix_hash", "")) + ".", width=94)
    y = _add_paragraph(fig, 0.08, y, "When multiple run-metrics.xlsx files are downloaded later, compliance_export can be joined by PUID and compared row by row. This package therefore provides raw material for subsequent repeated-run analysis without embedding cross-run calculations in a single execution.", width=94)
    pdf.savefig(fig)
    plt.close(fig)



def _add_real_llm_examples_page(pdf: PdfPages, metrics: Dict[str, Any]) -> None:
    fig = plt.figure(figsize=(8.27, 11.69))
    fig.patch.set_facecolor("white")
    _add_page_title(fig, "Real LLM validation examples from this execution", "How invalid output, fallback, and retry telemetry should be read.")
    ex = metrics.get("examples", {})
    failed = ex.get("failed_call", {}) or {}
    fallback = ex.get("fallback_item", {}) or {}
    retry = ex.get("retry_call", {}) or {}
    y = 0.84
    if failed:
        y = _add_paragraph(fig, 0.08, y, f"Invalid or incomplete LLM call example: {failed.get('llm_call_id', '')} expected {failed.get('expected_items', '')} items and received {failed.get('received_items', '')}. json_valid={str(failed.get('json_valid')).lower()}, schema_valid={str(failed.get('schema_valid')).lower()}, retry_count={failed.get('retry_count', '')}, elapsed_s={failed.get('elapsed_s', '')}.", width=94)
        y = _add_paragraph(fig, 0.10, y, "Error recorded in llm_calls: " + _short_text(failed.get("error", ""), 320), width=90, fontsize=8.2, color="#4B5563")
    if retry:
        y = _add_paragraph(fig, 0.08, y, f"Retry example: {retry.get('llm_call_id', '')} records retry_count={retry.get('retry_count', '')}. This means the workflow attempted to recover from invalid or incomplete output before accepting or rejecting the final response for that call.", width=94)
    if fallback:
        y = _add_paragraph(fig, 0.08, y, f"Deterministic fallback item example: {fallback.get('puid', '')} has expected_by_llm={str(fallback.get('expected_by_llm')).lower()}, received_from_llm={str(fallback.get('received_from_llm')).lower()}, field_complete={str(fallback.get('field_complete')).lower()}, traceability_ok={str(fallback.get('traceability_ok')).lower()}, fallback_used={str(fallback.get('fallback_used')).lower()}, justification_source={fallback.get('justification_source', '')}, and result={fallback.get('result', '')}.", width=94)
    y = _add_paragraph(fig, 0.08, y, "Interpretation: when expected_by_llm=true but received_from_llm=false, the model did not return an accepted PUID-level justification. The workflow keeps the deterministic requirement result and replaces only the missing or invalid justification with deterministic fallback text.", width=94)
    y = _add_paragraph(fig, 0.08, y, "This behavior is intentional. It shows that malformed or incomplete LLM output is isolated and does not override the requirement result.", width=94, color="#17365D")
    pdf.savefig(fig)
    plt.close(fig)

def _add_chart_page(pdf: PdfPages, fig: Any, caption: str) -> None:
    fig.text(0.08, 0.05, _wrap_text(caption, 110), fontsize=8.5, color="#4B5563")
    pdf.savefig(fig)
    plt.close(fig)




def _add_prompt_contract_methodology_page(pdf: PdfPages, metrics: Dict[str, Any]) -> None:
    prompt = metrics.get("prompt_metrics", {})
    summary_rows = prompt.get("prompt_contract_summary", [])
    lookup = {str(r.get("metric")): r.get("value") for r in summary_rows if isinstance(r, dict)}
    fig = plt.figure(figsize=(8.27, 11.69))
    fig.patch.set_facecolor("white")
    _add_page_title(fig, "Prompt-contract control model", "How LLM prompts are identified, controlled, validated, and prepared for repeated-run stability analysis.")
    y = 0.86
    y = _add_paragraph(fig, 0.08, y, "Each runtime LLM invocation is assigned a sequential prompt_call_id and linked to a stable prompt_id. Prompt contracts are classified by scope: audit_matrix, audit_summary, audit_summary_repair, run_metrics, or infrastructure. Only audit-related prompt contracts are used to explain the role of the LLM in the audit workflow.", width=94)
    y = _add_paragraph(fig, 0.08, y, "The prompt inventory separates primary prompts from auxiliary repair prompts. Primary prompts generate requirement justifications or Audit Summary content. Auxiliary repair prompts only complete missing structured treatment fields; they do not adjudicate compliance, alter yes/no/n/a outcomes, or introduce new evidence.", width=94)
    rows = [
        ["Registered prompt contracts", lookup.get("registered_prompt_contract_count", "")],
        ["Primary audit-related prompts", lookup.get("primary_audit_related_prompt_count", "")],
        ["Auxiliary repair prompts", lookup.get("auxiliary_repair_prompt_count", "")],
        ["Runtime prompt calls", lookup.get("executed_prompt_call_count", "")],
        ["Unregistered prompt calls", lookup.get("unregistered_prompt_call_count", "")],
        ["Prompt inventory hash", _short_text(lookup.get("prompt_inventory_hash", ""), 72)],
    ]
    _add_table(fig, [0.08, 0.44, 0.84, 0.27], rows, ["Metric", "Value"], fontsize=8.0, col_widths=[0.45, 0.55])
    y = 0.36
    y = _add_paragraph(fig, 0.08, y, "The prompt_controls sheet records whether each prompt call contains control clauses for JSON-only output, schema adherence, identifier preservation, grounding in provided evidence, no invented evidence, no change to precomputed compliance results, English-only output, and repair or retry behavior.", width=94)
    y = _add_paragraph(fig, 0.08, y, "For repeated-run analysis, prompt_inventory_hash, prompt_hash, schema_hash, payload_hash, and llm_config_hash allow the analyst to verify that executions compared in stability-analysis.xlsx used fixed prompt contracts, fixed output schemas, fixed inputs, and fixed LLM configuration.", width=94)
    pdf.savefig(fig)
    plt.close(fig)

def _generate_methodology_pdf(output_pdf: Path, metrics: Dict[str, Any]) -> None:
    output_pdf.parent.mkdir(parents=True, exist_ok=True)
    with PdfPages(output_pdf) as pdf:
        _add_title_page(pdf, metrics)
        _add_methodology_scope_page(pdf, metrics)
        _add_workbook_structure_page(pdf, metrics)
        _add_prompt_contract_methodology_page(pdf, metrics)
        _add_metric_detail_page(pdf, metrics)
        _add_compliance_hash_page(pdf, metrics)
        _add_real_llm_examples_page(pdf, metrics)
        _add_chart_page(
            pdf,
            _plot_bar(["yes", "no", "n/a"], [metrics["counts"].get("yes", 0), metrics["counts"].get("no", 0), metrics["counts"].get("n/a", 0)], "Compliance result distribution", "Requirement count"),
            "This chart summarizes the deterministic compliance result distribution recorded in compliance_export. It does not recalculate or reinterpret the audit outcome."
        )
        _add_chart_page(
            pdf,
            _plot_bar(["JSON", "schema", "completion", "traceability"], [metrics["json_valid_rate"], metrics["schema_valid_rate"], metrics["completion_rate"], metrics["traceability_ok_rate"]], "LLM output validation rates", "Rate", percent=True),
            "This chart shows how well LLM responses followed the structured-output contract in this execution. JSON and schema are call-level checks; completion and traceability are PUID-level checks."
        )
        _add_chart_page(
            pdf,
            _plot_bar(["fallback", "retry"], [metrics["fallback_rate"], metrics["retry_rate"]], "Fallback and retry rates", "Rate", percent=True),
            "Fallback indicates deterministic justification replacement after an invalid, missing, or rejected LLM item. Retry indicates operational recovery attempts at the LLM-call level."
        )

def build(args: argparse.Namespace) -> None:
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    raw_path = Path(args.raw_metrics)
    if not raw_path.is_file():
        raise SystemExit(f"Missing run metrics workbook: {raw_path}")

    output_xlsx = out_dir / RUN_METRICS_XLSX
    output_pdf = out_dir / RUN_METRICS_PDF
    if raw_path.resolve() != output_xlsx.resolve():
        shutil.copy2(raw_path, output_xlsx)

    wb = openpyxl.load_workbook(output_xlsx)
    _remove_non_raw_sheets(wb)
    existing_prompt_calls = _read_sheet_as_dicts(wb, "prompt_calls")
    prompt_telemetry = Path(args.prompt_telemetry) if str(args.prompt_telemetry or "").strip() else None
    prompt_metrics = _prepare_prompt_metrics(prompt_telemetry, extra_prompt_calls=existing_prompt_calls)
    metrics = _compute_metrics(wb)
    metrics["prompt_metrics"] = prompt_metrics
    _add_prompt_sheets(wb, prompt_metrics)
    _add_package_manifest_sheet(wb, raw_path, output_xlsx, output_pdf)
    _normalize_workbook_for_export(wb)
    _style_workbook(wb)
    wb.save(output_xlsx)

    _generate_methodology_pdf(output_pdf, metrics)

    # Update manifest hashes after the PDF exists.
    wb = openpyxl.load_workbook(output_xlsx)
    _add_package_manifest_sheet(wb, raw_path, output_xlsx, output_pdf)
    _normalize_workbook_for_export(wb)
    _style_workbook(wb)
    wb.save(output_xlsx)

    print(f"[OK] Run metrics workbook: {output_xlsx}")
    print(f"[OK] Run metrics methodology PDF: {output_pdf}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a styled per-run metrics workbook and methodology PDF.")
    parser.add_argument("--raw-metrics", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--analysis-pack", required=False, default="")
    parser.add_argument("--audit-summary-docx", required=False, default="")
    parser.add_argument("--audit-summary-pdf", required=False, default="")
    parser.add_argument("--prompt-telemetry", required=False, default=os.getenv("PROMPT_TELEMETRY_PATH", ""))
    return parser.parse_args()


if __name__ == "__main__":
    build(parse_args())
