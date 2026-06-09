#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import hashlib
import math
import shutil
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
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


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

    return {
        "summary": summary,
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
        "json_valid_rate": _rate(json_valid_count, num_llm_calls),
        "schema_valid_rate": _rate(schema_valid_count, num_llm_calls),
        "completion_rate": _rate(received_items, expected_items),
        "traceability_ok_rate": _rate(traceability_ok, traceability_expected),
        "fallback_rate": _rate(fallback_count, num_requirements),
        "retry_rate": _rate(retry_count, num_llm_calls),
    }


def _remove_non_raw_sheets(wb: Any) -> None:
    allowed = {"run_summary", "input_hashes", "compliance_export", "llm_calls", "llm_items", "package_manifest"}
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


def _add_title_page(pdf: PdfPages, metrics: Dict[str, Any]) -> None:
    summary = metrics.get("summary", {})
    fig = plt.figure(figsize=(8.27, 11.69))
    fig.patch.set_facecolor("white")
    fig.text(0.5, 0.92, "Run Metrics Methodology", ha="center", fontsize=22, fontweight="bold")
    fig.text(0.5, 0.885, "Per-execution evidence package for audit reproducibility", ha="center", fontsize=11, style="italic")
    purpose = (
        "This document describes the formulas, interpretation criteria, and visual summaries produced for the current audit execution. "
        "The companion spreadsheet contains raw exportable telemetry structured for subsequent repeated-run analysis when multiple executions are available."
    )
    fig.text(0.08, 0.81, "Purpose", fontsize=14, fontweight="bold")
    fig.text(0.08, 0.77, purpose, fontsize=10, wrap=True)

    rows = [
        ("Run ID", summary.get("run_id", "")),
        ("Repository", summary.get("repository", "")),
        ("Commit SHA", summary.get("commit_sha", "")),
        ("Model", summary.get("config.OPENAI_MODEL") or summary.get("config.AI_MODEL") or ""),
        ("AI profile", summary.get("config.AI_PROFILE", "")),
        ("LLM configuration hash", summary.get("llm_config_hash", "")),
        ("Compliance matrix hash", summary.get("compliance_matrix_hash", "")),
        ("Generated at", summary.get("generated_at_utc", _now_utc())),
    ]
    ax = fig.add_axes([0.08, 0.40, 0.84, 0.30])
    ax.axis("off")
    table = ax.table(cellText=[[k, str(v)] for k, v in rows], colLabels=["Field", "Value"], loc="center", cellLoc="left", colWidths=[0.28, 0.72])
    table.auto_set_font_size(False)
    table.set_fontsize(8.5)
    table.scale(1, 1.45)
    for (r, c), cell in table.get_celld().items():
        cell.set_edgecolor("#D0D7DE")
        if r == 0:
            cell.set_facecolor("#17365D")
            cell.set_text_props(color="white", weight="bold")
        elif c == 0:
            cell.set_facecolor("#EEF5FB")
            cell.set_text_props(weight="bold")
    fig.text(0.08, 0.31, "Current execution at a glance", fontsize=14, fontweight="bold")
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


def _add_formula_page(pdf: PdfPages, metrics: Dict[str, Any]) -> None:
    fig = plt.figure(figsize=(8.27, 11.69))
    fig.patch.set_facecolor("white")
    fig.text(0.08, 0.94, "Metric formulas and interpretation", fontsize=16, fontweight="bold")
    rows = [
        ["JSON validity rate", "json_valid_count / num_llm_calls", "Formal parseability of LLM responses."],
        ["Schema validity rate", "schema_valid_count / num_llm_calls", "Conformance with the expected response structure."],
        ["Completion rate", "received_items_count / expected_items_count", "Whether the LLM returned all requested PUID-level items."],
        ["Traceability preservation rate", "traceability_ok_count / expected_items_count", "Whether returned PUIDs match the deterministic context."],
        ["Fallback rate", "fallback_count / num_requirements", "Frequency of deterministic fallback usage."],
        ["Retry rate", "retry_count / num_llm_calls", "Operational effort required to obtain valid outputs."],
    ]
    ax = fig.add_axes([0.05, 0.47, 0.90, 0.40])
    ax.axis("off")
    table = ax.table(cellText=rows, colLabels=["Metric", "Formula", "Interpretation"], loc="center", cellLoc="left", colWidths=[0.24, 0.31, 0.45])
    table.auto_set_font_size(False)
    table.set_fontsize(8)
    table.scale(1, 1.7)
    for (r, c), cell in table.get_celld().items():
        cell.set_edgecolor("#D0D7DE")
        if r == 0:
            cell.set_facecolor("#17365D")
            cell.set_text_props(color="white", weight="bold")
        elif r % 2 == 0:
            cell.set_facecolor("#F7F9FC")

    values = [
        ["Number of requirements", str(metrics["num_requirements"])],
        ["Number of LLM calls", str(metrics["num_llm_calls"])],
        ["JSON validity rate", f"{metrics['json_valid_rate']:.1%}"],
        ["Schema validity rate", f"{metrics['schema_valid_rate']:.1%}"],
        ["Completion rate", f"{metrics['completion_rate']:.1%}"],
        ["Traceability preservation rate", f"{metrics['traceability_ok_rate']:.1%}"],
        ["Fallback rate", f"{metrics['fallback_rate']:.1%}"],
        ["Retry rate", f"{metrics['retry_rate']:.1%}"],
    ]
    ax2 = fig.add_axes([0.14, 0.14, 0.72, 0.25])
    ax2.axis("off")
    table2 = ax2.table(cellText=values, colLabels=["Current execution metric", "Value"], loc="center", cellLoc="left", colWidths=[0.65, 0.35])
    table2.auto_set_font_size(False)
    table2.set_fontsize(8.5)
    table2.scale(1, 1.35)
    for (r, c), cell in table2.get_celld().items():
        cell.set_edgecolor("#D0D7DE")
        if r == 0:
            cell.set_facecolor("#17365D")
            cell.set_text_props(color="white", weight="bold")
        elif c == 0:
            cell.set_facecolor("#EEF5FB")
    pdf.savefig(fig)
    plt.close(fig)


def _generate_methodology_pdf(output_pdf: Path, metrics: Dict[str, Any]) -> None:
    output_pdf.parent.mkdir(parents=True, exist_ok=True)
    with PdfPages(output_pdf) as pdf:
        _add_title_page(pdf, metrics)
        _add_formula_page(pdf, metrics)
        pdf.savefig(_plot_bar(["yes", "no", "n/a"], [metrics["counts"].get("yes", 0), metrics["counts"].get("no", 0), metrics["counts"].get("n/a", 0)], "Compliance result distribution", "Requirement count"))
        plt.close()
        pdf.savefig(_plot_bar(["JSON", "schema", "completion", "traceability"], [metrics["json_valid_rate"], metrics["schema_valid_rate"], metrics["completion_rate"], metrics["traceability_ok_rate"]], "LLM output validation rates", "Rate", percent=True))
        plt.close()
        pdf.savefig(_plot_bar(["fallback", "retry"], [metrics["fallback_rate"], metrics["retry_rate"]], "Fallback and retry rates", "Rate", percent=True))
        plt.close()


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
    metrics = _compute_metrics(wb)
    _add_package_manifest_sheet(wb, raw_path, output_xlsx, output_pdf)
    _style_workbook(wb)
    wb.save(output_xlsx)

    _generate_methodology_pdf(output_pdf, metrics)

    # Update manifest hashes after the PDF exists.
    wb = openpyxl.load_workbook(output_xlsx)
    _add_package_manifest_sheet(wb, raw_path, output_xlsx, output_pdf)
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
    return parser.parse_args()


if __name__ == "__main__":
    build(parse_args())
