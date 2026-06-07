#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Conditional startup hook for Audit Summary report generation.

Python imports sitecustomize before running a script when the module is present
on sys.path. This hook is intentionally narrow: it only applies the Audit
Summary report-quality patches when the current Python process is executing one
of the two Audit Summary generation scripts. It does not affect other scripts,
workflows, or tools.
"""

from __future__ import annotations

import py_compile
import sys
from pathlib import Path


def _should_patch() -> bool:
    argv = " ".join(str(x) for x in sys.argv).replace("\\", "/")
    return (
        "audit_summary_stage1_build_analysis_pack.py" in argv
        or "audit_summary_stage2_generate_docx.py" in argv
    )


def _post_patch_cleanup(scripts_dir: Path) -> None:
    """Repair escaped word-boundary regexes if a runtime patch inserted them as backspace chars."""
    for filename in (
        "audit_summary_stage1_build_analysis_pack.py",
        "audit_summary_stage2_generate_docx.py",
    ):
        target = scripts_dir / filename
        if not target.is_file():
            continue

        text = target.read_text(encoding="utf-8")
        if "\x08" in text:
            text = text.replace("\x08", r"\b")
            target.write_text(text, encoding="utf-8")
            print(f"[OK] Audit Summary runtime patch cleanup normalized regex word-boundaries in {filename}.")

        py_compile.compile(str(target), doraise=True)


def _run_patch() -> None:
    if not _should_patch():
        return

    scripts_dir = Path(__file__).resolve().parent
    patch_path = scripts_dir / "audit_summary_runtime_report_patches.py"
    if not patch_path.is_file():
        return

    try:
        namespace = {"__name__": "__audit_summary_runtime_report_patches__", "__file__": str(patch_path)}
        code = compile(patch_path.read_text(encoding="utf-8"), str(patch_path), "exec")
        exec(code, namespace)
        main = namespace.get("main")
        if callable(main):
            main()
    except Exception as exc:
        print(f"[WARN] Audit Summary runtime report patch hook failed before cleanup: {exc}", file=sys.stderr)
    finally:
        try:
            _post_patch_cleanup(scripts_dir)
        except Exception as cleanup_exc:
            print(f"[WARN] Audit Summary runtime report patch cleanup failed: {cleanup_exc}", file=sys.stderr)


_run_patch()
