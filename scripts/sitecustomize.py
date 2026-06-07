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

import sys
from pathlib import Path


def _should_patch() -> bool:
    argv = " ".join(str(x) for x in sys.argv).replace("\\", "/")
    return (
        "audit_summary_stage1_build_analysis_pack.py" in argv
        or "audit_summary_stage2_generate_docx.py" in argv
    )


def _run_patch() -> None:
    if not _should_patch():
        return

    scripts_dir = Path(__file__).resolve().parent
    patch_path = scripts_dir / "audit_summary_runtime_report_patches.py"
    if not patch_path.is_file():
        return

    namespace = {"__name__": "__audit_summary_runtime_report_patches__", "__file__": str(patch_path)}
    code = compile(patch_path.read_text(encoding="utf-8"), str(patch_path), "exec")
    exec(code, namespace)
    main = namespace.get("main")
    if callable(main):
        main()


try:
    _run_patch()
except Exception as exc:
    print(f"[WARN] Audit Summary runtime report patch hook failed: {exc}", file=sys.stderr)
