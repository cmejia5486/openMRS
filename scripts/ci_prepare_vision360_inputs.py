#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import shutil
import sys
import zipfile
from typing import Dict, List, Optional, Tuple


REQUIRED = {
    "mobsf-report.zip": {
        "members_all": ["mobsf_results.json"],
        "member_aliases": {
            "mobsf_results.json": ["mobsf_results.json", "mobsf-report.json"],
        },
        "zip_filename_aliases": ["mobsf-report.zip"],
    },
    "mobsf-dynamic-report.zip": {
        "members_all": ["mobsf_dynamic_results.json"],
        "member_aliases": {
            "mobsf_dynamic_results.json": ["mobsf_dynamic_results.json", "mobsf-dynamic-report.json"],
        },
        "zip_filename_aliases": ["mobsf-dynamic-report.zip"],
    },
    "openMRS.zip": {
        "members_all": [],
        "member_aliases": {},
        "zip_filename_aliases": [
            "openMRS.zip",
            "openmrs.zip",
            "openmrs-zip.zip",
            "openmrs_source.zip",
            "app-zip.zip",
        ],
    },
    "sast-findings.zip": {
        "members_all": ["merged.sarif", "semgrep.sarif"],
        "member_aliases": {
            "merged.sarif": ["merged.sarif"],
            "semgrep.sarif": ["semgrep.sarif"],
        },
        "zip_filename_aliases": ["sast-findings.zip"],
    },
    "trivy-payload.zip": {
        "members_all": ["trivy.json", "agent_payload.json"],
        "member_aliases": {
            "trivy.json": ["trivy.json"],
            "agent_payload.json": ["agent_payload.json"],
        },
        "zip_filename_aliases": ["trivy-payload.zip"],
    },
}


def walk_files(root: str) -> List[str]:
    out = []
    for base, _, files in os.walk(root):
        for fn in files:
            out.append(os.path.join(base, fn))
    return out


def is_zip(path: str) -> bool:
    if not os.path.isfile(path):
        return False
    if not path.lower().endswith(".zip"):
        return False
    try:
        with zipfile.ZipFile(path, "r") as zf:
            zf.testzip()
        return True
    except Exception:
        return False


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def copy_to(src: str, dst: str) -> None:
    ensure_dir(os.path.dirname(dst))
    shutil.copy2(src, dst)


def _norm_name(name: str) -> str:
    return name.replace("\\", "/").strip("/").lower()


def _basename_norm(name: str) -> str:
    return os.path.basename(_norm_name(name))


def _accepted_aliases(spec: Dict[str, object], canonical_member: str) -> List[str]:
    aliases = spec.get("member_aliases", {})
    if isinstance(aliases, dict):
        values = aliases.get(canonical_member, [])
        if isinstance(values, list):
            out = [str(v) for v in values if str(v).strip()]
            if canonical_member not in out:
                out.insert(0, canonical_member)
            return out
    return [canonical_member]


def find_zip_member(zf: zipfile.ZipFile, accepted_names: List[str]) -> Optional[str]:
    names = zf.namelist()
    accepted_exact = {_norm_name(n) for n in accepted_names}
    accepted_base = {_basename_norm(n) for n in accepted_names}

    for name in names:
        if _norm_name(name) in accepted_exact:
            return name

    for name in names:
        if _basename_norm(name) in accepted_base:
            return name

    return None


def zip_can_satisfy(zip_path: str, spec: Dict[str, object]) -> bool:
    members_all = [str(m) for m in spec.get("members_all", [])]
    if not is_zip(zip_path):
        return False

    if not members_all:
        return True

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            for canonical in members_all:
                if find_zip_member(zf, _accepted_aliases(spec, canonical)) is None:
                    return False
        return True
    except Exception:
        return False


def zip_is_already_canonical(zip_path: str, spec: Dict[str, object]) -> bool:
    members_all = [str(m) for m in spec.get("members_all", [])]
    if not members_all:
        return True

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            names = {_norm_name(n) for n in zf.namelist()}
        return all(_norm_name(m) in names for m in members_all)
    except Exception:
        return False


def find_best_zip_candidate(files: List[str], expected_name: str, spec: Dict[str, object]) -> Optional[str]:
    aliases = [expected_name]
    for alias in spec.get("zip_filename_aliases", []):
        s = str(alias).strip()
        if s and s not in aliases:
            aliases.append(s)

    alias_set = {a.lower() for a in aliases}

    exact = [p for p in files if os.path.basename(p).lower() in alias_set and is_zip(p)]
    for p in exact:
        if zip_can_satisfy(p, spec):
            return p

    if spec.get("members_all"):
        zips = [p for p in files if is_zip(p)]
        for p in zips:
            if zip_can_satisfy(p, spec):
                return p

    return None


def find_raw_members(files: List[str], spec: Dict[str, object]) -> Dict[str, str]:
    found: Dict[str, str] = {}
    members_all = [str(m) for m in spec.get("members_all", [])]

    want_base: Dict[str, str] = {}

    for canonical in members_all:
        for alias in _accepted_aliases(spec, canonical):
            want_base[_basename_norm(alias)] = canonical

    for p in files:
        base_key = _basename_norm(os.path.basename(p))
        canonical = want_base.get(base_key)
        if canonical and canonical not in found:
            found[canonical] = p

    return found


def build_zip_from_raw(raw_map: Dict[str, str], dst_zip: str) -> None:
    ensure_dir(os.path.dirname(dst_zip))
    with zipfile.ZipFile(dst_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for member_name, src_path in raw_map.items():
            zf.write(src_path, arcname=member_name)


def build_normalized_zip_from_zip(src_zip: str, dst_zip: str, spec: Dict[str, object]) -> None:
    members_all = [str(m) for m in spec.get("members_all", [])]
    ensure_dir(os.path.dirname(dst_zip))

    with zipfile.ZipFile(src_zip, "r") as zf_in:
        with zipfile.ZipFile(dst_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf_out:
            for canonical in members_all:
                source_member = find_zip_member(zf_in, _accepted_aliases(spec, canonical))
                if source_member is None:
                    raise RuntimeError(f"{os.path.basename(src_zip)} does not contain {canonical} or accepted aliases")
                data = zf_in.read(source_member)
                zf_out.writestr(canonical, data)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifacts-dir", required=True, help="Directory where actions/download-artifact stored files.")
    ap.add_argument("--out-dir", default="/mnt/data", help="Output directory, default: /mnt/data.")
    args = ap.parse_args()

    artifacts_dir = os.path.abspath(args.artifacts_dir)
    out_dir = os.path.abspath(args.out_dir)

    if not os.path.isdir(artifacts_dir):
        print(f"[ERR] artifacts-dir not found: {artifacts_dir}", file=sys.stderr)
        return 2

    ensure_dir(out_dir)
    files = walk_files(artifacts_dir)

    plan: List[Tuple[str, str]] = []
    missing: List[str] = []

    for expected_zip, spec in REQUIRED.items():
        dst = os.path.join(out_dir, expected_zip)

        if expected_zip == "openMRS.zip":
            cand = find_best_zip_candidate(files, expected_zip, spec)
            if cand is None:
                missing.append(expected_zip)
                continue
            copy_to(cand, dst)
            plan.append((expected_zip, f"copied source zip from {os.path.relpath(cand, artifacts_dir)}"))
            continue

        cand_zip = find_best_zip_candidate(files, expected_zip, spec)
        if cand_zip:
            if zip_is_already_canonical(cand_zip, spec):
                copy_to(cand_zip, dst)
                plan.append((expected_zip, f"copied canonical zip from {os.path.relpath(cand_zip, artifacts_dir)}"))
            else:
                build_normalized_zip_from_zip(cand_zip, dst, spec)
                plan.append((expected_zip, f"built normalized zip from aliased zip {os.path.relpath(cand_zip, artifacts_dir)}"))
            continue

        raw_map = find_raw_members(files, spec)
        members_all = [str(m) for m in spec.get("members_all", [])]
        if members_all and all(k in raw_map for k in members_all):
            build_zip_from_raw(raw_map, dst)
            srcs = ", ".join(os.path.relpath(raw_map[k], artifacts_dir) for k in members_all)
            plan.append((expected_zip, f"built normalized zip from raw files: {srcs}"))
            continue

        missing.append(expected_zip)

    if missing:
        print("[ERR] Missing required VISION360 inputs after artifact download:", file=sys.stderr)
        for m in missing:
            print(f"  - {m}", file=sys.stderr)
        print("\n[HINT] Ensure upstream jobs upload artifacts containing these members or aliases:", file=sys.stderr)
        print("  - mobsf-report.json or mobsf_results.json, static MobSF", file=sys.stderr)
        print("  - mobsf-dynamic-report.json or mobsf_dynamic_results.json, dynamic MobSF", file=sys.stderr)
        print("  - merged.sarif and semgrep.sarif, SAST", file=sys.stderr)
        print("  - trivy.json and agent_payload.json", file=sys.stderr)
        print("  - app-zip.zip, openMRS.zip, openmrs-zip.zip, or openmrs_source.zip from the source snapshot job", file=sys.stderr)
        return 2

    print("[OK] Prepared VISION360 inputs in:", out_dir)
    for name, how in plan:
        print(f"  - {name}: {how}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
