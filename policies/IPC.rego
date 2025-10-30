package secmcat.ipc
import rego.v1



# Auto-generated helpers (safe getters and detectors)

# Safe getter
getp(obj, key, dflt) = out {
  out := object.get(obj, key, dflt)
}

# ---- Trivy (agent payload shape) ----
trivy_findings := getp(getp(input, "trivy", {}), "findings", [])
has_trivy_high_or_critical if {
  some i
  f := trivy_findings[i]
  s := upper(getp(f, "severity", ""))
  s in {"HIGH","CRITICAL"}
}

# ---- Dependency scanner (generic) ----
dependency_findings := getp(getp(input, "dependency", {}), "findings", [])
has_dependency_high_or_critical if {
  some i
  f := dependency_findings[i]
  s := upper(getp(f, "severity", ""))
  s in {"HIGH","CRITICAL"}
}

# ---- CodeQL/SARIF (opcional) ----
codeql := getp(input, "codeql", {})
codeql_has_high_or_critical if {
  some i
  run := getp(getp(codeql, "runs", []), i, {})
  res := getp(run, "results", [])
  some j
  r := res[j]
  sev := upper(getp(getp(r, "properties", {}), "securitySeverity", getp(r, "severity", "")))
  sev in {"HIGH","CRITICAL"}
}

# ---- MobSF ----
mobsf := getp(input, "mobsf", {})
mobsf_manifest_findings := getp(getp(mobsf, "manifest_analysis", {}), "manifest_findings", [])
mobsf_code_map := getp(getp(mobsf, "code_analysis", {}), "findings", {})

mobsf_manifest_has(rule_name) if {
  some i
  f := mobsf_manifest_findings[i]
  getp(f, "rule", "") == rule_name
}

mobsf_manifest_has_sev(rule_name, min_sev) if {
  some i
  f := mobsf_manifest_findings[i]
  getp(f, "rule", "") == rule_name
  sev := upper(getp(f, "severity", ""))
  wanted := {"CRITICAL":4,"HIGH":3,"WARNING":2,"INFO":1}
  wanted[sev] >= wanted[upper(min_sev)]
}

mobsf_code_has(key) if {
  v := getp(mobsf_code_map, key, null)
  v != null
}

# Certificate debug check (MobSF summary)
mobsf_debug_cert_present if {
  summary := getp(getp(mobsf, "certificate_analysis", {}), "certificate_summary", {})
  high := getp(summary, "high", 0)
  high > 0
}

# --------- Predicados de cumplimiento (true == compliant) ---------

compliant_no_hardcoded_secrets if {
  not mobsf_code_has("android_hardcoded")
}

compliant_not_debuggable if {
  not mobsf_manifest_has_sev("app_is_debuggable", "high")
  not mobsf_code_has("android_aar_jar_debug_enabled")
}

compliant_no_allow_backup if {
  not mobsf_manifest_has("app_allowbackup")
}

compliant_no_exported_components if {
  not mobsf_manifest_has("exported_intent_filter_exists")
}

compliant_secure_min_sdk if {
  not mobsf_manifest_has("vulnerable_os_version")
}

compliant_no_external_storage if {
  not mobsf_code_has("android_read_write_external")
}

compliant_no_sensitive_logging if {
  not mobsf_code_has("android_logging")
}

compliant_no_raw_sql if {
  not mobsf_code_has("android_sql_raw_query")
}

compliant_no_weak_hashes if {
  not mobsf_code_has("android_sha1")
}

compliant_secure_rng if {
  not mobsf_code_has("android_insecure_random")
}

compliant_tls_or_pinning if {
  tls := getp(input, "tls_enabled", false)
  good_pinning := mobsf_code_has("android_ssl_pinning")
  tls == true or good_pinning
}

compliant_no_high_vulns if {
  not has_trivy_high_or_critical
  not has_dependency_high_or_critical
  not codeql_has_high_or_critical
}

compliant_no_clipboard_sensitive if {
  not mobsf_code_has("android_clipboard_copy")
}

compliant_no_debug_certificate if {
  not mobsf_debug_cert_present
}



# SECM-CAT-IPC-001
violation contains "SECM-CAT-IPC-001" if {
  not compliant_no_exported_components
}

# SECM-CAT-IPC-002
violation contains "SECM-CAT-IPC-002" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IPC-003
violation contains "SECM-CAT-IPC-003" if {
  not compliant_no_exported_components
}

# SECM-CAT-IPC-004
violation contains "SECM-CAT-IPC-004" if {
  not compliant_no_exported_components
}

# SECM-CAT-IPC-005
violation contains "SECM-CAT-IPC-005" if {
  not compliant_no_exported_components
}

# SECM-CAT-IPC-006
violation contains "SECM-CAT-IPC-006" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IPC-007
violation contains "SECM-CAT-IPC-007" if {
  not compliant_no_exported_components
}

# SECM-CAT-IPC-008
violation contains "SECM-CAT-IPC-008" if {
  not compliant_no_exported_components
}

# SECM-CAT-IPC-009
violation contains "SECM-CAT-IPC-009" if {
  not compliant_no_exported_components
}

# SECM-CAT-IPC-010
violation contains "SECM-CAT-IPC-010" if {
  not compliant_no_exported_components
}

# SECM-CAT-IPC-011
violation contains "SECM-CAT-IPC-011" if {
  not compliant_no_exported_components
}

# SECM-CAT-IPC-012
violation contains "SECM-CAT-IPC-012" if {
  not compliant_no_exported_components
}

# SECM-CAT-IPC-013
violation contains "SECM-CAT-IPC-013" if {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IPC-014
violation contains "SECM-CAT-IPC-014" if {
  not compliant_no_exported_components
}

# SECM-CAT-IPC-015
violation contains "SECM-CAT-IPC-015" if {
  not compliant_no_exported_components
}

# SECM-CAT-IPC-016
violation contains "SECM-CAT-IPC-016" if {
  not compliant_no_exported_components
}

# SECM-CAT-IPC-017
violation contains "SECM-CAT-IPC-017" if {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IPC-018
violation contains "SECM-CAT-IPC-018" if {
  not compliant_no_exported_components
}

# SECM-CAT-IPC-019
violation contains "SECM-CAT-IPC-019" if {
  not compliant_no_exported_components
}

# SECM-CAT-IPC-020
violation contains "SECM-CAT-IPC-020" if {
  not compliant_no_exported_components
}

# SECM-CAT-IPC-021
violation contains "SECM-CAT-IPC-021" if {
  not compliant_no_exported_components
}

# SECM-CAT-IPC-022
violation contains "SECM-CAT-IPC-022" if {
  not compliant_no_exported_components
}

# SECM-CAT-IPC-023
violation contains "SECM-CAT-IPC-023" if {
  not compliant_no_exported_components
}

# SECM-CAT-IPC-024
violation contains "SECM-CAT-IPC-024" if {
  not compliant_no_exported_components
}

# SECM-CAT-IPC-025
violation contains "SECM-CAT-IPC-025" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IPC-026
violation contains "SECM-CAT-IPC-026" if {
  not compliant_not_debuggable
}

# SECM-CAT-IPC-027
violation contains "SECM-CAT-IPC-027" if {
  not compliant_no_exported_components
}

# SECM-CAT-IPC-028
violation contains "SECM-CAT-IPC-028" if {
  not compliant_no_exported_components
}

# SECM-CAT-IPC-029
violation contains "SECM-CAT-IPC-029" if {
  not compliant_no_high_vulns
}

# SECM-CAT-IPC-030
violation contains "SECM-CAT-IPC-030" if {
  not compliant_no_exported_components
}

# SECM-CAT-IPC-031
violation contains "SECM-CAT-IPC-031" if {
  not compliant_no_exported_components
}

# SECM-CAT-IPC-032
violation contains "SECM-CAT-IPC-032" if {
  not compliant_no_exported_components
}

# SECM-CAT-IPC-033
violation contains "SECM-CAT-IPC-033" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IPC-034
violation contains "SECM-CAT-IPC-034" if {
  not compliant_no_exported_components
}

# SECM-CAT-IPC-035
violation contains "SECM-CAT-IPC-035" if {
  not compliant_no_exported_components
}

# SECM-CAT-IPC-036
violation contains "SECM-CAT-IPC-036" if {
  not compliant_no_exported_components
}

# SECM-CAT-IPC-037
violation contains "SECM-CAT-IPC-037" if {
  not compliant_no_exported_components
}

# SECM-CAT-IPC-038
violation contains "SECM-CAT-IPC-038" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IPC-039
violation contains "SECM-CAT-IPC-039" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IPC-040
violation contains "SECM-CAT-IPC-040" if {
  not compliant_no_exported_components
}

# SECM-CAT-IPC-041
violation contains "SECM-CAT-IPC-041" if {
  not compliant_no_exported_components
}

# SECM-CAT-IPC-042
violation contains "SECM-CAT-IPC-042" if {
  not compliant_no_exported_components
}



# END