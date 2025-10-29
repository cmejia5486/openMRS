package secmcat.ibp



# Auto-generated helpers (safe getters and detectors)

# Safe getter
getp(obj, key, dflt) = out {
  out := object.get(obj, key, dflt)
}

# ---- Trivy (agent payload shape) ----
trivy_findings := getp(getp(input, "trivy", {}), "findings", [])
has_trivy_high_or_critical {
  some i
  f := trivy_findings[i]
  s := upper(getp(f, "severity", ""))
  {"HIGH", "CRITICAL"}[s]
}

# ---- Dependency scanner (generic) ----
dependency_findings := getp(getp(input, "dependency", {}), "findings", [])
has_dependency_high_or_critical {
  some i
  f := dependency_findings[i]
  s := upper(getp(f, "severity", ""))
  {"HIGH", "CRITICAL"}[s]
}

# ---- CodeQL/SARIF (opcional) ----
codeql := getp(input, "codeql", {})
codeql_has_high_or_critical {
  some i
  run := getp(getp(codeql, "runs", []), i, {})
  res := getp(run, "results", [])
  some j
  r := res[j]
  sev := upper(getp(getp(r, "properties", {}), "securitySeverity", getp(r, "severity", "")))
  {"HIGH", "CRITICAL"}[sev]
}

# ---- MobSF ----
mobsf := getp(input, "mobsf", {})
mobsf_manifest_findings := getp(getp(mobsf, "manifest_analysis", {}), "manifest_findings", [])
mobsf_code_map := getp(getp(mobsf, "code_analysis", {}), "findings", {})

mobsf_manifest_has(rule_name) {
  some i
  f := mobsf_manifest_findings[i]
  getp(f, "rule", "") == rule_name
}

mobsf_manifest_has_sev(rule_name, min_sev) {
  some i
  f := mobsf_manifest_findings[i]
  getp(f, "rule", "") == rule_name
  sev := upper(getp(f, "severity", ""))
  wanted := {"CRITICAL":4,"HIGH":3,"WARNING":2,"INFO":1}
  wanted[sev] >= wanted[upper(min_sev)]
}

mobsf_code_has(key) {
  v := getp(mobsf_code_map, key, null)
  v != null
}

# Certificate debug check (MobSF summary)
mobsf_debug_cert_present {
  summary := getp(getp(mobsf, "certificate_analysis", {}), "certificate_summary", {})
  high := getp(summary, "high", 0)
  high > 0
}

# --------- Predicados de cumplimiento (true == compliant) ---------

compliant_no_hardcoded_secrets {
  not mobsf_code_has("android_hardcoded")
}

compliant_not_debuggable {
  not mobsf_manifest_has_sev("app_is_debuggable", "high")
  not mobsf_code_has("android_aar_jar_debug_enabled")
}

compliant_no_allow_backup {
  not mobsf_manifest_has("app_allowbackup")
}

compliant_no_exported_components {
  not mobsf_manifest_has("exported_intent_filter_exists")
}

compliant_secure_min_sdk {
  not mobsf_manifest_has("vulnerable_os_version")
}

compliant_no_external_storage {
  not mobsf_code_has("android_read_write_external")
}

compliant_no_sensitive_logging {
  not mobsf_code_has("android_logging")
}

compliant_no_raw_sql {
  not mobsf_code_has("android_sql_raw_query")
}

compliant_no_weak_hashes {
  not mobsf_code_has("android_sha1")
}

compliant_secure_rng {
  not mobsf_code_has("android_insecure_random")
}

compliant_tls_or_pinning {
  tls := getp(input, "tls_enabled", false)
  good_pinning := mobsf_code_has("android_ssl_pinning")
  tls == true or good_pinning
}

compliant_no_high_vulns {
  not has_trivy_high_or_critical
  not has_dependency_high_or_critical
  not codeql_has_high_or_critical
}

compliant_no_clipboard_sensitive {
  not mobsf_code_has("android_clipboard_copy")
}

compliant_no_debug_certificate {
  not mobsf_debug_cert_present
}



# SECM-CAT-IBP-001
violation["SECM-CAT-IBP-001"] {
  not compliant_no_high_vulns
}

# SECM-CAT-IBP-002
violation["SECM-CAT-IBP-002"] {
  not compliant_not_debuggable
}

# SECM-CAT-IBP-003
violation["SECM-CAT-IBP-003"] {
  not compliant_not_debuggable
}

# SECM-CAT-IBP-004
violation["SECM-CAT-IBP-004"] {
  not compliant_not_debuggable
}

# SECM-CAT-IBP-005
violation["SECM-CAT-IBP-005"] {
  not compliant_no_high_vulns
}

# SECM-CAT-IBP-006
violation["SECM-CAT-IBP-006"] {
  not compliant_no_high_vulns
}

# SECM-CAT-IBP-007
violation["SECM-CAT-IBP-007"] {
  not compliant_not_debuggable
}

# SECM-CAT-IBP-008
violation["SECM-CAT-IBP-008"] {
  not compliant_no_high_vulns
}

# SECM-CAT-IBP-009
violation["SECM-CAT-IBP-009"] {
  not compliant_no_raw_sql
}

# SECM-CAT-IBP-010
violation["SECM-CAT-IBP-010"] {
  not compliant_no_raw_sql
}

# SECM-CAT-IBP-011
violation["SECM-CAT-IBP-011"] {
  not compliant_no_raw_sql
}

# SECM-CAT-IBP-012
violation["SECM-CAT-IBP-012"] {
  not compliant_no_high_vulns
}

# SECM-CAT-IBP-013
violation["SECM-CAT-IBP-013"] {
  not compliant_not_debuggable
}

# SECM-CAT-IBP-014
violation["SECM-CAT-IBP-014"] {
  not compliant_not_debuggable
}

# SECM-CAT-IBP-015
violation["SECM-CAT-IBP-015"] {
  not compliant_not_debuggable
}

# SECM-CAT-IBP-016
violation["SECM-CAT-IBP-016"] {
  not compliant_no_high_vulns
}

# SECM-CAT-IBP-017
violation["SECM-CAT-IBP-017"] {
  not compliant_not_debuggable
}

# SECM-CAT-IBP-018
violation["SECM-CAT-IBP-018"] {
  not compliant_no_high_vulns
}

# SECM-CAT-IBP-019
violation["SECM-CAT-IBP-019"] {
  not compliant_no_high_vulns
}

# SECM-CAT-IBP-020
violation["SECM-CAT-IBP-020"] {
  not compliant_no_high_vulns
}

# SECM-CAT-IBP-021
violation["SECM-CAT-IBP-021"] {
  not compliant_no_high_vulns
}

# SECM-CAT-IBP-022
violation["SECM-CAT-IBP-022"] {
  not compliant_no_high_vulns
}

# SECM-CAT-IBP-023
violation["SECM-CAT-IBP-023"] {
  not compliant_no_raw_sql
}

# SECM-CAT-IBP-024
violation["SECM-CAT-IBP-024"] {
  not compliant_not_debuggable
}

# SECM-CAT-IBP-025
violation["SECM-CAT-IBP-025"] {
  not compliant_no_external_storage
}

# SECM-CAT-IBP-026
violation["SECM-CAT-IBP-026"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IBP-027
violation["SECM-CAT-IBP-027"] {
  not compliant_no_high_vulns
}

# SECM-CAT-IBP-028
violation["SECM-CAT-IBP-028"] {
  not compliant_not_debuggable
}

# SECM-CAT-IBP-029
violation["SECM-CAT-IBP-029"] {
  not compliant_not_debuggable
}

# SECM-CAT-IBP-030
violation["SECM-CAT-IBP-030"] {
  not compliant_no_high_vulns
}

# SECM-CAT-IBP-031
violation["SECM-CAT-IBP-031"] {
  not compliant_not_debuggable
}

# SECM-CAT-IBP-032
violation["SECM-CAT-IBP-032"] {
  not compliant_not_debuggable
}

# SECM-CAT-IBP-033
violation["SECM-CAT-IBP-033"] {
  not compliant_not_debuggable
}

# SECM-CAT-IBP-034
violation["SECM-CAT-IBP-034"] {
  not compliant_not_debuggable
}



# END