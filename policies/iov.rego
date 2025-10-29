package secmcat.iov



# Auto-generated helpers (safe getters and detectors)

# Safe getters
get(obj, key, default) = out {
  some v
  v := object.get(obj, key, default)
  out := v
}

# ---- Trivy (agent payload shape) ----
trivy_findings := get(get(input, "trivy", {}), "findings", [])
has_trivy_high_or_critical {
  some i
  f := trivy_findings[i]
  s := upper(get(f, "severity", ""))
  s == "HIGH" or s == "CRITICAL"
}

# ---- Dependency scanner (generic) ----
dependency_findings := get(get(input, "dependency", {}), "findings", [])
has_dependency_high_or_critical {
  some i
  f := dependency_findings[i]
  s := upper(get(f, "severity", ""))
  s == "HIGH" or s == "CRITICAL"
}

# ---- CodeQL/SARIF (optional) ----
codeql := get(input, "codeql", {})
codeql_has_high_or_critical {
  some i
  run := get(codeql, "runs", [])[i]
  res := get(run, "results", [])
  some j
  r := res[j]
  sev := upper(get(get(r, "properties", {}), "securitySeverity", get(r, "severity", "")))
  sev == "HIGH" or sev == "CRITICAL"
}

# ---- MobSF ----
mobsf := get(input, "mobsf", {})
mobsf_manifest_findings := get(get(mobsf, "manifest_analysis", {}), "manifest_findings", [])
mobsf_code_map := get(get(mobsf, "code_analysis", {}), "findings", {})

mobsf_manifest_has(rule_name) {
  some i
  f := mobsf_manifest_findings[i]
  get(f, "rule", "") == rule_name
}

mobsf_manifest_has_sev(rule_name, min_sev) {
  some i
  f := mobsf_manifest_findings[i]
  get(f, "rule", "") == rule_name
  sev := upper(get(f, "severity", ""))
  wanted := {"CRITICAL":4,"HIGH":3,"WARNING":2,"INFO":1}
  wanted[sev] >= wanted[upper(min_sev)]
}

mobsf_code_has(key) {
  v := get(mobsf_code_map, key, null)
  v != null
}

# Certificate debug check (MobSF summary)
mobsf_debug_cert_present {
  summary := get(get(mobsf, "certificate_analysis", {}), "certificate_summary", {})
  high := get(summary, "high", 0)
  high > 0
}

# Specific common compliance predicates (true == compliant)

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
  tls := get(input, "tls_enabled", false)
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



# SECM-CAT-IOV-001
violation["SECM-CAT-IOV-001"] {
  not compliant_no_high_vulns
}

# SECM-CAT-IOV-002
violation["SECM-CAT-IOV-002"] {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IOV-003
violation["SECM-CAT-IOV-003"] {
  not compliant_no_high_vulns
}

# SECM-CAT-IOV-004
violation["SECM-CAT-IOV-004"] {
  not compliant_no_raw_sql
}

# SECM-CAT-IOV-005
violation["SECM-CAT-IOV-005"] {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IOV-006
violation["SECM-CAT-IOV-006"] {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IOV-007
violation["SECM-CAT-IOV-007"] {
  not compliant_no_high_vulns
}

# SECM-CAT-IOV-008
violation["SECM-CAT-IOV-008"] {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IOV-009
violation["SECM-CAT-IOV-009"] {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IOV-010
violation["SECM-CAT-IOV-010"] {
  not compliant_no_high_vulns
}

# SECM-CAT-IOV-011
violation["SECM-CAT-IOV-011"] {
  not compliant_no_high_vulns
}

# SECM-CAT-IOV-012
violation["SECM-CAT-IOV-012"] {
  not compliant_no_high_vulns
}

# SECM-CAT-IOV-013
violation["SECM-CAT-IOV-013"] {
  not compliant_no_high_vulns
}

# SECM-CAT-IOV-014
violation["SECM-CAT-IOV-014"] {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IOV-015
violation["SECM-CAT-IOV-015"] {
  not compliant_no_raw_sql
}

# SECM-CAT-IOV-016
violation["SECM-CAT-IOV-016"] {
  not compliant_no_raw_sql
}

# SECM-CAT-IOV-017
violation["SECM-CAT-IOV-017"] {
  not compliant_no_external_storage
}

# SECM-CAT-IOV-018
violation["SECM-CAT-IOV-018"] {
  not compliant_no_raw_sql
}

# SECM-CAT-IOV-019
violation["SECM-CAT-IOV-019"] {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IOV-020
violation["SECM-CAT-IOV-020"] {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IOV-021
violation["SECM-CAT-IOV-021"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IOV-022
violation["SECM-CAT-IOV-022"] {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IOV-023
violation["SECM-CAT-IOV-023"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IOV-024
violation["SECM-CAT-IOV-024"] {
  not compliant_no_clipboard_sensitive
}

# SECM-CAT-IOV-025
violation["SECM-CAT-IOV-025"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IOV-026
violation["SECM-CAT-IOV-026"] {
  not compliant_no_sensitive_logging
}



# END