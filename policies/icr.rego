package secmcat.icr



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
  s == "HIGH" or s == "CRITICAL"
}

# ---- Dependency scanner (generic) ----
dependency_findings := getp(getp(input, "dependency", {}), "findings", [])
has_dependency_high_or_critical {
  some i
  f := dependency_findings[i]
  s := upper(getp(f, "severity", ""))
  s == "HIGH" or s == "CRITICAL"
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
  sev == "HIGH" or sev == "CRITICAL"
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



# SECM-CAT-ICR-001
violation["SECM-CAT-ICR-001"] {
  not compliant_no_weak_hashes
}

# SECM-CAT-ICR-002
violation["SECM-CAT-ICR-002"] {
  not compliant_no_weak_hashes
}

# SECM-CAT-ICR-003
violation["SECM-CAT-ICR-003"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-ICR-004
violation["SECM-CAT-ICR-004"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-ICR-005
violation["SECM-CAT-ICR-005"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-ICR-006
violation["SECM-CAT-ICR-006"] {
  not compliant_no_weak_hashes
}

# SECM-CAT-ICR-007
violation["SECM-CAT-ICR-007"] {
  not compliant_no_weak_hashes
}

# SECM-CAT-ICR-008
violation["SECM-CAT-ICR-008"] {
  not compliant_no_weak_hashes
}

# SECM-CAT-ICR-009
violation["SECM-CAT-ICR-009"] {
  not compliant_no_weak_hashes
}

# SECM-CAT-ICR-010
violation["SECM-CAT-ICR-010"] {
  not compliant_no_weak_hashes
}

# SECM-CAT-ICR-011
violation["SECM-CAT-ICR-011"] {
  not compliant_no_weak_hashes
}

# SECM-CAT-ICR-012
violation["SECM-CAT-ICR-012"] {
  not compliant_no_weak_hashes
}

# SECM-CAT-ICR-013
violation["SECM-CAT-ICR-013"] {
  not compliant_no_weak_hashes
}

# SECM-CAT-ICR-014
violation["SECM-CAT-ICR-014"] {
  not compliant_no_weak_hashes
}

# SECM-CAT-ICR-015
violation["SECM-CAT-ICR-015"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-ICR-016
violation["SECM-CAT-ICR-016"] {
  not compliant_no_weak_hashes
}

# SECM-CAT-ICR-017
violation["SECM-CAT-ICR-017"] {
  not compliant_no_weak_hashes
}

# SECM-CAT-ICR-018
violation["SECM-CAT-ICR-018"] {
  not compliant_no_weak_hashes
}

# SECM-CAT-ICR-019
violation["SECM-CAT-ICR-019"] {
  not compliant_no_weak_hashes
}

# SECM-CAT-ICR-020
violation["SECM-CAT-ICR-020"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-ICR-021
violation["SECM-CAT-ICR-021"] {
  not compliant_no_weak_hashes
}

# SECM-CAT-ICR-022
violation["SECM-CAT-ICR-022"] {
  not compliant_secure_rng
}

# SECM-CAT-ICR-023
violation["SECM-CAT-ICR-023"] {
  not compliant_secure_rng
}



# END