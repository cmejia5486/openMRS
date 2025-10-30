package secmcat.ids



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
  s in {"HIGH", "CRITICAL"}
}

# ---- Dependency scanner (generic) ----
dependency_findings := getp(getp(input, "dependency", {}), "findings", [])
has_dependency_high_or_critical {
  some i
  f := dependency_findings[i]
  s := upper(getp(f, "severity", ""))
  s in {"HIGH", "CRITICAL"}
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
  sev in {"HIGH", "CRITICAL"}
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
  true in {tls, good_pinning}
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



# SECM-CAT-IDS-001
violation["SECM-CAT-IDS-001"] {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IDS-002
violation["SECM-CAT-IDS-002"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-003
violation["SECM-CAT-IDS-003"] {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IDS-004
violation["SECM-CAT-IDS-004"] {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IDS-005
violation["SECM-CAT-IDS-005"] {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IDS-006
violation["SECM-CAT-IDS-006"] {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IDS-007
violation["SECM-CAT-IDS-007"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-008
violation["SECM-CAT-IDS-008"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-009
violation["SECM-CAT-IDS-009"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-010
violation["SECM-CAT-IDS-010"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-011
violation["SECM-CAT-IDS-011"] {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IDS-012
violation["SECM-CAT-IDS-012"] {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IDS-013
violation["SECM-CAT-IDS-013"] {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IDS-014
violation["SECM-CAT-IDS-014"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-015
violation["SECM-CAT-IDS-015"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-016
violation["SECM-CAT-IDS-016"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-017
violation["SECM-CAT-IDS-017"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-018
violation["SECM-CAT-IDS-018"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-019
violation["SECM-CAT-IDS-019"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-020
violation["SECM-CAT-IDS-020"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-021
violation["SECM-CAT-IDS-021"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-022
violation["SECM-CAT-IDS-022"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-023
violation["SECM-CAT-IDS-023"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-024
violation["SECM-CAT-IDS-024"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-025
violation["SECM-CAT-IDS-025"] {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IDS-026
violation["SECM-CAT-IDS-026"] {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IDS-027
violation["SECM-CAT-IDS-027"] {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IDS-028
violation["SECM-CAT-IDS-028"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-029
violation["SECM-CAT-IDS-029"] {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IDS-030
violation["SECM-CAT-IDS-030"] {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IDS-031
violation["SECM-CAT-IDS-031"] {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IDS-032
violation["SECM-CAT-IDS-032"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-033
violation["SECM-CAT-IDS-033"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-034
violation["SECM-CAT-IDS-034"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-035
violation["SECM-CAT-IDS-035"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-036
violation["SECM-CAT-IDS-036"] {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IDS-037
violation["SECM-CAT-IDS-037"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-038
violation["SECM-CAT-IDS-038"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-039
violation["SECM-CAT-IDS-039"] {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IDS-040
violation["SECM-CAT-IDS-040"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-041
violation["SECM-CAT-IDS-041"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-042
violation["SECM-CAT-IDS-042"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-043
violation["SECM-CAT-IDS-043"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-044
violation["SECM-CAT-IDS-044"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-045
violation["SECM-CAT-IDS-045"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-046
violation["SECM-CAT-IDS-046"] {
  not compliant_no_allow_backup
}

# SECM-CAT-IDS-047
violation["SECM-CAT-IDS-047"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-048
violation["SECM-CAT-IDS-048"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IDS-049
violation["SECM-CAT-IDS-049"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-050
violation["SECM-CAT-IDS-050"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-051
violation["SECM-CAT-IDS-051"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-052
violation["SECM-CAT-IDS-052"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-053
violation["SECM-CAT-IDS-053"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-054
violation["SECM-CAT-IDS-054"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-055
violation["SECM-CAT-IDS-055"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-056
violation["SECM-CAT-IDS-056"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-057
violation["SECM-CAT-IDS-057"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-058
violation["SECM-CAT-IDS-058"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-059
violation["SECM-CAT-IDS-059"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-060
violation["SECM-CAT-IDS-060"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-061
violation["SECM-CAT-IDS-061"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-062
violation["SECM-CAT-IDS-062"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-063
violation["SECM-CAT-IDS-063"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-064
violation["SECM-CAT-IDS-064"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-065
violation["SECM-CAT-IDS-065"] {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IDS-066
violation["SECM-CAT-IDS-066"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-067
violation["SECM-CAT-IDS-067"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-068
violation["SECM-CAT-IDS-068"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-069
violation["SECM-CAT-IDS-069"] {
  not compliant_no_exported_components
}

# SECM-CAT-IDS-070
violation["SECM-CAT-IDS-070"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-071
violation["SECM-CAT-IDS-071"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-072
violation["SECM-CAT-IDS-072"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-073
violation["SECM-CAT-IDS-073"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IDS-074
violation["SECM-CAT-IDS-074"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-075
violation["SECM-CAT-IDS-075"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IDS-076
violation["SECM-CAT-IDS-076"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IDS-077
violation["SECM-CAT-IDS-077"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IDS-078
violation["SECM-CAT-IDS-078"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-079
violation["SECM-CAT-IDS-079"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-080
violation["SECM-CAT-IDS-080"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-081
violation["SECM-CAT-IDS-081"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-082
violation["SECM-CAT-IDS-082"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-083
violation["SECM-CAT-IDS-083"] {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-084
violation["SECM-CAT-IDS-084"] {
  not compliant_no_allow_backup
}



# END