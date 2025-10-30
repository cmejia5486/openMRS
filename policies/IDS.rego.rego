package secmcat.ids



# Auto-generated helpers (safe getters and detectors)

# Safe getter
getp(obj, key, dflt) = out if {
  out := object.get(obj, key, dflt)
}

# ---- Trivy (agent payload shape) ----
trivy_findings := getp(getp(input, "trivy", {}), "findings", [])
has_trivy_high_or_critical if {
  some i
  f := trivy_findings[i]
  s := upper(getp(f, "severity", ""))
  s == "HIGH" or s == "CRITICAL"
}

# ---- Dependency scanner (generic) ----
dependency_findings := getp(getp(input, "dependency", {}), "findings", [])
has_dependency_high_or_critical if {
  some i
  f := dependency_findings[i]
  s := upper(getp(f, "severity", ""))
  s == "HIGH" or s == "CRITICAL"
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
  sev == "HIGH" or sev == "CRITICAL"
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
  tls == true or good_pinning == true
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



# SECM-CAT-IDS-001
violation contains "SECM-CAT-IDS-001" if {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IDS-002
violation contains "SECM-CAT-IDS-002" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-003
violation contains "SECM-CAT-IDS-003" if {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IDS-004
violation contains "SECM-CAT-IDS-004" if {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IDS-005
violation contains "SECM-CAT-IDS-005" if {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IDS-006
violation contains "SECM-CAT-IDS-006" if {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IDS-007
violation contains "SECM-CAT-IDS-007" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-008
violation contains "SECM-CAT-IDS-008" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-009
violation contains "SECM-CAT-IDS-009" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-010
violation contains "SECM-CAT-IDS-010" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-011
violation contains "SECM-CAT-IDS-011" if {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IDS-012
violation contains "SECM-CAT-IDS-012" if {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IDS-013
violation contains "SECM-CAT-IDS-013" if {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IDS-014
violation contains "SECM-CAT-IDS-014" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-015
violation contains "SECM-CAT-IDS-015" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-016
violation contains "SECM-CAT-IDS-016" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-017
violation contains "SECM-CAT-IDS-017" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-018
violation contains "SECM-CAT-IDS-018" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-019
violation contains "SECM-CAT-IDS-019" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-020
violation contains "SECM-CAT-IDS-020" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-021
violation contains "SECM-CAT-IDS-021" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-022
violation contains "SECM-CAT-IDS-022" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-023
violation contains "SECM-CAT-IDS-023" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-024
violation contains "SECM-CAT-IDS-024" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-025
violation contains "SECM-CAT-IDS-025" if {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IDS-026
violation contains "SECM-CAT-IDS-026" if {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IDS-027
violation contains "SECM-CAT-IDS-027" if {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IDS-028
violation contains "SECM-CAT-IDS-028" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-029
violation contains "SECM-CAT-IDS-029" if {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IDS-030
violation contains "SECM-CAT-IDS-030" if {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IDS-031
violation contains "SECM-CAT-IDS-031" if {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IDS-032
violation contains "SECM-CAT-IDS-032" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-033
violation contains "SECM-CAT-IDS-033" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-034
violation contains "SECM-CAT-IDS-034" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-035
violation contains "SECM-CAT-IDS-035" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-036
violation contains "SECM-CAT-IDS-036" if {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IDS-037
violation contains "SECM-CAT-IDS-037" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-038
violation contains "SECM-CAT-IDS-038" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-039
violation contains "SECM-CAT-IDS-039" if {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IDS-040
violation contains "SECM-CAT-IDS-040" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-041
violation contains "SECM-CAT-IDS-041" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-042
violation contains "SECM-CAT-IDS-042" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-043
violation contains "SECM-CAT-IDS-043" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-044
violation contains "SECM-CAT-IDS-044" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-045
violation contains "SECM-CAT-IDS-045" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-046
violation contains "SECM-CAT-IDS-046" if {
  not compliant_no_allow_backup
}

# SECM-CAT-IDS-047
violation contains "SECM-CAT-IDS-047" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-048
violation contains "SECM-CAT-IDS-048" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IDS-049
violation contains "SECM-CAT-IDS-049" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-050
violation contains "SECM-CAT-IDS-050" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-051
violation contains "SECM-CAT-IDS-051" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-052
violation contains "SECM-CAT-IDS-052" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-053
violation contains "SECM-CAT-IDS-053" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-054
violation contains "SECM-CAT-IDS-054" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-055
violation contains "SECM-CAT-IDS-055" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-056
violation contains "SECM-CAT-IDS-056" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-057
violation contains "SECM-CAT-IDS-057" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-058
violation contains "SECM-CAT-IDS-058" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-059
violation contains "SECM-CAT-IDS-059" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-060
violation contains "SECM-CAT-IDS-060" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-061
violation contains "SECM-CAT-IDS-061" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-062
violation contains "SECM-CAT-IDS-062" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-063
violation contains "SECM-CAT-IDS-063" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-064
violation contains "SECM-CAT-IDS-064" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-065
violation contains "SECM-CAT-IDS-065" if {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IDS-066
violation contains "SECM-CAT-IDS-066" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-067
violation contains "SECM-CAT-IDS-067" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-068
violation contains "SECM-CAT-IDS-068" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-069
violation contains "SECM-CAT-IDS-069" if {
  not compliant_no_exported_components
}

# SECM-CAT-IDS-070
violation contains "SECM-CAT-IDS-070" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-071
violation contains "SECM-CAT-IDS-071" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-072
violation contains "SECM-CAT-IDS-072" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-073
violation contains "SECM-CAT-IDS-073" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IDS-074
violation contains "SECM-CAT-IDS-074" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-075
violation contains "SECM-CAT-IDS-075" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IDS-076
violation contains "SECM-CAT-IDS-076" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IDS-077
violation contains "SECM-CAT-IDS-077" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IDS-078
violation contains "SECM-CAT-IDS-078" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-079
violation contains "SECM-CAT-IDS-079" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-080
violation contains "SECM-CAT-IDS-080" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-081
violation contains "SECM-CAT-IDS-081" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-082
violation contains "SECM-CAT-IDS-082" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-083
violation contains "SECM-CAT-IDS-083" if {
  not compliant_no_external_storage
}

# SECM-CAT-IDS-084
violation contains "SECM-CAT-IDS-084" if {
  not compliant_no_allow_backup
}



# END