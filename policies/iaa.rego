package secmcat.iaa



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



# SECM-CAT-IAA-001
violation["SECM-CAT-IAA-001"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-002
violation["SECM-CAT-IAA-002"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-003
violation["SECM-CAT-IAA-003"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-004
violation["SECM-CAT-IAA-004"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-005
violation["SECM-CAT-IAA-005"] {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IAA-006
violation["SECM-CAT-IAA-006"] {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IAA-007
violation["SECM-CAT-IAA-007"] {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IAA-008
violation["SECM-CAT-IAA-008"] {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IAA-009
violation["SECM-CAT-IAA-009"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-010
violation["SECM-CAT-IAA-010"] {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IAA-011
violation["SECM-CAT-IAA-011"] {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IAA-012
violation["SECM-CAT-IAA-012"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-013
violation["SECM-CAT-IAA-013"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-014
violation["SECM-CAT-IAA-014"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-015
violation["SECM-CAT-IAA-015"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-016
violation["SECM-CAT-IAA-016"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-017
violation["SECM-CAT-IAA-017"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-018
violation["SECM-CAT-IAA-018"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-019
violation["SECM-CAT-IAA-019"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-020
violation["SECM-CAT-IAA-020"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-021
violation["SECM-CAT-IAA-021"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-022
violation["SECM-CAT-IAA-022"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-023
violation["SECM-CAT-IAA-023"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-024
violation["SECM-CAT-IAA-024"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-025
violation["SECM-CAT-IAA-025"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-026
violation["SECM-CAT-IAA-026"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-027
violation["SECM-CAT-IAA-027"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-028
violation["SECM-CAT-IAA-028"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-029
violation["SECM-CAT-IAA-029"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-030
violation["SECM-CAT-IAA-030"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-031
violation["SECM-CAT-IAA-031"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-032
violation["SECM-CAT-IAA-032"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-033
violation["SECM-CAT-IAA-033"] {
  not compliant_no_high_vulns
}

# SECM-CAT-IAA-034
violation["SECM-CAT-IAA-034"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-035
violation["SECM-CAT-IAA-035"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-036
violation["SECM-CAT-IAA-036"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-037
violation["SECM-CAT-IAA-037"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-038
violation["SECM-CAT-IAA-038"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-039
violation["SECM-CAT-IAA-039"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-040
violation["SECM-CAT-IAA-040"] {
  not compliant_secure_rng
}

# SECM-CAT-IAA-041
violation["SECM-CAT-IAA-041"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-042
violation["SECM-CAT-IAA-042"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-043
violation["SECM-CAT-IAA-043"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-044
violation["SECM-CAT-IAA-044"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-045
violation["SECM-CAT-IAA-045"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-046
violation["SECM-CAT-IAA-046"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-047
violation["SECM-CAT-IAA-047"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-048
violation["SECM-CAT-IAA-048"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-049
violation["SECM-CAT-IAA-049"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-050
violation["SECM-CAT-IAA-050"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-051
violation["SECM-CAT-IAA-051"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-052
violation["SECM-CAT-IAA-052"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-053
violation["SECM-CAT-IAA-053"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-054
violation["SECM-CAT-IAA-054"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-055
violation["SECM-CAT-IAA-055"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-056
violation["SECM-CAT-IAA-056"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-057
violation["SECM-CAT-IAA-057"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-058
violation["SECM-CAT-IAA-058"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-059
violation["SECM-CAT-IAA-059"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-060
violation["SECM-CAT-IAA-060"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-061
violation["SECM-CAT-IAA-061"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-062
violation["SECM-CAT-IAA-062"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-063
violation["SECM-CAT-IAA-063"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-064
violation["SECM-CAT-IAA-064"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-065
violation["SECM-CAT-IAA-065"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-066
violation["SECM-CAT-IAA-066"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-067
violation["SECM-CAT-IAA-067"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-068
violation["SECM-CAT-IAA-068"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-069
violation["SECM-CAT-IAA-069"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-070
violation["SECM-CAT-IAA-070"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-071
violation["SECM-CAT-IAA-071"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-072
violation["SECM-CAT-IAA-072"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-073
violation["SECM-CAT-IAA-073"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-074
violation["SECM-CAT-IAA-074"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-075
violation["SECM-CAT-IAA-075"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-076
violation["SECM-CAT-IAA-076"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-077
violation["SECM-CAT-IAA-077"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-078
violation["SECM-CAT-IAA-078"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-079
violation["SECM-CAT-IAA-079"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-080
violation["SECM-CAT-IAA-080"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-081
violation["SECM-CAT-IAA-081"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-082
violation["SECM-CAT-IAA-082"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-083
violation["SECM-CAT-IAA-083"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-084
violation["SECM-CAT-IAA-084"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-085
violation["SECM-CAT-IAA-085"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-086
violation["SECM-CAT-IAA-086"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-087
violation["SECM-CAT-IAA-087"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-088
violation["SECM-CAT-IAA-088"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-089
violation["SECM-CAT-IAA-089"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-090
violation["SECM-CAT-IAA-090"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-091
violation["SECM-CAT-IAA-091"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-092
violation["SECM-CAT-IAA-092"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-093
violation["SECM-CAT-IAA-093"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-094
violation["SECM-CAT-IAA-094"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-095
violation["SECM-CAT-IAA-095"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-096
violation["SECM-CAT-IAA-096"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-097
violation["SECM-CAT-IAA-097"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-098
violation["SECM-CAT-IAA-098"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-100
violation["SECM-CAT-IAA-100"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-101
violation["SECM-CAT-IAA-101"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-102
violation["SECM-CAT-IAA-102"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-103
violation["SECM-CAT-IAA-103"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-104
violation["SECM-CAT-IAA-104"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-105
violation["SECM-CAT-IAA-105"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-106
violation["SECM-CAT-IAA-106"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-107
violation["SECM-CAT-IAA-107"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-108
violation["SECM-CAT-IAA-108"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-109
violation["SECM-CAT-IAA-109"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-110
violation["SECM-CAT-IAA-110"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-111
violation["SECM-CAT-IAA-111"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-112
violation["SECM-CAT-IAA-112"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-113
violation["SECM-CAT-IAA-113"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-114
violation["SECM-CAT-IAA-114"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-115
violation["SECM-CAT-IAA-115"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-116
violation["SECM-CAT-IAA-116"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-117
violation["SECM-CAT-IAA-117"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-118
violation["SECM-CAT-IAA-118"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-119
violation["SECM-CAT-IAA-119"] {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-120
violation["SECM-CAT-IAA-120"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-121
violation["SECM-CAT-IAA-121"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-122
violation["SECM-CAT-IAA-122"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-123
violation["SECM-CAT-IAA-123"] {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-124
violation["SECM-CAT-IAA-124"] {
  not compliant_tls_or_pinning
}



# END