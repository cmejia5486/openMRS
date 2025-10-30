package secmcat.iaa
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



# SECM-CAT-IAA-001
violation contains "SECM-CAT-IAA-001" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-002
violation contains "SECM-CAT-IAA-002" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-003
violation contains "SECM-CAT-IAA-003" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-004
violation contains "SECM-CAT-IAA-004" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-005
violation contains "SECM-CAT-IAA-005" if {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IAA-006
violation contains "SECM-CAT-IAA-006" if {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IAA-007
violation contains "SECM-CAT-IAA-007" if {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IAA-008
violation contains "SECM-CAT-IAA-008" if {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IAA-009
violation contains "SECM-CAT-IAA-009" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-010
violation contains "SECM-CAT-IAA-010" if {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IAA-011
violation contains "SECM-CAT-IAA-011" if {
  not compliant_no_sensitive_logging
}

# SECM-CAT-IAA-012
violation contains "SECM-CAT-IAA-012" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-013
violation contains "SECM-CAT-IAA-013" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-014
violation contains "SECM-CAT-IAA-014" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-015
violation contains "SECM-CAT-IAA-015" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-016
violation contains "SECM-CAT-IAA-016" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-017
violation contains "SECM-CAT-IAA-017" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-018
violation contains "SECM-CAT-IAA-018" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-019
violation contains "SECM-CAT-IAA-019" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-020
violation contains "SECM-CAT-IAA-020" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-021
violation contains "SECM-CAT-IAA-021" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-022
violation contains "SECM-CAT-IAA-022" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-023
violation contains "SECM-CAT-IAA-023" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-024
violation contains "SECM-CAT-IAA-024" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-025
violation contains "SECM-CAT-IAA-025" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-026
violation contains "SECM-CAT-IAA-026" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-027
violation contains "SECM-CAT-IAA-027" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-028
violation contains "SECM-CAT-IAA-028" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-029
violation contains "SECM-CAT-IAA-029" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-030
violation contains "SECM-CAT-IAA-030" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-031
violation contains "SECM-CAT-IAA-031" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-032
violation contains "SECM-CAT-IAA-032" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-033
violation contains "SECM-CAT-IAA-033" if {
  not compliant_no_high_vulns
}

# SECM-CAT-IAA-034
violation contains "SECM-CAT-IAA-034" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-035
violation contains "SECM-CAT-IAA-035" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-036
violation contains "SECM-CAT-IAA-036" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-037
violation contains "SECM-CAT-IAA-037" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-038
violation contains "SECM-CAT-IAA-038" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-039
violation contains "SECM-CAT-IAA-039" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-040
violation contains "SECM-CAT-IAA-040" if {
  not compliant_secure_rng
}

# SECM-CAT-IAA-041
violation contains "SECM-CAT-IAA-041" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-042
violation contains "SECM-CAT-IAA-042" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-043
violation contains "SECM-CAT-IAA-043" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-044
violation contains "SECM-CAT-IAA-044" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-045
violation contains "SECM-CAT-IAA-045" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-046
violation contains "SECM-CAT-IAA-046" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-047
violation contains "SECM-CAT-IAA-047" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-048
violation contains "SECM-CAT-IAA-048" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-049
violation contains "SECM-CAT-IAA-049" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-050
violation contains "SECM-CAT-IAA-050" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-051
violation contains "SECM-CAT-IAA-051" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-052
violation contains "SECM-CAT-IAA-052" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-053
violation contains "SECM-CAT-IAA-053" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-054
violation contains "SECM-CAT-IAA-054" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-055
violation contains "SECM-CAT-IAA-055" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-056
violation contains "SECM-CAT-IAA-056" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-057
violation contains "SECM-CAT-IAA-057" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-058
violation contains "SECM-CAT-IAA-058" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-059
violation contains "SECM-CAT-IAA-059" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-060
violation contains "SECM-CAT-IAA-060" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-061
violation contains "SECM-CAT-IAA-061" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-062
violation contains "SECM-CAT-IAA-062" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-063
violation contains "SECM-CAT-IAA-063" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-064
violation contains "SECM-CAT-IAA-064" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-065
violation contains "SECM-CAT-IAA-065" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-066
violation contains "SECM-CAT-IAA-066" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-067
violation contains "SECM-CAT-IAA-067" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-068
violation contains "SECM-CAT-IAA-068" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-069
violation contains "SECM-CAT-IAA-069" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-070
violation contains "SECM-CAT-IAA-070" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-071
violation contains "SECM-CAT-IAA-071" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-072
violation contains "SECM-CAT-IAA-072" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-073
violation contains "SECM-CAT-IAA-073" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-074
violation contains "SECM-CAT-IAA-074" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-075
violation contains "SECM-CAT-IAA-075" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-076
violation contains "SECM-CAT-IAA-076" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-077
violation contains "SECM-CAT-IAA-077" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-078
violation contains "SECM-CAT-IAA-078" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-079
violation contains "SECM-CAT-IAA-079" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-080
violation contains "SECM-CAT-IAA-080" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-081
violation contains "SECM-CAT-IAA-081" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-082
violation contains "SECM-CAT-IAA-082" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-083
violation contains "SECM-CAT-IAA-083" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-084
violation contains "SECM-CAT-IAA-084" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-085
violation contains "SECM-CAT-IAA-085" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-086
violation contains "SECM-CAT-IAA-086" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-087
violation contains "SECM-CAT-IAA-087" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-088
violation contains "SECM-CAT-IAA-088" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-089
violation contains "SECM-CAT-IAA-089" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-090
violation contains "SECM-CAT-IAA-090" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-091
violation contains "SECM-CAT-IAA-091" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-092
violation contains "SECM-CAT-IAA-092" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-093
violation contains "SECM-CAT-IAA-093" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-094
violation contains "SECM-CAT-IAA-094" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-095
violation contains "SECM-CAT-IAA-095" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-096
violation contains "SECM-CAT-IAA-096" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-097
violation contains "SECM-CAT-IAA-097" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-098
violation contains "SECM-CAT-IAA-098" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-100
violation contains "SECM-CAT-IAA-100" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-101
violation contains "SECM-CAT-IAA-101" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-102
violation contains "SECM-CAT-IAA-102" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-103
violation contains "SECM-CAT-IAA-103" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-104
violation contains "SECM-CAT-IAA-104" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-105
violation contains "SECM-CAT-IAA-105" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-106
violation contains "SECM-CAT-IAA-106" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-107
violation contains "SECM-CAT-IAA-107" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-108
violation contains "SECM-CAT-IAA-108" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-109
violation contains "SECM-CAT-IAA-109" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-110
violation contains "SECM-CAT-IAA-110" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-111
violation contains "SECM-CAT-IAA-111" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-112
violation contains "SECM-CAT-IAA-112" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-113
violation contains "SECM-CAT-IAA-113" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-114
violation contains "SECM-CAT-IAA-114" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-115
violation contains "SECM-CAT-IAA-115" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-116
violation contains "SECM-CAT-IAA-116" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-117
violation contains "SECM-CAT-IAA-117" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-118
violation contains "SECM-CAT-IAA-118" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-119
violation contains "SECM-CAT-IAA-119" if {
  not compliant_tls_or_pinning
}

# SECM-CAT-IAA-120
violation contains "SECM-CAT-IAA-120" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-121
violation contains "SECM-CAT-IAA-121" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-122
violation contains "SECM-CAT-IAA-122" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-123
violation contains "SECM-CAT-IAA-123" if {
  not compliant_no_hardcoded_secrets
}

# SECM-CAT-IAA-124
violation contains "SECM-CAT-IAA-124" if {
  not compliant_tls_or_pinning
}



# END