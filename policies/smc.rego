package secmcat.smc

import data.requirements.requisitos as requirements

# Política genérica para la categoría SMC (Security Management & Compliance)
violation contains puid if {
  some i
  req := requirements[i]
  puid := req.puid
  startswith(puid, "SECM-CAT-SMC-")
  not input.tls_enabled
}

violation contains puid if {
  some i
  req := requirements[i]
  puid := req.puid
  startswith(puid, "SECM-CAT-SMC-")
  count(input.container_scan_vulnerabilities) > 0
}

violation contains puid if {
  some i
  req := requirements[i]
  puid := req.puid
  startswith(puid, "SECM-CAT-SMC-")
  count(input.dependency_vulnerabilities) > 0
}