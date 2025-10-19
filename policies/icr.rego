package secmcat.icr

import data.requirements.requisitos as requirements

# Política genérica para la categoría ICR
violation contains puid if {
  some i
  req := requirements[i]
  puid := req.puid
  startswith(puid, "SECM-CAT-ICR-")
  not input.tls_enabled
}

violation contains puid if {
  some i
  req := requirements[i]
  puid := req.puid
  startswith(puid, "SECM-CAT-ICR-")
  count(input.container_scan_vulnerabilities) > 0
}

violation contains puid if {
  some i
  req := requirements[i]
  puid := req.puid
  startswith(puid, "SECM-CAT-ICR-")
  count(input.dependency_vulnerabilities) > 0
}