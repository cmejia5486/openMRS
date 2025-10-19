package secmcat.ico

import data.requirements.requisitos as requirements

# Política genérica para la categoría ICO
violation contains puid if {
  some i
  req := requirements[i]
  puid := req.puid
  startswith(puid, "SECM-CAT-ICO-")
  not input.tls_enabled
}

violation contains puid if {
  some i
  req := requirements[i]
  puid := req.puid
  startswith(puid, "SECM-CAT-ICO-")
  count(input.container_scan_vulnerabilities) > 0
}

violation contains puid if {
  some i
  req := requirements[i]
  puid := req.puid
  startswith(puid, "SECM-CAT-ICO-")
  count(input.dependency_vulnerabilities) > 0
}
