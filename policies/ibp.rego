package secmcat.ibp

import data.requirements.requisitos as requirements

# Política genérica: marca como violación IBP cualquier requisito cuyo PUID
# no figure como compliant en input.compliance.
violation contains puid if {
  some i
  req := requirements[i]
  puid := req.puid
  startswith(puid, "SECM-CAT-IBP-")
  not input.tls_enabled
}

violation contains puid if {
  some i
  req := requirements[i]
  puid := req.puid
  startswith(puid, "SECM-CAT-IBP-")
  count(input.container_scan_vulnerabilities) > 0
}

violation contains puid if {
  some i
  req := requirements[i]
  puid := req.puid
  startswith(puid, "SECM-CAT-IBP-")
  count(input.dependency_vulnerabilities) > 0
}