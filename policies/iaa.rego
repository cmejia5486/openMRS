package secmcat.iaa

import data.requirements.requisitos as requirements

violation contains puid if {
  some i
  req := requirements[i]
  puid := req.puid
  startswith(puid, "SECM-CAT-IAA-")
  not input.tls_enabled
}

violation contains puid if {
  some i
  req := requirements[i]
  puid := req.puid
  startswith(puid, "SECM-CAT-IAA-")
  count(input.container_scan_vulnerabilities) > 0
}

violation contains puid if {
  some i
  req := requirements[i]
  puid := req.puid
  startswith(puid, "SECM-CAT-IAA-")
  count(input.dependency_vulnerabilities) > 0
}

