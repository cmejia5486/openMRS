package secmcat.iov

import data.requirements.requisitos as requirements

violation contains puid if {
  some i
  req := requirements[i]
  puid := req.puid
  startswith(puid, "SECM-CAT-IOV-")
  not input.tls_enabled
}

violation contains puid if {
  some i
  req := requirements[i]
  puid := req.puid
  startswith(puid, "SECM-CAT-IOV-")
  count(input.container_scan_vulnerabilities) > 0
}

violation contains puid if {
  some i
  req := requirements[i]
  puid := req.puid
  startswith(puid, "SECM-CAT-IOV-")
  count(input.dependency_vulnerabilities) > 0
}