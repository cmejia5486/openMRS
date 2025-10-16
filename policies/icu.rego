package secmcat.icu

import data.requirements.requisitos as requirements

violation contains puid if {
  some i
  req := requirements[i]
  startswith(req.puid, "SECM-CAT-ICU-")
  not input.tls_enabled
  puid := req.puid
}
