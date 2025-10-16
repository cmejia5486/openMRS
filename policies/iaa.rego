package secmcat.iaa

import data.requirements.requisitos as requirements

violation contains puid if {
  some i
  req := requirements[i]
  startswith(req.puid, "SECM-CAT-IAA-")
  not input.users["admin"]
  puid := req.puid
}

