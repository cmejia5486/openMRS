package secmcat.ids

import data.requirements.requisitos as requirements

# Política genérica para la categoría IDS
violation contains puid if {
    some i
    req := requirements[i]
    startswith(req.puid, "SECM-CAT-IDS-")
    not input.compliance[puid]
    puid := req.puid
}
