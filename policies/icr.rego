package secmcat.icr

import data.requirements.requisitos as requirements

# Política genérica para la categoría ICR
violation contains puid if {
    some i
    req := requirements[i]
    startswith(req.puid, "SECM-CAT-ICR-")
    not input.compliance[puid]
    puid := req.puid
}
