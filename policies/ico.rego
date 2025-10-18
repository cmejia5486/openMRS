package secmcat.ico

import data.requirements.requisitos as requirements

# Política genérica para la categoría ICO
violation contains puid if {
    some i
    req := requirements[i]
    startswith(req.puid, "SECM-CAT-ICO-")
    not input.compliance[puid]
    puid := req.puid
}
