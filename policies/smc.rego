package secmcat.smc

import data.requirements.requisitos as requirements

# Política genérica para la categoría SMC (Security Management & Compliance)
violation contains puid if {
    some i
    req := requirements[i]
    startswith(req.puid, "SECM-CAT-SMC-")
    not input.compliance[puid]
    puid := req.puid
}
