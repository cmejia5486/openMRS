package secmcat.ibp

import data.requirements.requisitos as requirements

# Política genérica: marca como violación IBP cualquier requisito cuyo PUID
# no figure como compliant en input.compliance.
violation contains puid if {
    some i
    req := requirements[i]
    startswith(req.puid, "SECM-CAT-IBP-")
    not input.compliance[puid]
    puid := req.puid
}
