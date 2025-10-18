package secmcat.iov

import data.requirements.requisitos as requirements

# Política genérica para la categoría IOV
violation contains puid if {
    some i
    req := requirements[i]
    startswith(req.puid, "SECM-CAT-IOV-")
    not input.compliance[puid]
    puid := req.puid
}
