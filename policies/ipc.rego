package secmcat.ipc

import data.requirements.requisitos as requirements

# Política genérica para la categoría IPC
violation contains puid if {
    some i
    req := requirements[i]
    startswith(req.puid, "SECM-CAT-IPC-")
    not input.compliance[puid]
    puid := req.puid
}
