package secmcat

# Agrega las violaciones de cada módulo individual

import data.secmcat.isu001 as isu001
import data.secmcat.icu   as icu
import data.secmcat.isu   as isu
import data.secmcat.iaa   as iaa
import data.secmcat.ibp   as ibp
import data.secmcat.ico   as ico
import data.secmcat.icr   as icr
import data.secmcat.ids   as ids
import data.secmcat.iov   as iov
import data.secmcat.ipc   as ipc
import data.secmcat.smc   as smc

import data.requirements.requisitos as requirements

# Recolectar violaciones de cada módulo
violation contains v if {
  v := isu001.violation[_]
}
violation contains v if {
  v := icu.violation[_]
}
violation contains v if {
  v := iaa.violation[_]
}
violation contains v if {
  v := isu.violation[_]
}
violation contains v if {
  v := ibp.violation[_]
}
violation contains v if {
  v := ico.violation[_]
}
violation contains v if {
  v := icr.violation[_]
}
violation contains v if {
  v := ids.violation[_]
}
violation contains v if {
  v := iov.violation[_]
}
violation contains v if {
  v := ipc.violation[_]
}
violation contains v if {
  v := smc.violation[_]
}

# Comprobación genérica: cualquier requisito cuyo PUID no esté marcado
# como compliant en input.compliance se considera violación
violation contains puid if {
  some i
  puid := requirements[i].puid
  not input.compliance[puid]
}
