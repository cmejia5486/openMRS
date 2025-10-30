package secmcat

import rego.v1

# Agregador: junta todas las violaciones de los submódulos.

violation contains v if {
  v := data.secmcat.iaa.violation[_]
}

violation contains v if {
  v := data.secmcat.ibp.violation[_]
}

violation contains v if {
  v := data.secmcat.ico.violation[_]
}

violation contains v if {
  v := data.secmcat.icr.violation[_]
}

violation contains v if {
  v := data.secmcat.icu.violation[_]
}

violation contains v if {
  v := data.secmcat.ids.violation[_]
}

violation contains v if {
  v := data.secmcat.iov.violation[_]
}

violation contains v if {
  v := data.secmcat.ipc.violation[_]
}

violation contains v if {
  v := data.secmcat.isu.violation[_]
}
