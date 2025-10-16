package secmcat

# Aggregate violations from individual policy modules

import data.secmcat.isu001 as isu001
import data.secmcat.icu as icu
import data.secmcat.isu as isu
import data.secmcat.iaa as iaa
import data.requirements.requisitos as requirements

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

# Generic compliance rule for all requirements

violation contains puid if {
  some i
  req := requirements[i]
  puid := req.puid
  not input.compliance[puid]
}
