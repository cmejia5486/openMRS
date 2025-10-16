package secmcat

# Aggregate violations from individual policy modules

import data.secmcat.isu001 as isu001
import data.secmcat.isu as isu

import data.secmcat.icu as icu
import data.secmcat.iaa as iaa

violation[v] {
    v := isu001.violation[_]
}

violation[v] {
    v := icu.violation[_]
}

violation[v] {
    v := iaa.violation[_]
}

violation[v] {
    v := isu.violation[_]
}
