package secmcat

import data.secmcat.isu001 as isu001

# Aggregate violations from multiple policies
violation[v] {
    v := isu001.violation[_]
}
