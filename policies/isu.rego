package secmcat.isu

import data.requirements

violation[puid] {
    some req
    puid := requirements[req].puid
    startswith(puid, "SECM-CAT-ISU-")
    input.tls_enabled == false
}

violation[puid] {
    some req
    puid := requirements[req].puid
    startswith(puid, "SECM-CAT-ISU-")
    count(input.container_scan_vulnerabilities) > 0
}

violation[puid] {
    some req
    puid := requirements[req].puid
    startswith(puid, "SECM-CAT-ISU-")
    count(input.dependency_vulnerabilities) > 0
}
