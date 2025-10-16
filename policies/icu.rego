package secmcat.icu

# Policy for SECM CAT ICU requirements
# This rule iterates over each requirement in data.requirements and
# triggers a violation for all ICU requirements when TLS is not enabled.

import data.requirements

violation[puid] {
    req := requirements[_]
    startswith(req.puid, "SECM-CAT-ICU-")
    not input.tls_enabled
    puid := req.puid
}
