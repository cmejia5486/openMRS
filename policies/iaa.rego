package secmcat.iaa

# Policy for SECM‑CAT‑IAA requirements
# This rule iterates over each requirement in data.requirements and
# triggers a violation for all IAA requirements when there is no admin user.

import data.requirements

violation[puid] {
    req := requirements[_]
    startswith(req.puid, "SECM-CAT-IAA-")
    not input.users["admin"]
    puid := req.puid
}
