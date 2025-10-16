package secmcat.isu001

# Example policy for SECM-CAT-ISU-001

# input.last_rotation_days is a map of secret names to days since last rotation
violation contains puid if {
  some k
  puid := "SECM-CAT-ISU-001"
  secret := input.last_rotation_days[k]
  secret > 90
}

