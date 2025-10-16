#!/usr/bin/env python3
import json

"""
This script simulates collection of data for compliance testing. In a real
implementation, you would replace this with code that inspects your
infrastructure, configuration files, secrets management system and other
sources to generate inputs for the OPA policies. The keys used here
correspond to the example policies defined in the `policies` directory.

- `last_rotation_days`: maps secret names to the number of days since
  their last rotation.
- `tls_enabled`: indicates whether TLS is enabled in your environment.
- `users`: maps usernames to a boolean indicating whether the user has
  administrative privileges.
"""

data = {
    "last_rotation_days": {
        "api_key_1": 120,
        "api_key_2": 45
    },
    # Set TLS to false to demonstrate a violation for ICU requirements.
    "tls_enabled": False,
    # Define some users; ensure at least one admin user exists.
    "users": {
        "admin": True,
        "editor": True,
        "viewer": False
    }
}

with open('input.json', 'w') as f:
    json.dump(data, f, indent=2)
