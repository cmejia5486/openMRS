#!/usr/bin/env python3
import json

# This is a placeholder script that simulates collection of data for compliance testing.
# Replace this with logic to gather real system configuration data.

data = {
    "last_rotation_days": {
        "api_key_1": 120,
        "api_key_2": 45
    }
}

with open('input.json', 'w') as f:
    json.dump(data, f, indent=2)
