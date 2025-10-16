#!/usr/bin/env python3
import json
import os

"""
Data collection script for SECM-CAT compliance testing.

This script reads the security requirements from `requirements/requisitos.json`
and generates a placeholder compliance dictionary with an entry for every PUID.
In a real implementation you would compute a boolean for each PUID based on
actual scans and configuration inspections.

Additionally, this script collects illustrative data used by our example OPA
policies (last_rotation_days, tls_enabled, users, container and dependency
vulnerabilities) and writes them together with the compliance dictionary to
`input.json`.

"""

def load_requirements(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def build_compliance_dict(requirements):
    # Initialize all requirements as not compliant (False).
    compliance = {}
    for req in requirements:
        puid = req.get('puid')
        compliance[puid] = False
    return compliance

def main():
    # Determine the path to the requirements file relative to this script.
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    reqs_path = os.path.join(repo_root, 'requirements', 'requisitos.json')
    requirements = load_requirements(reqs_path)
    compliance = build_compliance_dict(requirements)

    data = {
        "compliance": compliance,
        "last_rotation_days": {
            "api_key_1": 120,
            "api_key_2": 45
        },
        "tls_enabled": False,
        "users": {
            "admin": True,
            "editor": True,
            "viewer": False
        },
        # Example container scan vulnerabilities
        "container_scan_vulnerabilities": [
            {"id": "CVE-2023-0001", "severity": "HIGH"},
            {"id": "CVE-2023-0002", "severity": "LOW"}
        ],
        # Example dependency scan vulnerabilities
        "dependency_vulnerabilities": [
            {"package": "libssl", "severity": "CRITICAL"},
            {"package": "libxyz", "severity": "MEDIUM"}
        ]
    }

    with open('input.json', 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

if __name__ == "__main__":
    main()
