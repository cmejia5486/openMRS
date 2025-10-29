#!/usr/bin/env python3
"""
Script to collect security compliance data for OPA evaluation.

This script reads the SECM‑CAT requirements catalogue and a mapping of compliance
results (derived from manual audit or automated scans) to build an `input.json`
file consumed by the OPA policies.  The JSON structure includes a
`compliance` dictionary keyed by each requirement PUID, a map of days since
last secret rotation, TLS configuration flags, user roles counts, and lists
of vulnerabilities discovered during container and dependency scans.

If a `requirements/compliance_status.json` file is present, the boolean
values from that file will be used; otherwise all requirements default to
compliant (`True`).  Optionally, this script will parse Trivy results from
`trivy_results.json` and dependency vulnerability results from
`dependency_results.json` to populate the vulnerability lists.
"""

import json
import os
from typing import Dict, List, Any


def load_requirements(path: str) -> List[Dict[str, Any]]:
    """Load the requirements catalogue from a JSON file."""
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def load_compliance_mapping(path: str) -> Dict[str, bool]:
    """Load a compliance mapping from a JSON file if it exists."""
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                # ensure boolean values
                return {k: bool(v) for k, v in data.items()}
        except Exception:
            return {}
    return {}


def parse_trivy_results(path: str) -> List[Dict[str, Any]]:
    """Parse a Trivy JSON results file into a list of vulnerability entries.

    Each entry is a dict with at least `id` and `severity` keys.  This
    function is resilient to changes in the Trivy output format.
    """
    vulnerabilities: List[Dict[str, Any]] = []
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            # Trivy results JSON has a `Results` array with objects containing
            # `Vulnerabilities` arrays.
            for result in data.get('Results', []):
                for vuln in result.get('Vulnerabilities', []) or []:
                    vulnerabilities.append({
                        'id': vuln.get('VulnerabilityID'),
                        'severity': vuln.get('Severity')
                    })
        except Exception:
            # If parsing fails, return empty list
            pass
    return vulnerabilities


def parse_dependency_results(path: str) -> List[Dict[str, Any]]:
    """Parse dependency vulnerability results into a list.

    The expected format is a JSON object with a `vulnerabilities` field that
    contains a list of objects describing package vulnerabilities.  If the
    structure differs, this function returns an empty list.
    """
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            vulns = data.get('vulnerabilities', [])
            if isinstance(vulns, list):
                return vulns
        except Exception:
            pass
    return []


def parse_mobsf_results(path: str) -> List[Dict[str, Any]]:
    """Parse a MobSF JSON report into a list of vulnerability entries.

    The MobSF report structure can vary depending on the scan configuration,
    but typically it contains nested dictionaries and lists with findings that
    include `title` and `severity` fields.  This function traverses the
    report recursively, extracting any objects that contain those keys.

    Args:
        path: Path to the MobSF JSON report file.

    Returns:
        A list of dictionaries with at least `title` and `severity` keys.
    """
    vulnerabilities: List[Dict[str, Any]] = []
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            def extract_items(obj: Any) -> None:
                if isinstance(obj, dict):
                    # If the object has both title and severity, record it as a vulnerability
                    if 'title' in obj and 'severity' in obj:
                        vulnerabilities.append({'title': obj['title'], 'severity': obj['severity']})
                    # Recurse into dictionary values
                    for v in obj.values():
                        extract_items(v)
                elif isinstance(obj, list):
                    for item in obj:
                        extract_items(item)

            extract_items(data)
        except Exception:
            # Parsing failure results in an empty list
            pass
    return vulnerabilities


def main() -> None:
    """Main entry point for the data collection script."""
    # Paths relative to repository root
    requirements_path = os.path.join('requirements', 'requisitos.json')
    compliance_path = os.path.join('requirements', 'compliance_status.json')
    trivy_results_path = 'trivy_results.json'
    dependency_results_path = 'dependency_results.json'
    mobsf_results_path = 'mobsf_results.json'

    requirements = load_requirements(requirements_path)
    compliance_mapping = load_compliance_mapping(compliance_path)

    compliance: Dict[str, bool] = {}
    for req in requirements:
        puid = req.get('PUID')
        # Default to True (compliant) unless mapping says otherwise
        compliance[puid] = compliance_mapping.get(puid, True)

    # Example placeholders for rotation days, TLS and user roles
    # In a real environment these should be gathered from configuration
    # management systems, secrets managers or environment variables.
    last_rotation_days = {
        'api_key_1': 120,
        'api_key_2': 30
    }
    tls_enabled = False  # Should reflect real deployment settings
    users = {
        'admin': 1,
        'viewer': 5
    }

    # Parse vulnerability reports if they exist
    container_vulns = parse_trivy_results(trivy_results_path)
    dependency_vulns = parse_dependency_results(dependency_results_path)
    mobsf_vulns = parse_mobsf_results(mobsf_results_path)

    data = {
        'compliance': compliance,
        'last_rotation_days': last_rotation_days,
        'tls_enabled': tls_enabled,
        'users': users,
        'container_scan_vulnerabilities': container_vulns,
        'dependency_vulnerabilities': dependency_vulns
        ,
        'mobsf_vulnerabilities': mobsf_vulns
    }

    # Write the input file for OPA
    with open('input.json', 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)


if __name__ == '__main__':
    main()
