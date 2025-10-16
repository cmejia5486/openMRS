import json
import os

def parse_mobsf_results(path):
    vulns = []
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        def extract(obj):
            if isinstance(obj, dict):
                if 'title' in obj and 'severity' in obj:
                    vulns.append({'title': obj['title'], 'severity': obj['severity']})
                for v in obj.values():
                    extract(v)
            elif isinstance(obj, list):
                for item in obj:
                    extract(item)
        extract(data)
    return vulns

def main():
    # carga requisitos y compliance mapping, por ejemplo desde compliance_status.json…
    compliance = {...}  # tu lógica actual de compliance
    last_rotation_days = {'api_key_1': 120, 'api_key_2': 30}
    tls_enabled = False
    users = {'admin': 1, 'viewer': 5}
    container_vulns = [...]  # parseo de Trivy
    dependency_vulns = [...]  # parseo de dependencias
    mobsf_vulns = parse_mobsf_results('mobsf_results.json')

    data = {
        'compliance': compliance,
        'last_rotation_days': last_rotation_days,
        'tls_enabled': tls_enabled,
        'users': users,
        'container_scan_vulnerabilities': container_vulns,
        'dependency_vulnerabilities': dependency_vulns,
        'mobsf_vulnerabilities': mobsf_vulns,
    }
    with open('input.json', 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

if __name__ == '__main__':
    main()
