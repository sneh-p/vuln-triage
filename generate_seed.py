# generate_seed.py
import random
from datetime import datetime, timedelta

environments = ['prod', 'staging', 'dev', 'sandbox']
business_crits = [1, 2, 3]

# Create 20 assets
assets = []
for i in range(1, 21):
    env = environments[(i - 1) % len(environments)]
    crit = business_crits[(i - 1) % len(business_crits)]
    assets.append({
        'id': i,
        'name': f"asset-{i:02d}",
        'environment': env,
        'business_crit': crit
    })

# 15 CVEs (include 2 KEV and 1 public exploit CVE)
# CVE-2023-38831: KEV + public exploit (via our set check)
# CVE-2023-23397: KEV
# CVE-2021-44228: public exploit
# 12 other CVEs
cves = [
    {"cve": "CVE-2023-38831", "title": "RAR Labs WinRAR Remote Code Execution", "cvss": 7.8, "severity": "High"},
    {"cve": "CVE-2023-23397", "title": "Microsoft Outlook Elevation of Privilege", "cvss": 9.8, "severity": "Critical"},
    {"cve": "CVE-2021-44228", "title": "Apache Log4j Remote Code Execution", "cvss": 10.0, "severity": "Critical"},
    {"cve": "CVE-2023-0001", "title": "Linux Kernel Local Privilege Escalation", "cvss": 5.5, "severity": "Medium"},
    {"cve": "CVE-2023-0002", "title": "Nginx Denial of Service", "cvss": 4.3, "severity": "Medium"},
    {"cve": "CVE-2023-0003", "title": "OpenSSL Buffer Overflow", "cvss": 8.1, "severity": "High"},
    {"cve": "CVE-2023-0004", "title": "PostgreSQL SQL Injection", "cvss": 8.8, "severity": "High"},
    {"cve": "CVE-2023-0005", "title": "Git Remote Code Execution", "cvss": 9.8, "severity": "Critical"},
    {"cve": "CVE-2023-0006", "title": "Node.js HTTP Server Crash", "cvss": 7.5, "severity": "High"},
    {"cve": "CVE-2023-0007", "title": "Kubernetes API Privilege Escalation", "cvss": 8.8, "severity": "High"},
    {"cve": "CVE-2023-0008", "title": "Docker Desktop Privilege Escalation", "cvss": 7.0, "severity": "High"},
    {"cve": "CVE-2023-0009", "title": "Redis Remote Code Execution", "cvss": 9.8, "severity": "Critical"},
    {"cve": "CVE-2023-0010", "title": "Jenkins Remote Code Execution", "cvss": 8.8, "severity": "High"},
    {"cve": "CVE-2023-0011", "title": "Tomcat Remote Code Execution", "cvss": 8.5, "severity": "High"},
    {"cve": "CVE-2023-0012", "title": "Curl Buffer Overflow", "cvss": 7.5, "severity": "High"}
]

# Generate 50 findings
findings = []
used_pairs = set()

# Ensure we have at least one finding for each of the 15 CVEs
for i, cve_info in enumerate(cves):
    asset_id = (i % 20) + 1
    used_pairs.add((asset_id, cve_info['cve']))
    findings.append({
        'asset_id': asset_id,
        'cve': cve_info['cve'],
        'title': cve_info['title'],
        'description': f"Vulnerability {cve_info['cve']} detected on asset-{asset_id:02d}.",
        'cvss_base': cve_info['cvss'],
        'severity': cve_info['severity']
    })

# Add 35 more findings randomly
random.seed(42)
while len(findings) < 50:
    asset_id = random.randint(1, 20)
    cve_info = random.choice(cves)
    pair = (asset_id, cve_info['cve'])
    if pair not in used_pairs:
        used_pairs.add(pair)
        findings.append({
            'asset_id': asset_id,
            'cve': cve_info['cve'],
            'title': cve_info['title'],
            'description': f"Vulnerability {cve_info['cve']} detected on asset-{asset_id:02d}.",
            'cvss_base': cve_info['cvss'],
            'severity': cve_info['severity']
        })

# Write seed.sql
with open("seed.sql", "w") as f:
    f.write("-- Seed Assets\n")
    for asset in assets:
        f.write(f"INSERT INTO assets (id, name, environment, business_crit) VALUES ({asset['id']}, '{asset['name']}', '{asset['environment']}', {asset['business_crit']}) ON CONFLICT (name) DO UPDATE SET environment=EXCLUDED.environment, business_crit=EXCLUDED.business_crit;\n")
        
    f.write("\n-- Seed Findings\n")
    base_date = datetime.now() - timedelta(days=5)
    for i, finding in enumerate(findings):
        det_date = (base_date + timedelta(hours=i*2)).strftime('%Y-%m-%d %H:%M:%S')
        desc = finding['description'].replace("'", "''")
        f.write(f"INSERT INTO findings (asset_id, cve, title, description, cvss_base, severity, detected_at) VALUES ({finding['asset_id']}, '{finding['cve']}', '{finding['title']}', '{desc}', {finding['cvss_base']}, '{finding['severity']}', '{det_date}') ON CONFLICT (asset_id, cve) DO NOTHING;\n")

print(f"Generated seed.sql with 20 assets and {len(findings)} findings.")
