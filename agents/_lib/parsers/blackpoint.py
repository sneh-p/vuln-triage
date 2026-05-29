# agents/_lib/parsers/blackpoint.py
import csv
from datetime import datetime

def parse_date(date_str):
    if not date_str or date_str.strip() == "":
        return None
    date_str_clean = date_str.strip()
    for fmt in ('%Y-%m-%dT%H:%M:%S%z', '%Y-%m-%dT%H:%M:%S.%f%z', '%Y-%m-%d %H:%M:%S', '%Y-%m-%d'):
        try:
            return datetime.strptime(date_str_clean, fmt)
        except ValueError:
            pass
    try:
        return datetime.fromisoformat(date_str_clean.replace('Z', '+00:00'))
    except Exception:
        return None

def parse(file_obj):
    """
    Parses a Blackpoint CSV file stream and yields normalized findings dicts.
    Only parses findings containing a valid CVE identifier.
    """
    reader = csv.DictReader(file_obj)
    
    for row in reader:
        cve_id = row.get("CVE ID", "").strip()
        if not cve_id or not cve_id.upper().startswith("CVE-"):
            continue
            
        asset_hostname = row.get("Asset Hostname", "").strip()
        asset_name = row.get("Asset Name", "").strip()
        
        hostname = asset_hostname if asset_hostname else asset_name
        if not hostname:
            continue
            
        # Determine IP (first if comma separated)
        ip_field = row.get("Asset IP Addresses", "").strip()
        ip = None
        if ip_field:
            ip = ip_field.split(",")[0].strip()
            
        cve = cve_id.upper()
        
        # CVSS base
        cvss_str = row.get("CVSS Base Score", "").strip()
        cvss_base = 0.0
        if cvss_str:
            try:
                cvss_base = float(cvss_str)
            except ValueError:
                pass
                
        # Exploited in the Wild != 'Unreported'
        exploited = row.get("Exploited in the Wild", "").strip()
        public_exploit = True if (exploited and exploited.lower() != "unreported") else None
        
        # Dates
        first_seen = parse_date(row.get("First Seen", ""))
        last_seen = parse_date(row.get("Last Seen", ""))
        if not last_seen:
            last_seen = datetime.now()
            
        # Description and Remediation
        description = row.get("Description", "").strip()
        remediation = row.get("Remediation", "").strip()
        
        # Build raw dict
        raw = {
            "application_name": row.get("Application Name", ""),
            "application_family": row.get("Application Family", ""),
            "blackpoint_priority_score": row.get("Blackpoint Priority Score", ""),
            "severity": row.get("Severity", ""),
            "description": description,
            "status": row.get("Status", "")
        }
        
        yield {
            "asset_hostname": hostname,
            "ip": ip,
            "cve": cve,
            "plugin_id": cve_id, # plugin_id = CVE ID
            "cvss_base": cvss_base,
            "cvss_vector": row.get("CVSS Base Vector", None),
            "title": row.get("CVE Name", cve_id),
            "scanner": "blackpoint",
            "first_seen": first_seen,
            "last_seen": last_seen,
            "public_exploit": public_exploit,
            "vendor_advisory": remediation if remediation else None,
            "raw": raw
        }
