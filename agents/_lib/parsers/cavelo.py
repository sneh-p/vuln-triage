# agents/_lib/parsers/cavelo.py
import re
import csv
from datetime import datetime

def parse(file_obj):
    """
    Parses a Cavelo CSV file stream and yields normalized findings dicts.
    Only parses findings containing a valid CVE identifier.
    """
    reader = csv.DictReader(file_obj)
    
    for row in reader:
        location = row.get("Location", "").strip()
        title = row.get("Title", "").strip()
        solution = row.get("Solution", "").strip()
        
        if not location or not title:
            continue
            
        # CVE extraction: regex r'CVE-\d{4}-\d{4,7}'
        cve_match = re.search(r'CVE-\d{4}-\d+', title, re.IGNORECASE)
        if not cve_match:
            continue
            
        cve = cve_match.group(0).upper()
        plugin_id = cve
        
        # Map location to asset_hostname (no IP available)
        asset_hostname = location
        ip = None
                
        # CVSS base: prefer v4 if >0 else v3 if >0 else v2
        def get_float(val):
            if not val:
                return 0.0
            try:
                return float(str(val).strip())
            except ValueError:
                return 0.0
                
        cvss_v4 = get_float(row.get("CVSS (v4)", ""))
        cvss_v3 = get_float(row.get("CVSS (v3)", ""))
        cvss_v2 = get_float(row.get("CVSS (v2)", ""))
        
        if cvss_v4 > 0.0:
            cvss_base = cvss_v4
        elif cvss_v3 > 0.0:
            cvss_base = cvss_v3
        else:
            cvss_base = cvss_v2
            
        # Parse EPSS
        epss_str = row.get("EPSS", "").strip()
        epss_csv_val = None
        if epss_str:
            try:
                if epss_str.endswith('%'):
                    epss_csv_val = float(epss_str.replace('%', '')) / 100.0
                else:
                    epss_csv_val = float(epss_str)
            except ValueError:
                pass
                
        raw = {
            "epss_csv": epss_csv_val,
            "affected_products": row.get("Affected Products", ""),
            "cvss_v2": cvss_v2,
            "cvss_v3": cvss_v3,
            "cvss_v4": cvss_v4
        }
        
        yield {
            "asset_hostname": asset_hostname,
            "ip": ip,
            "cve": cve,
            "plugin_id": plugin_id,
            "cvss_base": cvss_base,
            "cvss_vector": None,
            "title": title,
            "scanner": "cavelo",
            "first_seen": None,
            "last_seen": datetime.now(),
            "public_exploit": None,
            "vendor_advisory": solution if solution else None,
            "raw": raw
        }
