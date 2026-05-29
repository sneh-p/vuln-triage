# agents/ingestor/app.py
import os
import csv
import sys
import time
import glob
import shutil
import logging
import requests
from datetime import datetime

# Setup sys.path to import common library
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from _lib.db import get_db_connection, execute_write
from _lib.integrations import get_integration

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] ingestor: %(message)s")
logger = logging.getLogger("ingestor")

EXPORT_DIR = os.getenv("SCANNER_EXPORT_DIR", "/data/scanner-exports")
PROCESSED_DIR = os.path.join(EXPORT_DIR, "processed")

CAVELO_API_URL = os.getenv("CAVELO_API_URL", "https://api.cavelo.com")
CAVELO_API_TOKEN = os.getenv("CAVELO_API_TOKEN", "")

def ensure_directories():
    os.makedirs(EXPORT_DIR, exist_ok=True)
    os.makedirs(PROCESSED_DIR, exist_ok=True)

def get_severity_from_cvss(cvss):
    if cvss >= 9.0: return 'Critical'
    elif cvss >= 7.0: return 'High'
    elif cvss >= 4.0: return 'Medium'
    return 'Low'

def save_finding(conn, asset_name, environment, business_crit, cve, title, description, cvss_base, severity, detected_at, extra_details=None):
    """Saves a single asset and finding to the database with audit logs."""
    # 1. Upsert asset
    asset_query = """
        INSERT INTO assets (name, environment, business_crit)
        VALUES (%s, %s, %s)
        ON CONFLICT (name)
        DO UPDATE SET environment = COALESCE(assets.environment, EXCLUDED.environment),
                      business_crit = COALESCE(assets.business_crit, EXCLUDED.business_crit)
        RETURNING id;
    """
    execute_write(
        conn,
        action="upsert_asset",
        target_type="asset",
        target_id=asset_name,
        details={"environment": environment, "business_crit": business_crit},
        write_query=asset_query,
        write_params=(asset_name, environment, business_crit)
    )
    
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM assets WHERE name = %s", (asset_name,))
        asset_id = cur.fetchone()[0]
    
    # 2. Upsert finding
    finding_query = """
        INSERT INTO findings (asset_id, cve, title, description, cvss_base, severity, detected_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (asset_id, cve)
        DO UPDATE SET title = EXCLUDED.title, description = EXCLUDED.description,
                      cvss_base = EXCLUDED.cvss_base, severity = EXCLUDED.severity,
                      detected_at = EXCLUDED.detected_at;
    """
    audit_details = {
        "asset_id": asset_id,
        "cve": cve,
        "cvss_base": cvss_base,
        "severity": severity,
        "detected_at": str(detected_at)
    }
    if extra_details:
        audit_details.update(extra_details)
        
    execute_write(
        conn,
        action="upsert_finding",
        target_type="finding",
        target_id=f"{asset_id}:{cve}",
        details=audit_details,
        write_query=finding_query,
        write_params=(asset_id, cve, title, description, cvss_base, severity, detected_at)
    )

def run_cavelo_ingestion():
    logger.info("Starting Cavelo VM Ingestion...")
    
    integration = get_integration("cavelo")
    if not integration.get("enabled", False):
        logger.info("Cavelo integration is disabled. Skipping.")
        return
        
    config = integration.get("config") or {}
    secrets = integration.get("secrets") or {}
    
    api_url = config.get("api_url") or os.getenv("CAVELO_API_URL", "https://api.cavelo.com")
    api_token = secrets.get("api_token") or os.getenv("CAVELO_API_TOKEN", "")
    
    findings = []
    
    if not api_token:
        # LOG BANNER AS REQUIRED
        logger.info("*" * 50)
        logger.info("CAVELO stub mode — no real fetch")
        logger.info("*" * 50)
        
        # Mock Cavelo data fallback
        findings = [
            {
                "asset_hostname": "cavelo-asset-01",
                "ip": "192.168.1.150",
                "cve": "CVE-2023-38831",
                "plugin_id": "cav-101",
                "cvss_base": 7.8,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                "title": "RAR Labs WinRAR Remote Code Execution",
                "scanner": "cavelo"
            },
            {
                "asset_hostname": "cavelo-asset-02",
                "ip": "192.168.1.151",
                "cve": "CVE-2021-44228",
                "plugin_id": "cav-102",
                "cvss_base": 10.0,
                "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "title": "Apache Log4j Remote Code Execution",
                "scanner": "cavelo"
            }
        ]
    else:
        # Real API request
        try:
            url = f"{api_url}/api/v1/findings"
            logger.info(f"Fetching findings from real Cavelo endpoint: {url}")
            r = requests.get(url, headers={"Authorization": f"Bearer {api_token}"}, timeout=15)
            if r.ok:
                data = r.json()
                # Cavelo API returns a list under data or results
                results = data.get("data", data.get("results", []))
                for item in results:
                    findings.append({
                        "asset_hostname": item.get("asset_hostname", "unknown-cavelo-host"),
                        "ip": item.get("ip", "0.0.0.0"),
                        "cve": item.get("cve", "CVE-UNKNOWN").upper(),
                        "plugin_id": item.get("plugin_id", "cavelo-plugin"),
                        "cvss_base": float(item.get("cvss_base", 0.0)),
                        "cvss_vector": item.get("cvss_vector", ""),
                        "title": item.get("title", "Cavelo Detected Vulnerability"),
                        "scanner": "cavelo"
                    })
            else:
                logger.error(f"Failed to fetch from Cavelo API: HTTP {r.status_code} - {r.text}")
        except Exception as e:
            logger.error(f"Error fetching from Cavelo API: {e}")
            
    # Process findings
    if not findings:
        logger.info("No Cavelo findings found.")
        return
        
    try:
        with get_db_connection() as conn:
            for f in findings:
                # Normalize inputs
                hostname = f["asset_hostname"].strip()
                ip = f["ip"].strip()
                cve = f["cve"].strip().upper()
                title = f["title"].strip()
                cvss_base = f["cvss_base"]
                severity = get_severity_from_cvss(cvss_base)
                
                description = f"Cavelo VM Plugin {f['plugin_id']} - Vector: {f['cvss_vector']}"
                
                with conn:
                    save_finding(
                        conn, 
                        asset_name=hostname, 
                        environment="dev", # default Cavelo environment
                        business_crit=1, # default criticality
                        cve=cve, 
                        title=title, 
                        description=description, 
                        cvss_base=cvss_base, 
                        severity=severity, 
                        detected_at=datetime.now(),
                        extra_details={
                            "plugin_id": f["plugin_id"],
                            "cvss_vector": f["cvss_vector"],
                            "scanner": f["scanner"],
                            "ip": ip
                        }
                    )
            logger.info(f"Ingested {len(findings)} findings from Cavelo source.")
    except Exception as e:
        logger.error(f"Error during Cavelo database ingestion: {e}")

def process_csv_file(file_path):
    logger.info(f"Processing CSV file: {file_path}")
    success_count = 0
    error_count = 0
    
    with open(file_path, mode='r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        required_cols = {'asset_name', 'environment', 'business_crit', 'cve', 'title', 'cvss_base', 'severity', 'detected_at'}
        if not required_cols.issubset(set(reader.fieldnames or [])):
            logger.error(f"CSV file {file_path} is missing required columns.")
            return False

        try:
            with get_db_connection() as conn:
                for row in reader:
                    try:
                        asset_name = row['asset_name'].strip()
                        environment = row['environment'].strip().lower()
                        business_crit = int(row['business_crit'].strip())
                        cve = row['cve'].strip().upper()
                        title = row['title'].strip()
                        description = row.get('description', '').strip()
                        cvss_base = float(row['cvss_base'].strip())
                        severity = row['severity'].strip()
                        detected_at = row['detected_at'].strip()
                        
                        with conn:
                            save_finding(
                                conn, 
                                asset_name=asset_name, 
                                environment=environment, 
                                business_crit=business_crit, 
                                cve=cve, 
                                title=title, 
                                description=description, 
                                cvss_base=cvss_base, 
                                severity=severity, 
                                detected_at=detected_at,
                                extra_details={"scanner": "csv_fallback"}
                            )
                        success_count += 1
                    except Exception as row_error:
                        logger.error(f"Error processing CSV row: {row_error}")
                        error_count += 1
        except Exception as conn_error:
            logger.error(f"Database connection error during file processing: {conn_error}")
            return False

    logger.info(f"Finished CSV file {file_path}: {success_count} success, {error_count} errors")
    return True

def run_csv_ingestion():
    ensure_directories()
    csv_files = glob.glob(os.path.join(EXPORT_DIR, "*.csv"))
    if not csv_files:
        logger.info("No CSV files found in exports directory.")
        return
        
    for file_path in csv_files:
        if process_csv_file(file_path):
            dest = os.path.join(PROCESSED_DIR, os.path.basename(file_path))
            try:
                shutil.move(file_path, dest)
                logger.info(f"Moved processed file to {dest}")
            except Exception as e:
                logger.error(f"Failed to move file {file_path} to {dest}: {e}")

def run_once():
    """Runs ingestion check for both Cavelo API and CSV files"""
    run_cavelo_ingestion()
    run_csv_ingestion()

if __name__ == "__main__":
    logger.info("Ingestor agent started.")
    if len(sys.argv) > 1 and sys.argv[1] == "--once":
        logger.info("Running a single ingestion pass.")
        run_once()
        sys.exit(0)
        
    ensure_directories()
    while True:
        try:
            run_once()
        except Exception as e:
            logger.error(f"Error during ingestion loop: {e}")
        time.sleep(10)
