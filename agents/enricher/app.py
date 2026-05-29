# agents/enricher/app.py
import os
import sys
import time
import logging
import requests
from datetime import datetime, timedelta

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from _lib.db import get_db_connection, execute_write

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] enricher: %(message)s")
logger = logging.getLogger("enricher")

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"

# In-memory cache for CISA KEV feed to avoid downloading for every single CVE
kev_cache = set()
kev_cache_expiry = None

def fetch_cisa_kev_feed():
    global kev_cache, kev_cache_expiry
    now = datetime.now()
    if kev_cache_expiry is not None and now < kev_cache_expiry:
        return kev_cache
        
    logger.info("Fetching CISA KEV feed...")
    try:
        r = requests.get(CISA_KEV_URL, timeout=15)
        if r.ok:
            data = r.json()
            vulns = data.get("vulnerabilities", [])
            new_cache = {v["cveID"].strip().upper() for v in vulns if "cveID" in v}
            logger.info(f"Loaded {len(new_cache)} KEV CVEs from CISA.")
            kev_cache = new_cache
            kev_cache_expiry = now + timedelta(hours=12) # Cache KEV feed for 12 hours
        else:
            logger.warning(f"Failed to fetch CISA KEV feed: HTTP {r.status_code}. Using existing cache if available.")
    except Exception as e:
        logger.error(f"Error fetching CISA KEV feed: {e}")
        
    return kev_cache

def fetch_epss_score(cve):
    logger.info(f"Fetching EPSS for {cve}...")
    try:
        r = requests.get(f"{EPSS_API_URL}?cve={cve}", timeout=10)
        if r.ok:
            data = r.json()
            results = data.get("data", [])
            if results:
                epss_val = float(results[0].get("epss", 0.0))
                logger.info(f"Found EPSS for {cve}: {epss_val}")
                return epss_val
    except Exception as e:
        logger.error(f"Error fetching EPSS for {cve}: {e}")
    return 0.0

def check_exploitdb_mock(cve):
    # Simulated ExploitDB check (using deterministic hash and explicit list of known exploit CVEs)
    known_exploits = {"CVE-2021-44228", "CVE-2017-0144", "CVE-2023-38831"}
    # Consistent mock behavior: check set, otherwise check if last digit of CVE number is 7
    if cve in known_exploits:
        return True
    try:
        # e.g. CVE-2023-1237 -> 1237
        parts = cve.split('-')
        if len(parts) >= 3:
            num = int(parts[-1])
            return num % 10 == 7
    except ValueError:
        pass
    return False

def enrich_cve(cve, kev_set):
    epss = fetch_epss_score(cve)
    in_kev = cve in kev_set
    public_exploit = check_exploitdb_mock(cve)
    
    logger.info(f"CVE: {cve} | EPSS: {epss} | KEV: {in_kev} | Public Exploit: {public_exploit}")
    
    query = """
        INSERT INTO enrichment (cve, epss, in_kev, public_exploit, last_enriched_at)
        VALUES (%s, %s, %s, %s, NOW())
        ON CONFLICT (cve)
        DO UPDATE SET epss = EXCLUDED.epss, in_kev = EXCLUDED.in_kev, 
                      public_exploit = EXCLUDED.public_exploit, last_enriched_at = EXCLUDED.last_enriched_at;
    """
    
    try:
        with get_db_connection() as conn:
            with conn:
                execute_write(
                    conn,
                    action="enrich_cve",
                    target_type="enrichment",
                    target_id=cve,
                    details={
                        "epss": epss,
                        "in_kev": in_kev,
                        "public_exploit": public_exploit
                    },
                    write_query=query,
                    write_params=(cve, epss, in_kev, public_exploit)
                )
        return True
    except Exception as e:
        logger.error(f"Failed to save enrichment for {cve}: {e}")
        return False

def run_once():
    # Load CISA KEV feed
    kev_set = fetch_cisa_kev_feed()
    
    # Query CVEs from findings table that need enrichment
    cves_to_enrich = []
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # Select distinct CVEs that either have no entry in enrichment, 
                # or the existing entry is older than 24h.
                cur.execute("""
                    SELECT DISTINCT f.cve 
                    FROM findings f
                    LEFT JOIN enrichment e ON f.cve = e.cve
                    WHERE e.cve IS NULL OR e.last_enriched_at < NOW() - INTERVAL '24 hours';
                """)
                cves_to_enrich = [row[0] for row in cur.fetchall()]
    except Exception as e:
        logger.error(f"Error querying CVEs for enrichment: {e}")
        return
        
    if not cves_to_enrich:
        logger.info("No CVEs require enrichment at this time.")
        return

    logger.info(f"Found {len(cves_to_enrich)} CVEs to enrich.")
    for cve in cves_to_enrich:
        enrich_cve(cve, kev_set)
        # Avoid hammering APIs
        time.sleep(0.5)

if __name__ == "__main__":
    logger.info("Enricher agent started.")
    if len(sys.argv) > 1 and sys.argv[1] == "--once":
        logger.info("Running a single enrichment pass.")
        run_once()
        sys.exit(0)

    while True:
        try:
            run_once()
        except Exception as e:
            logger.error(f"Error in enricher loop: {e}")
        time.sleep(60) # check for new findings every minute
