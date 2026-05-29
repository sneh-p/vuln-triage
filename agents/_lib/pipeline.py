# agents/_lib/pipeline.py
import json
import logging
import requests
from datetime import datetime, timedelta
from _lib.db import execute_write

logger = logging.getLogger("pipeline_lib")

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"

ENV_MULTIPLIERS = {
    'prod': 1.5,
    'staging': 1.0,
    'dev': 0.5,
    'sandbox': 0.2
}

# Simple cached feed
_kev_cache = set()
_kev_cache_expiry = None

def fetch_cisa_kev_feed():
    global _kev_cache, _kev_cache_expiry
    now = datetime.now()
    if _kev_cache_expiry is not None and now < _kev_cache_expiry:
        return _kev_cache
        
    try:
        r = requests.get(CISA_KEV_URL, timeout=10)
        if r.ok:
            data = r.json()
            vulns = data.get("vulnerabilities", [])
            _kev_cache = {v["cveID"].strip().upper() for v in vulns if "cveID" in v}
            _kev_cache_expiry = now + timedelta(hours=6)
    except Exception as e:
        logger.error(f"Error fetching KEV feed in pipeline: {e}")
    return _kev_cache

def fetch_epss_score(cve):
    try:
        r = requests.get(f"{EPSS_API_URL}?cve={cve}", timeout=5)
        if r.ok:
            data = r.json()
            results = data.get("data", [])
            if results:
                return float(results[0].get("epss", 0.0))
    except Exception as e:
        logger.error(f"Error fetching EPSS for {cve} in pipeline: {e}")
    return 0.0

def check_exploitdb_mock(cve):
    known_exploits = {"CVE-2021-44228", "CVE-2017-0144", "CVE-2023-38831"}
    if cve in known_exploits:
        return True
    try:
        parts = cve.split('-')
        if len(parts) >= 3:
            num = int(parts[-1])
            return num % 10 == 7
    except ValueError:
        pass
    return False

def enrich_batch(conn, finding_ids):
    """Enriches CVEs associated with the given finding_ids."""
    if not finding_ids:
        return
        
    # Get distinct CVEs from findings
    cves = []
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT DISTINCT cve 
                FROM findings 
                WHERE id = ANY(%s) AND cve IS NOT NULL AND cve != '';
            """, (finding_ids,))
            cves = [row[0] for row in cur.fetchall()]
    except Exception as e:
        logger.error(f"Failed to query CVEs for batch enrichment: {e}")
        return
        
    if not cves:
        return
        
    kev_set = fetch_cisa_kev_feed()
    
    for cve in cves:
        epss = fetch_epss_score(cve)
        
        # Fallback to CSV EPSS if API lookup returned 0.0 (or failed)
        if epss == 0.0:
            try:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT (raw->>'epss_csv')::numeric 
                        FROM findings 
                        WHERE cve = %s AND raw->>'epss_csv' IS NOT NULL 
                        LIMIT 1;
                    """, (cve,))
                    row = cur.fetchone()
                    if row and row[0] is not None:
                        epss = float(row[0])
                        logger.info(f"Fallback to CSV-provided EPSS for {cve}: {epss}")
            except Exception as e:
                logger.error(f"Failed to check CSV EPSS fallback for {cve}: {e}")

        in_kev = cve in kev_set
        public_exploit = check_exploitdb_mock(cve)
        
        query = """
            INSERT INTO enrichment (cve, epss, in_kev, public_exploit, last_enriched_at)
            VALUES (%s, %s, %s, %s, NOW())
            ON CONFLICT (cve)
            DO UPDATE SET epss = EXCLUDED.epss, in_kev = EXCLUDED.in_kev, 
                          public_exploit = EXCLUDED.public_exploit, last_enriched_at = EXCLUDED.last_enriched_at;
        """
        
        try:
            execute_write(
                conn,
                action="enrich_cve",
                target_type="enrichment",
                target_id=cve,
                details={
                    "epss": epss,
                    "in_kev": in_kev,
                    "public_exploit": public_exploit,
                    "source": "batch_upload"
                },
                write_query=query,
                write_params=(cve, epss, in_kev, public_exploit)
            )
        except Exception as e:
            logger.error(f"Failed to insert enrichment for {cve} in batch: {e}")

def correlate_batch(conn, finding_ids):
    """Calculates risk score and upserts triage records for given finding_ids."""
    if not finding_ids:
        return
        
    query = """
        SELECT 
            f.id AS finding_id,
            f.cve,
            f.cvss_base,
            a.environment,
            a.business_crit,
            COALESCE(e.epss, 0.0) as epss,
            COALESCE(e.in_kev, FALSE) as in_kev,
            COALESCE(e.public_exploit, FALSE) as public_exploit,
            t.id AS triage_id,
            t.priority_score AS existing_score,
            t.status AS existing_status
        FROM findings f
        JOIN assets a ON f.asset_id = a.id
        LEFT JOIN enrichment e ON f.cve = e.cve
        LEFT JOIN triage t ON f.id = t.finding_id
        WHERE f.id = ANY(%s);
    """
    
    try:
        with conn.cursor() as cur:
            cur.execute(query, (finding_ids,))
            rows = cur.fetchall()
            
        for row in rows:
            finding_id = row[0]
            cve = row[1]
            cvss_base = row[2]
            environment = row[3]
            business_crit = row[4]
            epss = row[5]
            in_kev = row[6]
            public_exploit = row[7]
            triage_id = row[8]
            existing_score = row[9]
            existing_status = row[10]
            
            # Score formula
            multiplier = ENV_MULTIPLIERS.get(environment.lower(), 1.0)
            score = float(cvss_base)
            score *= (1.0 + 2.0 * float(epss))
            score *= 3.0 if in_kev else 1.0
            score *= 2.0 if public_exploit else 1.0
            score *= (float(business_crit) / 3.0)
            score *= multiplier
            new_score = round(score, 2)
            
            # Construct detailed rationale
            rationale_parts = [
                f"CVSS: {cvss_base}",
                f"EPSS: {float(epss):.4f}",
                f"KEV: {in_kev}",
                f"Exploit: {public_exploit}",
                f"Env: {environment} (mult: {multiplier})",
                f"Crit: {business_crit}/3"
            ]
            rationale = " | ".join(rationale_parts)
            
            insert_query = """
                INSERT INTO triage (finding_id, status, priority_score, rationale, updated_at)
                VALUES (%s, 'pending', %s, %s, NOW())
                ON CONFLICT (finding_id) DO UPDATE 
                SET priority_score = EXCLUDED.priority_score,
                    rationale = EXCLUDED.rationale,
                    updated_at = NOW();
            """
            execute_write(
                conn,
                action="upsert_triage",
                target_type="triage",
                target_id=finding_id,
                details={
                    "cve": cve,
                    "priority_score": new_score,
                    "status": "pending",
                    "rationale": rationale
                },
                write_query=insert_query,
                write_params=(finding_id, new_score, rationale)
            )
    except Exception as e:
        logger.error(f"Failed to correlate batch: {e}")
