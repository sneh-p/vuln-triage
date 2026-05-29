# agents/correlator/app.py
import os
import sys
import time
import logging

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from _lib.db import get_db_connection, execute_write

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] correlator: %(message)s")
logger = logging.getLogger("correlator")

ENV_MULTIPLIERS = {
    'prod': 1.5,
    'staging': 1.0,
    'dev': 0.5,
    'sandbox': 0.2
}

def calculate_priority_score(cvss_base, epss, in_kev, public_exploit, business_crit, environment):
    # priority_score = cvss_base * (1 + 2*epss) * (3 if in_kev else 1) * (2 if public_exploit else 1) * (business_crit/3) * env_multiplier
    multiplier = ENV_MULTIPLIERS.get(environment.lower(), 1.0)
    score = float(cvss_base)
    score *= (1.0 + 2.0 * float(epss or 0.0))
    score *= 3.0 if in_kev else 1.0
    score *= 2.0 if public_exploit else 1.0
    score *= (float(business_crit) / 3.0)
    score *= multiplier
    # Round to 2 decimal places
    return round(score, 2)

def run_once():
    logger.info("Starting correlation run...")
    try:
        with get_db_connection() as conn:
            # Query all findings with their assets and enrichment details
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
                LEFT JOIN triage t ON f.id = t.finding_id;
            """
            
            with conn.cursor() as cur:
                cur.execute(query)
                rows = cur.fetchall()
                
            logger.info(f"Loaded {len(rows)} findings for correlation.")
            
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
                
                # Compute score
                new_score = calculate_priority_score(
                    cvss_base, epss, in_kev, public_exploit, business_crit, environment
                )
                
                # Construct detailed rationale
                multiplier = ENV_MULTIPLIERS.get(environment.lower(), 1.0)
                rationale_parts = [
                    f"CVSS: {cvss_base}",
                    f"EPSS: {float(epss or 0.0):.4f}",
                    f"KEV: {in_kev}",
                    f"Exploit: {public_exploit}",
                    f"Env: {environment} (mult: {multiplier})",
                    f"Crit: {business_crit}/3"
                ]
                rationale = " | ".join(rationale_parts)
                
                logger.info(f"Upserting triage record for finding_id {finding_id} ({cve}) with score {new_score}")
                insert_query = """
                    INSERT INTO triage (finding_id, status, priority_score, rationale, updated_at)
                    VALUES (%s, 'pending', %s, %s, NOW())
                    ON CONFLICT (finding_id) DO UPDATE 
                    SET priority_score = EXCLUDED.priority_score,
                        rationale = EXCLUDED.rationale,
                        updated_at = NOW();
                """
                with conn:
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
        logger.error(f"Error during correlation run: {e}")

if __name__ == "__main__":
    logger.info("Correlator agent started.")
    if len(sys.argv) > 1 and sys.argv[1] == "--once":
        logger.info("Running a single correlation pass.")
        run_once()
        sys.exit(0)

    while True:
        try:
            run_once()
        except Exception as e:
            logger.error(f"Error in correlator loop: {e}")
        time.sleep(15)
