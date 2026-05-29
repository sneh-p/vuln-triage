# agents/ticketer/app.py
import os
import sys
import time
import json
import logging
import requests

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from _lib.db import get_db_connection, execute_write
from _lib.integrations import get_integration

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] ticketer: %(message)s")
logger = logging.getLogger("ticketer")

REQUIRE_HUMAN_APPROVAL = os.getenv("REQUIRE_HUMAN_APPROVAL", "true").lower() == "true"
MAX_TICKETS_PER_DAY = int(os.getenv("MAX_TICKETS_PER_DAY", "25"))

# Autotask Configurations
AUTOTASK_API_URL = os.getenv("AUTOTASK_API_URL", "https://webservices.autotask.net/atservicesrest/v1.0")
AUTOTASK_API_INTEGRATION_CODE = os.getenv("AUTOTASK_API_INTEGRATION_CODE", "")
AUTOTASK_USERNAME = os.getenv("AUTOTASK_USERNAME", "")
AUTOTASK_SECRET = os.getenv("AUTOTASK_SECRET", "")
AUTOTASK_QUEUE_ID = os.getenv("AUTOTASK_QUEUE_ID", "")
AUTOTASK_ACCOUNT_ID = os.getenv("AUTOTASK_ACCOUNT_ID", "")
AUTOTASK_DEFAULT_ASSIGNEE_RESOURCE_ID = os.getenv("AUTOTASK_DEFAULT_ASSIGNEE_RESOURCE_ID", "")

def get_recent_tickets_count():
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM tickets WHERE created_at >= NOW() - INTERVAL '24 hours';")
                return cur.fetchone()[0]
    except Exception as e:
        logger.error(f"Error checking recent ticket count: {e}")
        return 999

def open_autotask_ticket(cve, hostname, severity, in_kev, public_exploit, priority_score, finding_title, finding_description):
    integration = get_integration("autotask")
    config = integration.get("config") or {}
    secrets = integration.get("secrets") or {}
    
    api_url = config.get("api_url") or os.getenv("AUTOTASK_API_URL", "https://webservices.autotask.net/atservicesrest/v1.0")
    queue_id = config.get("queue_id") or os.getenv("AUTOTASK_QUEUE_ID", "")
    account_id = config.get("account_id") or os.getenv("AUTOTASK_ACCOUNT_ID", "")
    default_assignee_resource_id = config.get("default_assignee_resource_id") or os.getenv("AUTOTASK_DEFAULT_ASSIGNEE_RESOURCE_ID", "")
    
    api_integration_code = secrets.get("api_integration_code") or os.getenv("AUTOTASK_API_INTEGRATION_CODE", "")
    username = secrets.get("username") or os.getenv("AUTOTASK_USERNAME", "")
    secret = secrets.get("secret") or os.getenv("AUTOTASK_SECRET", "")

    # 1. Determine priority mapping
    # KEV + exploit -> 1 (Critical), score >= 8 -> 2 (High), else 3 (Medium)
    if in_kev and public_exploit:
        priority = 1
    elif priority_score >= 8.0:
        priority = 2
    else:
        priority = 3
        
    title = f"[{severity}] {cve} on {hostname}"
    
    rationale = f"Vulnerability {cve} ({finding_title}) detected on asset {hostname}.\nPriority Score: {priority_score}."
    remediation = f"Remediation: Patch system or check vendor advisory for {cve}.\nDescription: {finding_description}"
    description = f"RATIONALE:\n{rationale}\n\nREMEDIATION:\n{remediation}"
    
    payload = {
        "title": title,
        "description": description,
        "status": 1, # New
        "priority": priority,
        "queueID": int(queue_id) if queue_id else None,
        "companyID": int(account_id) if account_id else None,
        "assignedResourceID": int(default_assignee_resource_id) if default_assignee_resource_id else None
    }
    
    headers = {
        "ApiIntegrationCode": api_integration_code,
        "UserName": username,
        "Secret": secret,
        "Content-Type": "application/json"
    }
    
    url = f"{api_url}/Tickets"
    logger.info(f"Posting Autotask ticket creation to: {url}")
    
    r = requests.post(url, json=payload, headers=headers, timeout=15)
    if r.ok:
        data = r.json()
        # Assume ticket ID is returned in response
        return str(data.get("id", "AT-TICKET-OK"))
    else:
        raise Exception(f"Autotask API response failed: HTTP {r.status_code} - {r.text}")

def run_once():
    logger.info("Starting ticketer pass...")
    
    integration = get_integration("autotask")
    if not integration.get("enabled", False):
        logger.info("Autotask integration is disabled. Skipping ticketing.")
        return

    config = integration.get("config") or {}
    secrets = integration.get("secrets") or {}
    
    api_url = config.get("api_url") or os.getenv("AUTOTASK_API_URL", "https://webservices.autotask.net/atservicesrest/v1.0")
    queue_id = config.get("queue_id") or os.getenv("AUTOTASK_QUEUE_ID", "")
    account_id = config.get("account_id") or os.getenv("AUTOTASK_ACCOUNT_ID", "")
    default_assignee_resource_id = config.get("default_assignee_resource_id") or os.getenv("AUTOTASK_DEFAULT_ASSIGNEE_RESOURCE_ID", "")
    
    api_integration_code = secrets.get("api_integration_code") or os.getenv("AUTOTASK_API_INTEGRATION_CODE", "")
    username = secrets.get("username") or os.getenv("AUTOTASK_USERNAME", "")
    secret = secrets.get("secret") or os.getenv("AUTOTASK_SECRET", "")
    
    # 1. Check daily ticket limit
    current_tickets_count = get_recent_tickets_count()
    logger.info(f"Tickets created in last 24 hours: {current_tickets_count}/{MAX_TICKETS_PER_DAY}")
    
    if current_tickets_count >= MAX_TICKETS_PER_DAY:
        logger.warning("Daily ticket quota reached. Skipping ticketing.")
        return
        
    tickets_remaining = MAX_TICKETS_PER_DAY - current_tickets_count
    
    # 2. Check for missing Autotask credentials to determine stub mode
    required_creds = [
        api_integration_code,
        username,
        secret,
        queue_id,
        account_id,
        default_assignee_resource_id
    ]
    is_stub_mode = any(not str(val).strip() for val in required_creds)
    
    if is_stub_mode:
        logger.info("Autotask integration in STUB mode: missing one or more credentials.")
        
    # 3. Query candidates for ticketing
    candidates = []
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                query = """
                    SELECT 
                        t.id, 
                        t.status, 
                        f.cve, 
                        a.hostname as asset_name,
                        t.priority_score,
                        f.severity,
                        COALESCE(e.in_kev, FALSE) as in_kev,
                        COALESCE(e.public_exploit, FALSE) as public_exploit,
                        f.title,
                        f.description
                    FROM triage t
                    JOIN findings f ON t.finding_id = f.id
                    JOIN assets a ON f.asset_id = a.id
                    LEFT JOIN enrichment e ON f.cve = e.cve
                    WHERE t.status = 'approved' 
                       OR (t.status = 'pending' AND %s = FALSE)
                    ORDER BY t.priority_score DESC;
                """
                cur.execute(query, (REQUIRE_HUMAN_APPROVAL,))
                candidates = cur.fetchall()
    except Exception as e:
        logger.error(f"Error querying ticketing candidates: {e}")
        return
        
    if not candidates:
        logger.info("No candidates for ticketing found.")
        return

    logger.info(f"Found {len(candidates)} candidate(s) for ticketing. Processing up to {tickets_remaining} ticket(s).")
    
    processed_count = 0
    for row in candidates:
        if processed_count >= tickets_remaining:
            logger.info("Reached maximum ticket quota for this tick.")
            break
            
        triage_id = row[0]
        status = row[1]
        cve = row[2]
        asset_name = row[3]
        priority_score = float(row[4])
        severity = row[5]
        in_kev = row[6]
        public_exploit = row[7]
        finding_title = row[8]
        finding_description = row[9]
        
        logger.info(f"Processing ticket for triage_id {triage_id} ({cve} on {asset_name})")
        
        try:
            with get_db_connection() as conn:
                with conn:
                    if is_stub_mode:
                        # 1. Log a TODO row in audit_events FIRST (mandatory write audit rule)
                        todo_audit_query = """
                            INSERT INTO audit_events (action, target_type, target_id, details)
                            VALUES ('AUTOTASK_TODO', 'triage', %s, %s);
                        """
                        todo_details = json.dumps({
                            "message": "Autotask API ticket creation pending. Running in stub mode.",
                            "cve": cve,
                            "asset_name": asset_name,
                            "priority_score": priority_score
                        })
                        with conn.cursor() as cur:
                            cur.execute(todo_audit_query, (str(triage_id), todo_details))
                        
                        # 2. Insert ticket with system 'autotask-stub' (write-before-action audit triggered via execute_write)
                        ticket_query = """
                            INSERT INTO tickets (triage_id, external_system, external_id)
                            VALUES (%s, 'autotask-stub', %s)
                            RETURNING id;
                        """
                        stub_ext_id = f"AT-STUB-{triage_id}"
                        execute_write(
                            conn,
                            action="create_stub_ticket",
                            target_type="ticket",
                            target_id=triage_id,
                            details={"external_system": "autotask-stub", "external_id": stub_ext_id},
                            write_query=ticket_query,
                            write_params=(triage_id, stub_ext_id)
                        )
                        
                        # 3. Update triage status
                        triage_update_query = """
                            UPDATE triage 
                            SET status = 'ticketed', updated_at = NOW() 
                            WHERE id = %s;
                        """
                        execute_write(
                            conn,
                            action="update_triage_status",
                            target_type="triage",
                            target_id=triage_id,
                            details={"old_status": status, "new_status": "ticketed", "system": "autotask-stub"},
                            write_query=triage_update_query,
                            write_params=(triage_id,)
                        )
                        logger.info(f"Logged TODO and created stub ticket for triage_id {triage_id}")
                    else:
                        # Real Autotask call
                        ticket_id = open_autotask_ticket(
                            cve=cve,
                            hostname=asset_name,
                            severity=severity,
                            in_kev=in_kev,
                            public_exploit=public_exploit,
                            priority_score=priority_score,
                            finding_title=finding_title,
                            finding_description=finding_description
                        )
                        
                        # Save ticket info (write-before-action audit triggered via execute_write)
                        ticket_query = """
                            INSERT INTO tickets (triage_id, external_system, external_id)
                            VALUES (%s, 'autotask', %s)
                            RETURNING id;
                        """
                        execute_write(
                            conn,
                            action="create_autotask_ticket",
                            target_type="ticket",
                            target_id=triage_id,
                            details={"external_system": "autotask", "external_id": ticket_id},
                            write_query=ticket_query,
                            write_params=(triage_id, ticket_id)
                        )
                        
                        # Update triage status
                        triage_update_query = """
                            UPDATE triage 
                            SET status = 'ticketed', updated_at = NOW() 
                            WHERE id = %s;
                        """
                        execute_write(
                            conn,
                            action="update_triage_status",
                            target_type="triage",
                            target_id=triage_id,
                            details={"old_status": status, "new_status": "ticketed", "system": "autotask"},
                            write_query=triage_update_query,
                            write_params=(triage_id,)
                        )
                        logger.info(f"Opened real Autotask ticket {ticket_id} for triage_id {triage_id}")
                        
            processed_count += 1
            
        except Exception as e:
            logger.error(f"Failed to create ticket for triage_id {triage_id}: {e}")

if __name__ == "__main__":
    logger.info("Ticketer agent started.")
    if len(sys.argv) > 1 and sys.argv[1] == "--once":
        logger.info("Running a single ticketing pass.")
        run_once()
        sys.exit(0)

    while True:
        try:
            run_once()
        except Exception as e:
            logger.error(f"Error in ticketer loop: {e}")
        time.sleep(30)
