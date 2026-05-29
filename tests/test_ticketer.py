# tests/test_ticketer.py
import pytest
from ticketer.app import run_once, generate_mock_ticket

def test_generate_mock_ticket():
    sys, ext_id = generate_mock_ticket("CVE-2023-1234", "asset-1")
    assert sys in ['jira', 'servicenow', 'github']
    assert len(ext_id) > 0

def test_ticketer_run_once(db_connection):
    import _lib.db
    orig_get_conn = _lib.db.get_db_connection
    _lib.db.get_db_connection = lambda: db_connection
    
    try:
        if hasattr(db_connection, 'cursor') and not db_connection.__class__.__name__ == 'MockConnection':
            with db_connection.cursor() as cur:
                # Setup clean slate
                cur.execute("DELETE FROM assets WHERE name = 'test-asset-ticket';")
                
                # Insert asset
                cur.execute("INSERT INTO assets (name, environment, business_crit) VALUES ('test-asset-ticket', 'prod', 3) RETURNING id;")
                asset_id = cur.fetchone()[0]
                
                # Insert finding
                cur.execute("INSERT INTO findings (asset_id, cve, title, cvss_base, severity, detected_at) VALUES (%s, 'CVE-2023-8888', 'Ticket test', 9.0, 'Critical', NOW()) RETURNING id;", (asset_id,))
                finding_id = cur.fetchone()[0]
                
                # Insert triage and set to approved
                cur.execute("INSERT INTO triage (finding_id, status, priority_score) VALUES (%s, 'approved', 45.0) RETURNING id;", (finding_id,))
                triage_id = cur.fetchone()[0]
                db_connection.commit()
                
            run_once()
            
            with db_connection.cursor() as cur:
                # Verify ticket created
                cur.execute("SELECT external_system, external_id FROM tickets WHERE triage_id = %s;", (triage_id,))
                ticket = cur.fetchone()
                assert ticket is not None
                assert ticket[0] in ['jira', 'servicenow', 'github']
                
                # Verify status updated to ticketed
                cur.execute("SELECT status FROM triage WHERE id = %s;", (triage_id,))
                status = cur.fetchone()[0]
                assert status == 'ticketed'
                
                # Verify audit logging
                cur.execute("SELECT action FROM audit_events WHERE action = 'create_ticket' AND target_id = %s;", (str(triage_id),))
                assert cur.fetchone() is not None
                cur.execute("SELECT action FROM audit_events WHERE action = 'update_triage_status' AND target_id = %s;", (str(triage_id),))
                assert cur.fetchone() is not None
    finally:
        _lib.db.get_db_connection = orig_get_conn
