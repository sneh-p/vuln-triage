# tests/test_coordinator.py
import pytest
from fastapi.testclient import TestClient
from coordinator.app import app

def test_healthz(db_connection):
    import _lib.db
    orig_get_conn = _lib.db.get_db_connection
    _lib.db.get_db_connection = lambda: db_connection
    
    try:
        client = TestClient(app)
        response = client.get("/healthz")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"
    finally:
        _lib.db.get_db_connection = orig_get_conn

def test_brief_html(db_connection):
    import _lib.db
    orig_get_conn = _lib.db.get_db_connection
    _lib.db.get_db_connection = lambda: db_connection
    
    try:
        client = TestClient(app)
        response = client.get("/brief.html")
        assert response.status_code == 200
        assert "Vulnerability Triage Gate Monitor" in response.text
    finally:
        _lib.db.get_db_connection = orig_get_conn

def test_approve_reject_endpoints(db_connection):
    import _lib.db
    orig_get_conn = _lib.db.get_db_connection
    _lib.db.get_db_connection = lambda: db_connection
    
    try:
        client = TestClient(app)
        
        # Test approving non-existent record
        response = client.get("/approve/999999")
        assert response.status_code == 404
        
        # Test on real db if possible
        if hasattr(db_connection, 'cursor') and not db_connection.__class__.__name__ == 'MockConnection':
            with db_connection.cursor() as cur:
                cur.execute("DELETE FROM assets WHERE name = 'test-asset-coord';")
                cur.execute("INSERT INTO assets (name, environment, business_crit) VALUES ('test-asset-coord', 'prod', 3) RETURNING id;")
                asset_id = cur.fetchone()[0]
                
                cur.execute("INSERT INTO findings (asset_id, cve, title, cvss_base, severity, detected_at) VALUES (%s, 'CVE-2023-7777', 'Coord test', 6.0, 'Medium', NOW()) RETURNING id;", (asset_id,))
                finding_id = cur.fetchone()[0]
                
                cur.execute("INSERT INTO triage (finding_id, status, priority_score) VALUES (%s, 'pending', 10.0) RETURNING id;", (finding_id,))
                triage_id = cur.fetchone()[0]
                db_connection.commit()
                
            # Approve it
            response = client.get(f"/approve/{triage_id}")
            assert response.status_code == 200
            assert response.json()["status"] == "success"
            
            # Check db status
            with db_connection.cursor() as cur:
                cur.execute("SELECT status FROM triage WHERE id = %s;", (triage_id,))
                assert cur.fetchone()[0] == 'approved'
                
                # Check audit trail
                cur.execute("SELECT action FROM audit_events WHERE action = 'approve_triage' AND target_id = %s;", (str(triage_id),))
                assert cur.fetchone() is not None
                
            # Try to approve again (should fail because no longer pending)
            response = client.get(f"/approve/{triage_id}")
            assert response.status_code == 400
            
            # Reset to pending for reject test
            with db_connection.cursor() as cur:
                cur.execute("UPDATE triage SET status = 'pending' WHERE id = %s;", (triage_id,))
                db_connection.commit()
                
            # Reject it
            response = client.get(f"/reject/{triage_id}")
            assert response.status_code == 200
            
            # Check status and audit
            with db_connection.cursor() as cur:
                cur.execute("SELECT status FROM triage WHERE id = %s;", (triage_id,))
                assert cur.fetchone()[0] == 'rejected'
                cur.execute("SELECT action FROM audit_events WHERE action = 'reject_triage' AND target_id = %s;", (str(triage_id),))
                assert cur.fetchone() is not None
    finally:
        _lib.db.get_db_connection = orig_get_conn
