# tests/test_correlator.py
import pytest
from correlator.app import calculate_priority_score, run_once

def test_calculate_priority_score():
    # priority_score = cvss_base * (1 + 2*epss) * (3 if in_kev else 1) * (2 if public_exploit else 1) * (business_crit/3) * env_multiplier
    # Scenario: cvss=5.0, epss=0.5, KEV=true, Exploit=true, crit=3, env=prod (1.5)
    # Score = 5.0 * (1 + 2*0.5) * 3 * 2 * (3/3) * 1.5
    # Score = 5.0 * 2.0 * 3 * 2 * 1 * 1.5 = 90.0
    score = calculate_priority_score(5.0, 0.5, True, True, 3, 'prod')
    assert score == 90.0
    
    # Scenario: cvss=10.0, epss=0.0, KEV=false, Exploit=false, crit=1, env=sandbox (0.2)
    # Score = 10.0 * 1 * 1 * 1 * (1/3) * 0.2 = 10 * 0.33333 * 0.2 = 0.67
    score = calculate_priority_score(10.0, 0.0, False, False, 1, 'sandbox')
    assert score == 0.67

def test_correlator_run_once(db_connection):
    import _lib.db
    orig_get_conn = _lib.db.get_db_connection
    _lib.db.get_db_connection = lambda: db_connection
    
    try:
        # Seed asset, finding, enrichment if real DB
        if hasattr(db_connection, 'cursor') and not db_connection.__class__.__name__ == 'MockConnection':
            with db_connection.cursor() as cur:
                # Clean up existing
                cur.execute("DELETE FROM assets WHERE name = 'test-asset-correlate';")
                
                # Insert asset
                cur.execute("INSERT INTO assets (name, environment, business_crit) VALUES ('test-asset-correlate', 'staging', 2) RETURNING id;")
                asset_id = cur.fetchone()[0]
                
                # Insert finding
                cur.execute("INSERT INTO findings (asset_id, cve, title, cvss_base, severity, detected_at) VALUES (%s, 'CVE-2023-9999', 'Correlate test', 8.0, 'High', NOW()) RETURNING id;", (asset_id,))
                finding_id = cur.fetchone()[0]
                
                # Insert enrichment
                cur.execute("INSERT INTO enrichment (cve, epss, in_kev, public_exploit, last_enriched_at) VALUES ('CVE-2023-9999', 0.1, TRUE, FALSE, NOW());")
                db_connection.commit()
                
            run_once()
            
            with db_connection.cursor() as cur:
                # Verify triage record
                cur.execute("SELECT priority_score, status FROM triage WHERE finding_id = %s;", (finding_id,))
                triage = cur.fetchone()
                assert triage is not None
                # Expected score: 8.0 * (1 + 2*0.1) * 3 (kev) * 1 (exploit) * (2/3) * 1.0 (staging)
                # Score = 8.0 * 1.2 * 3 * 0.66666 * 1.0 = 19.2
                assert float(triage[0]) == 19.2
                assert triage[1] == 'pending'
                
                # Verify audit log
                cur.execute("SELECT action FROM audit_events WHERE action = 'create_triage' AND target_id = %s;", (str(finding_id),))
                audit = cur.fetchone()
                assert audit is not None
    finally:
        _lib.db.get_db_connection = orig_get_conn
