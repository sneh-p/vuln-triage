# tests/test_enricher.py
import pytest
from enricher.app import enrich_cve, check_exploitdb_mock

def test_enricher_happy_path(db_connection):
    """Verifies that enrich_cve successfully queries APIs (or mocked fallbacks) and inserts enrichment data."""
    # Set up patch for db connection
    import _lib.db
    orig_get_conn = _lib.db.get_db_connection
    _lib.db.get_db_connection = lambda: db_connection
    
    try:
        cve = "CVE-2023-38831"
        kev_set = {cve} # Mock KEV set
        
        success = enrich_cve(cve, kev_set)
        assert success is True
        
        # Verify db insertion if real
        if hasattr(db_connection, 'cursor') and not db_connection.__class__.__name__ == 'MockConnection':
            with db_connection.cursor() as cur:
                cur.execute("SELECT epss, in_kev, public_exploit FROM enrichment WHERE cve = %s;", (cve,))
                res = cur.fetchone()
                assert res is not None
                assert res[1] is True # in_kev should be True
                assert res[2] is True # CVE-2023-38831 is in known exploits check
                
                # Check audit_events
                cur.execute("SELECT action FROM audit_events WHERE action = 'enrich_cve' AND target_id = %s;", (cve,))
                audit = cur.fetchone()
                assert audit is not None
    finally:
        _lib.db.get_db_connection = orig_get_conn

def test_check_exploitdb_mock():
    assert check_exploitdb_mock("CVE-2021-44228") is True
    assert check_exploitdb_mock("CVE-2023-38831") is True
    # CVE ends with 7
    assert check_exploitdb_mock("CVE-2023-1237") is True
    # Standard CVE does not exploit
    assert check_exploitdb_mock("CVE-2023-1234") is False
