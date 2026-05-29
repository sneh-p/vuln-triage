# tests/test_ingestor.py
import os
import csv
import tempfile
import pytest
from ingestor.app import process_csv_file

def test_ingestor_happy_path(db_connection):
    """Verifies that ingestor successfully parses a CSV file and inserts records into DB."""
    # Write a temporary CSV file
    fd, temp_path = tempfile.mkstemp(suffix=".csv")
    try:
        with os.fdopen(fd, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["asset_name", "environment", "business_crit", "cve", "title", "description", "cvss_base", "severity", "detected_at"])
            writer.writerow(["test-asset-1", "prod", "3", "CVE-2023-1234", "Test Vuln 1", "Detailed Description 1", "7.5", "High", "2026-05-27 10:00:00"])

        # Patch db connection library to use our test db connection
        import _lib.db
        orig_get_conn = _lib.db.get_db_connection
        _lib.db.get_db_connection = lambda: db_connection
        
        try:
            # Process the temporary CSV file
            success = process_csv_file(temp_path)
            assert success is True
            
            # Verify records were inserted if it's a real db connection
            if hasattr(db_connection, 'cursor') and not db_connection.__class__.__name__ == 'MockConnection':
                with db_connection.cursor() as cur:
                    # Check asset
                    cur.execute("SELECT id, environment, business_crit FROM assets WHERE name = 'test-asset-1';")
                    asset = cur.fetchone()
                    assert asset is not None
                    assert asset[1] == 'prod'
                    assert asset[2] == 3
                    
                    # Check finding
                    cur.execute("SELECT id, cve, cvss_base FROM findings WHERE asset_id = %s AND cve = 'CVE-2023-1234';", (asset[0],))
                    finding = cur.fetchone()
                    assert finding is not None
                    assert float(finding[2]) == 7.5
                    
                    # Check audit events
                    cur.execute("SELECT action FROM audit_events WHERE action = 'upsert_finding';")
                    audit = cur.fetchone()
                    assert audit is not None
        finally:
            _lib.db.get_db_connection = orig_get_conn
    finally:
        os.remove(temp_path)
