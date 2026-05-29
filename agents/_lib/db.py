# agents/_lib/db.py
import os
import json
import logging
import psycopg2
from psycopg2 import pool
from contextlib import contextmanager

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("db_lib")

# Load environment variables
DB_HOST = os.getenv("POSTGRES_HOST", "postgres")
DB_PORT = os.getenv("POSTGRES_PORT", "5432")
DB_NAME = os.getenv("POSTGRES_DB", "vuln_triage")
DB_USER = os.getenv("POSTGRES_USER", "triage_user")
DB_PASS = os.getenv("POSTGRES_PASSWORD", "secure_password_here")

# Initialize connection pool lazily
_pool = None

def get_pool():
    global _pool
    if _pool is None:
        try:
            logger.info(f"Initializing connection pool for {DB_USER}@{DB_HOST}:{DB_PORT}/{DB_NAME}")
            # Use ThreadedConnectionPool since services are multi-threaded or run concurrent tasks
            _pool = pool.ThreadedConnectionPool(
                minconn=2,
                maxconn=20,
                host=DB_HOST,
                port=DB_PORT,
                database=DB_NAME,
                user=DB_USER,
                password=DB_PASS
            )
        except Exception as e:
            logger.error(f"Failed to create connection pool: {e}")
            raise e
    return _pool

@contextmanager
def get_db_connection():
    db_pool = get_pool()
    conn = db_pool.getconn()
    try:
        yield conn
    finally:
        db_pool.putconn(conn)

@contextmanager
def get_db_cursor(commit=False):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            try:
                yield cur
                if commit:
                    conn.commit()
            except Exception as e:
                if commit:
                    conn.rollback()
                raise e

def execute_write(conn, action, target_type, target_id, details, write_query, write_params, actor=None, target=None, detail=None):
    """
    Executes a write operation by FIRST inserting an audit event, 
    then executing the write query, in the same transaction.
    """
    # Exclude any secrets or sensitive data from details before writing
    sanitized_details = {}
    if details:
        for k, v in details.items():
            if any(secret_word in k.lower() for secret_word in ["secret", "password", "token", "key"]):
                sanitized_details[k] = "[REDACTED]"
            else:
                sanitized_details[k] = v

    with conn.cursor() as cur:
        # 1. Insert audit event first
        audit_query = """
            INSERT INTO audit_events (action, target_type, target_id, details, actor, target, detail)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id;
        """
        db_actor = actor
        db_target = target or f"{target_type}:{target_id}"
        
        # Check if detail was passed, if not fallback to sanitized_details
        if detail is not None:
            sanitized_detail = {}
            for k, v in detail.items():
                if any(secret_word in k.lower() for secret_word in ["secret", "password", "token", "key"]):
                    sanitized_detail[k] = "[REDACTED]"
                else:
                    sanitized_detail[k] = v
            db_detail = json.dumps(sanitized_detail)
        else:
            db_detail = json.dumps(sanitized_details)
            
        cur.execute(audit_query, (
            action, 
            target_type, 
            str(target_id), 
            json.dumps(sanitized_details),
            db_actor,
            db_target,
            db_detail
        ))
        audit_id = cur.fetchone()[0]
        
        # 2. Execute the actual write
        cur.execute(write_query, write_params)
        
        return audit_id
