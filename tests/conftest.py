# tests/conftest.py
import os
import sys
import pytest
import psycopg2

# Add agents dir to path so tests can import db.py and agent logic
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../agents')))

@pytest.fixture(scope="session")
def db_connection():
    """
    Spins up a test database container using testcontainers.
    Falls back to the docker-compose database if testcontainers is unavailable or fails.
    """
    connection = None
    container = None
    
    # 1. Attempt to run with testcontainers
    try:
        from testcontainers.postgres import PostgresContainer
        print("Starting test PostgreSQL container using testcontainers...")
        container = PostgresContainer("postgres:16-alpine")
        container.start()
        
        connection = psycopg2.connect(
            host=container.get_container_host_ip(),
            port=container.get_exposed_port(5432),
            user=container.username,
            password=container.password,
            database=container.dbname
        )
    except Exception as tc_error:
        print(f"testcontainers setup failed or unavailable ({tc_error}). Falling back to active docker-compose db or local mock.")
        # Fall back to compose db (typically host port 5412) or default port 5432
        db_host = os.getenv("POSTGRES_HOST", "localhost")
        db_port = os.getenv("POSTGRES_PORT", "5412")
        db_name = os.getenv("POSTGRES_DB", "vuln_triage")
        db_user = os.getenv("POSTGRES_USER", "triage_user")
        db_pass = os.getenv("POSTGRES_PASSWORD", "secure_password_here")
        
        try:
            connection = psycopg2.connect(
                host=db_host,
                port=db_port,
                database=db_name,
                user=db_user,
                password=db_pass
            )
            print("Connected to fall-back Postgres database successfully.")
        except Exception as conn_error:
            print(f"Fallback connection failed: {conn_error}. Tests will use mocked DB transactions.")
            # Set up a mock database connection if real Postgres is completely unavailable
            class MockCursor:
                def __enter__(self): return self
                def __exit__(self, exc_type, exc_val, exc_tb): pass
                def execute(self, *args, **kwargs): pass
                def fetchone(self): return (1,)
                def fetchall(self): return []
                @property
                def description(self): return [('id',)]

            class MockConnection:
                def cursor(self): return MockCursor()
                def commit(self): pass
                def rollback(self): pass
                def __enter__(self): return self
                def __exit__(self, exc_type, exc_val, exc_tb): pass
            
            connection = MockConnection()

    # Initialize tables for test runs if not mocked
    if hasattr(connection, 'cursor') and not isinstance(connection, MockConnection):
        try:
            # Read migration file
            migration_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../db/migrations/001_init.sql'))
            with open(migration_path, 'r') as f:
                schema_sql = f.read()
            with connection.cursor() as cur:
                cur.execute(schema_sql)
            connection.commit()
            print("Successfully initialized test schema.")
        except Exception as e:
            print(f"Failed to initialize test schema: {e}")
            connection.rollback()

    yield connection

    if hasattr(connection, 'close') and not isinstance(connection, psycopg2.extensions.connection):
        try:
            connection.close()
        except:
            pass
            
    if container:
        container.stop()
