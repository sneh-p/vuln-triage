# agents/coordinator/app.py
import os
import sys
import logging
import requests
from datetime import datetime
import json
import codecs
import time
from fastapi import FastAPI, HTTPException, Response, File, Form, UploadFile, Query, Request, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from pydantic import BaseModel
from typing import List
import bcrypt
from itsdangerous import Signer, BadSignature
from _lib.parsers import cavelo, blackpoint
from _lib.pipeline import enrich_batch, correlate_batch
from apscheduler.schedulers.background import BackgroundScheduler

# Encryption & Auth Setup
class PasswordContext:
    def hash(self, password: str) -> str:
        pwd_bytes = password.encode('utf-8')
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(pwd_bytes, salt)
        return hashed.decode('utf-8')

    def verify(self, plain_password: str, hashed_password: str) -> bool:
        try:
            return bcrypt.checkpw(
                plain_password.encode('utf-8'),
                hashed_password.encode('utf-8')
            )
        except Exception:
            return False

pwd_context = PasswordContext()
SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-triage-gate-key")
signer = Signer(SECRET_KEY)
ROLE_hierarchy = {"analyst": 1, "manager": 2, "admin": 3}

SHARED_JS_INJECTION = """
<style>
    #toast-container {
        position: fixed;
        top: 1rem;
        right: 1rem;
        z-index: 9999;
        display: flex;
        flex-direction: column;
        gap: 0.5rem;
        max-width: 350px;
        width: calc(100% - 2rem);
    }
    .toast-message {
        padding: 0.75rem 1rem;
        border-radius: 0.375rem;
        font-family: 'Outfit', sans-serif;
        font-size: 0.875rem;
        font-weight: 500;
        color: #f8fafc;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        cursor: pointer;
        animation: toast-fade-in 0.2s ease-out;
        transition: opacity 0.2s ease, transform 0.2s ease;
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 0.5rem;
        border: 1px solid var(--border-color, #334155);
    }
    .toast-info { background-color: #1e293b; border-left: 4px solid #3b82f6; }
    .toast-success { background-color: #0f172a; border-left: 4px solid #10b981; }
    .toast-error { background-color: #0f172a; border-left: 4px solid #ef4444; }
    .toast-warning { background-color: #1e293b; border-left: 4px solid #f59e0b; }
    @keyframes toast-fade-in {
        from { opacity: 0; transform: translateY(-10px); }
        to { opacity: 1; transform: translateY(0); }
    }
</style>
<script>
    (function() {
        function initToastContainer() {
            if (!document.getElementById('toast-container')) {
                const container = document.createElement('div');
                container.id = 'toast-container';
                document.body.appendChild(container);
            }
        }
        if (document.body) {
            initToastContainer();
        } else {
            document.addEventListener('DOMContentLoaded', initToastContainer);
        }

        window.toast = function(message, type = 'info', duration = 4000) {
            initToastContainer();
            const container = document.getElementById('toast-container');
            if (!container) return;
            
            const visibleToasts = container.querySelectorAll('.toast-message');
            if (visibleToasts.length >= 3) {
                visibleToasts[0].remove();
            }

            const el = document.createElement('div');
            el.className = `toast-message toast-${type}`;
            
            const textSpan = document.createElement('span');
            textSpan.textContent = message;
            el.appendChild(textSpan);
            
            const closeBtn = document.createElement('span');
            closeBtn.textContent = '×';
            closeBtn.style.fontSize = '1.2rem';
            closeBtn.style.cursor = 'pointer';
            closeBtn.style.opacity = '0.7';
            closeBtn.style.marginLeft = '0.5rem';
            closeBtn.onclick = (e) => { e.stopPropagation(); el.remove(); };
            el.appendChild(closeBtn);

            el.onclick = () => { el.remove(); };
            container.appendChild(el);

            setTimeout(() => {
                el.style.opacity = '0';
                el.style.transform = 'translateY(-10px)';
                setTimeout(() => el.remove(), 200);
            }, duration);
        };

        window.apiFetch = async function(url, options = {}) {
            try {
                const response = await fetch(url, options);
                if (response.status === 401) {
                    if (!window.location.pathname.endsWith('login.html')) {
                        localStorage.setItem('intended_path', window.location.pathname + window.location.search);
                        window.location.href = '/login.html';
                    }
                    return response;
                }
                if (response.status === 403) {
                    try {
                        const body = await response.clone().json();
                        let errorMsg = body.detail || body.error || "You don't have permission to do that";
                        if (typeof errorMsg === 'object') {
                            errorMsg = JSON.stringify(errorMsg);
                        }
                        window.toast(errorMsg, "error");
                    } catch (e) {
                        window.toast("You don't have permission to do that", "error");
                    }
                    return response;
                }
                if (response.status >= 500) {
                    try {
                        const body = await response.clone().json();
                        let errorMsg = body.detail || body.error || "Server error — try again or contact admin";
                        if (typeof errorMsg === 'object') {
                            errorMsg = JSON.stringify(errorMsg);
                        }
                        window.toast(errorMsg, "error");
                    } catch (e) {
                        window.toast("Server error — try again or contact admin", "error");
                    }
                    return response;
                }
                if (response.status >= 400) {
                    try {
                        const body = await response.clone().json();
                        let errorMsg = body.detail || body.error || ('Error ' + response.status);
                        if (typeof errorMsg === 'object') {
                            errorMsg = JSON.stringify(errorMsg);
                        }
                        window.toast(errorMsg, "error");
                    } catch (e) {
                        window.toast(`Request failed with status ${response.status}`, "error");
                    }
                    return response;
                }
                return response;
            } catch (err) {
                window.toast("Network error — check your connection", "error");
                throw err;
            }
        };

        window.confirmDialog = function({title, message, confirmText = 'Confirm', confirmStyle = 'primary'}) {
            return new Promise((resolve) => {
                const modal = document.createElement('div');
                modal.style.position = 'fixed';
                modal.style.top = '0';
                modal.style.left = '0';
                modal.style.width = '100%';
                modal.style.height = '100%';
                modal.style.backgroundColor = 'rgba(15, 23, 42, 0.85)';
                modal.style.backdropFilter = 'blur(4px)';
                modal.style.display = 'flex';
                modal.style.alignItems = 'center';
                modal.style.justifyContent = 'center';
                modal.style.zIndex = '10000';
                modal.style.fontFamily = "'Outfit', sans-serif";

                const btnColor = confirmStyle === 'danger' ? 'var(--accent-red, #ef4444)' : 'var(--accent-cyan, #06b6d4)';
                const card = document.createElement('div');
                card.style.backgroundColor = 'var(--bg-secondary, #1e293b)';
                card.style.border = '1px solid var(--border-color, #334155)';
                card.style.borderRadius = '0.5rem';
                card.style.padding = '1.5rem';
                card.style.maxWidth = '400px';
                card.style.width = 'calc(100% - 2rem)';
                card.style.color = 'var(--text-primary, #f8fafc)';
                card.style.boxShadow = '0 10px 15px -3px rgba(0, 0, 0, 0.3)';

                card.innerHTML = `
                    <h3 style="margin-top: 0; margin-bottom: 0.75rem; font-size: 1.2rem; font-weight: 600; color: var(--text-primary, #f8fafc);">${title}</h3>
                    <p style="margin-top: 0; margin-bottom: 1.5rem; color: var(--text-secondary, #94a3b8); font-size: 0.9rem; line-height: 1.4;">${message}</p>
                    <div style="display: flex; justify-content: flex-end; gap: 0.75rem;">
                        <button id="confirm-cancel" style="background: none; border: 1px solid var(--border-color, #334155); color: var(--text-primary, #f8fafc); padding: 0.5rem 1rem; border-radius: 0.25rem; cursor: pointer; font-family: inherit; font-size: 0.85rem; font-weight: 500;">Cancel</button>
                        <button id="confirm-ok" style="background: ${btnColor}; border: none; color: #fff; padding: 0.5rem 1rem; border-radius: 0.25rem; cursor: pointer; font-family: inherit; font-size: 0.85rem; font-weight: 500;">${confirmText}</button>
                    </div>
                `;
                modal.appendChild(card);
                document.body.appendChild(modal);

                const cleanUp = () => {
                    modal.remove();
                    document.removeEventListener('keydown', handleEsc);
                };

                const handleEsc = (e) => {
                    if (e.key === 'Escape') {
                        cleanUp();
                        resolve(false);
                    }
                };

                document.addEventListener('keydown', handleEsc);

                modal.onclick = (e) => {
                    if (e.target === modal) {
                        cleanUp();
                        resolve(false);
                    }
                };

                card.querySelector('#confirm-cancel').onclick = () => {
                    cleanUp();
                    resolve(false);
                };

                card.querySelector('#confirm-ok').onclick = () => {
                    cleanUp();
                    resolve(true);
                };
            });
        };
    })();
</script>
"""

def render_html(html_str: str) -> HTMLResponse:
    return HTMLResponse(content=html_str.replace("</head>", f"{SHARED_JS_INJECTION}</head>"))



sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from _lib.db import get_db_connection, execute_write

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] coordinator: %(message)s")
logger = logging.getLogger("coordinator")

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
COORDINATOR_EXTERNAL_URL = os.getenv("COORDINATOR_EXTERNAL_URL", "http://localhost:8080")


failed_login_attempts = {}
blocked_ips = {}
app = FastAPI(title="Vulnerability Triage Coordinator")

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception(f"Unhandled error on route {request.url.path}: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "An unexpected server error occurred.", "code": "INTERNAL_SERVER_ERROR"}
    )


def get_top_pending():
    query = """
        SELECT 
            t.id AS triage_id,
            f.cve,
            f.title,
            f.cvss_base,
            a.hostname AS asset_name,
            a.environment,
            t.priority_score,
            COALESCE(e.epss, 0.0) as epss,
            COALESCE(e.in_kev, FALSE) as in_kev,
            COALESCE(e.public_exploit, FALSE) as public_exploit
        FROM triage t
        JOIN findings f ON t.finding_id = f.id
        JOIN assets a ON f.asset_id = a.id
        LEFT JOIN enrichment e ON f.cve = e.cve
        WHERE t.status = 'pending'
        ORDER BY t.priority_score DESC
        LIMIT 10;
    """
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(query)
                cols = [desc[0] for desc in cur.description]
                rows = cur.fetchall()
                return [dict(zip(cols, row)) for row in rows]
    except Exception as e:
        logger.error(f"Failed to query top pending: {e}")
        return []

def format_slack_message(pending_items):
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "🛡️ Daily Vulnerability Triage Brief",
                "emoji": True
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"Here are the top pending vulnerabilities for triage as of *{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*."
            }
        },
        {"type": "divider"}
    ]
    
    if not pending_items:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "🎉 *No pending vulnerabilities to triage!*"
            }
        })
        return {"blocks": blocks}
        
    for item in pending_items:
        cve = item['cve']
        asset = item['asset_name']
        score = item['priority_score']
        env = item['environment']
        triage_id = item['triage_id']
        title = item['title']
        
        # Badges
        badges = []
        if item['in_kev']:
            badges.append("🔥 KEV")
        if item['public_exploit']:
            badges.append("🔓 Exploit")
        badge_str = f" [{', '.join(badges)}]" if badges else ""
        
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*CVE*: {cve} | *Score*: `{score}` | *Asset*: `{asset}` ({env}){badge_str}\n_{title}_"
            },
            "accessory": {
                "type": "button",
                "text": {
                    "type": "plain_text",
                    "text": "Review Brief",
                    "emoji": True
                },
                "value": str(triage_id),
                "url": f"{COORDINATOR_EXTERNAL_URL}/brief.html"
            }
        })
        
    return {"blocks": blocks}

def send_slack_brief(dry_run=False):
    logger.info("Generating Slack daily brief...")
    pending = get_top_pending()
    payload = format_slack_message(pending)
    
    from _lib.integrations import get_integration
    slack_integration = get_integration("slack")
    enabled = slack_integration.get("enabled", False)
    webhook_url = slack_integration.get("secrets", {}).get("webhook_url", "")
    
    if not webhook_url:
        webhook_url = os.getenv("SLACK_WEBHOOK_URL", "")
        
    if not enabled and not dry_run:
        logger.info("Slack integration is disabled. Skipping daily brief.")
        return

    if dry_run or not webhook_url:
        logger.info(f"[DRY RUN / MOCK] Generated Slack Brief payload:\n{payload}")
        return
        
    try:
        r = requests.post(webhook_url, json=payload, timeout=10)
        if r.ok:
            logger.info("Successfully posted daily brief to Slack.")
        else:
            logger.error(f"Failed to post to Slack: HTTP {r.status_code} - {r.text}")
    except Exception as e:
        logger.error(f"Exception posting brief to Slack: {e}")

# Scheduler setup
scheduler = BackgroundScheduler()
scheduler.add_job(send_slack_brief, 'cron', hour=7, minute=0, args=[False])

@app.on_event("startup")
def startup_event():
    scheduler.start()
    logger.info("APScheduler started.")

    # 1. Create users table if not exists
    create_users_table_query = """
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(64) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role VARCHAR(16) NOT NULL CHECK (role IN ('admin','manager','analyst')),
        must_change_password BOOLEAN NOT NULL DEFAULT true,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        last_login_at TIMESTAMPTZ
    );
    """
    
    # 2. Add columns to audit_events if they do not exist
    alter_audit_events_query = """
    ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS actor VARCHAR(64);
    ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS target VARCHAR(255);
    ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS detail JSONB;
    """
    
    # 3. Add columns to users table if they do not exist
    alter_users_query = """
    ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name VARCHAR(255);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT true;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS created_by INTEGER REFERENCES users(id);
    """
    
    # 4. Backfill full_name in users table
    backfill_users_query = "UPDATE users SET full_name = INITCAP(username) WHERE full_name IS NULL;"
    
    # 5. Create integrations table
    create_integrations_table_query = """
    CREATE TABLE IF NOT EXISTS integration_settings (
        integration_key VARCHAR(64) PRIMARY KEY,
        config JSONB NOT NULL DEFAULT '{}'::jsonb,
        secrets_encrypted BYTEA,
        enabled BOOLEAN NOT NULL DEFAULT false,
        last_test_status VARCHAR(16) DEFAULT 'never',
        last_test_message TEXT,
        last_tested_at TIMESTAMPTZ,
        updated_at TIMESTAMPTZ DEFAULT NOW(),
        updated_by INTEGER REFERENCES users(id)
    );
    """
    
    # 6. Add scanner column to findings if it doesn't exist
    alter_findings_query = """
    ALTER TABLE findings ADD COLUMN IF NOT EXISTS scanner VARCHAR(50) NOT NULL DEFAULT 'unknown';
    """
    
    seed_integrations_query = """
    INSERT INTO integration_settings (integration_key, config, secrets_encrypted, enabled)
    VALUES 
        ('cavelo', '{}'::jsonb, NULL, false),
        ('autotask', '{}'::jsonb, NULL, false),
        ('slack', '{}'::jsonb, NULL, false)
    ON CONFLICT (integration_key) DO NOTHING;
    """

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_users_table_query)
                cur.execute(alter_audit_events_query)
                cur.execute(alter_users_query)
                cur.execute(backfill_users_query)
                cur.execute(alter_findings_query)
                cur.execute(create_integrations_table_query)
                cur.execute(seed_integrations_query)
            conn.commit()
            
            # Check if users table is empty
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM users;")
                count = cur.fetchone()[0]
                if count == 0:
                    logger.info("Users table is empty. Seeding default users...")
                    default_users = [
                        ("admin", "admin", True),
                        ("manager", "manager", True),
                        ("analyst", "analyst", True)
                    ]
                    for username, role, must_change in default_users:
                        hashed = pwd_context.hash("changeme")
                        cur.execute(
                            "INSERT INTO users (username, password_hash, role, must_change_password, full_name) VALUES (%s, %s, %s, %s, INITCAP(%s));",
                            (username, hashed, role, must_change, username)
                        )
                    conn.commit()
                    logger.info("Default users seeded successfully.")
    except Exception as e:
        logger.error(f"Error during startup database migration/seeding: {e}")

    # Check and generate INTEGRATION_SECRET_KEY
    key = os.getenv("INTEGRATION_SECRET_KEY")
    env_path = "/root/vuln-triage/secrets/.env"
    if not key:
        key_found = False
        if os.path.exists(env_path):
            try:
                with open(env_path, "r") as f:
                    for line in f:
                        if line.strip().startswith("INTEGRATION_SECRET_KEY="):
                            key_found = True
                            break
            except Exception:
                pass
        
        if not key_found:
            from cryptography.fernet import Fernet
            new_key = Fernet.generate_key().decode()
            logger.warning("generated new INTEGRATION_SECRET_KEY — do not lose .env")
            try:
                os.makedirs(os.path.dirname(env_path), exist_ok=True)
                with open(env_path, "a") as f:
                    f.write(f"\nINTEGRATION_SECRET_KEY={new_key}\n")
            except Exception as e:
                logger.error(f"Failed to append key to .env: {e}")


@app.on_event("shutdown")
def shutdown_event():
    scheduler.shutdown()
    logger.info("APScheduler stopped.")

# Auth Models
class LoginRequest(BaseModel):
    username: str
    password: str

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str

# require_role Dependency
def require_role(min_role: str):
    def dependency(request: Request):
        user = getattr(request.state, "user", None)
        if not user:
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        user_role = user["role"]
        if ROLE_hierarchy.get(user_role, 0) < ROLE_hierarchy.get(min_role, 0):
            raise HTTPException(status_code=403, detail="Forbidden: insufficient permissions")
        return user
    return dependency

# Auth Middleware
@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    
    # Exempted public routes (don't require auth at all)
    exempt_paths = {"/login.html", "/api/login", "/api/me", "/healthz"}
    
    is_static = (
        path.startswith("/static/") or 
        path.endswith((".js", ".css", ".png", ".jpg", ".ico", ".svg"))
    )
    
    if path in exempt_paths or is_static:
        return await call_next(request)
        
    # Authenticate session
    cookie = request.cookies.get("session")
    user = None
    if cookie:
        try:
            unsigned = signer.unsign(cookie).decode()
            session_data = json.loads(unsigned)
            # Verify user exists in db and check must_change_password and active status
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT id, username, role, must_change_password, active FROM users WHERE id = %s;", (session_data["user_id"],))
                    row = cur.fetchone()
            if row and row[4] is True:
                user = {
                    "id": row[0],
                    "username": row[1],
                    "role": row[2],
                    "must_change_password": row[3]
                }
        except Exception:
            pass
            
    # Not authenticated
    if not user:
        if path.endswith(".html") or path == "/":
            return RedirectResponse(url="/login.html")
        else:
            return Response(content='{"detail":"Not authenticated"}', status_code=401, media_type="application/json")
            
    # Authenticated, but must change password
    if user["must_change_password"]:
        allowed_paths = {"/change-password.html", "/api/change-password", "/api/logout", "/api/me"}
        if path not in allowed_paths:
            if path.endswith(".html") or path == "/":
                return RedirectResponse(url="/change-password.html")
            else:
                return Response(content='{"detail":"Must change password"}', status_code=403, media_type="application/json")
                
    # Store user in request state for endpoints/dependencies
    request.state.user = user
    return await call_next(request)

# Root Redirect Route
@app.get("/")
def read_root():
    return RedirectResponse(url="/brief.html")

# Auth Endpoints
@app.post("/api/login")
async def login(payload: LoginRequest, response: Response, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    
    # Check if IP is blocked
    if client_ip in blocked_ips:
        block_until = blocked_ips[client_ip]
        if now < block_until:
            raise HTTPException(
                status_code=429,
                detail=f"Too many failed login attempts. Locked out. Try again in {int(block_until - now)} seconds."
            )
        else:
            del blocked_ips[client_ip]
            
    username = payload.username
    password = payload.password
            
    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password are required")
        
    # Authenticate user
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, username, password_hash, role, must_change_password, active FROM users WHERE username = %s;", (username,))
            row = cur.fetchone()
            
    if not row or not row[5] or not pwd_context.verify(password, row[2]):
        # Audit login failure
        try:
            with get_db_connection() as conn:
                with conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "INSERT INTO audit_events (actor, action, target, detail, target_type, target_id, details) VALUES ('anonymous', 'login_failed', 'session', %s, 'session', 'login', %s);",
                            (json.dumps({"username": username}), json.dumps({"username": username}))
                        )
        except Exception as e:
            logger.error(f"Failed to log login failure audit: {e}")
            
        # Log failed attempt for rate limiting
        attempts = failed_login_attempts.get(client_ip, [])
        attempts = [t for t in attempts if now - t < 60]
        attempts.append(now)
        failed_login_attempts[client_ip] = attempts
        
        if len(attempts) >= 5:
            blocked_ips[client_ip] = now + 60
            if client_ip in failed_login_attempts:
                del failed_login_attempts[client_ip]
            raise HTTPException(status_code=429, detail="Too many failed login attempts. Locked out for 60 seconds.")
            
        raise HTTPException(status_code=401, detail="Invalid credentials")
        
    user_id, db_username, db_hash, role, must_change, db_active = row
    
    # Successful login, clear failed attempts
    if client_ip in failed_login_attempts:
        del failed_login_attempts[client_ip]
    if client_ip in blocked_ips:
        del blocked_ips[client_ip]
        
    # Update last login time and audit login success
    try:
        with get_db_connection() as conn:
            with conn:
                with conn.cursor() as cur:
                    cur.execute("UPDATE users SET last_login_at = NOW() WHERE id = %s;", (user_id,))
                    cur.execute(
                        "INSERT INTO audit_events (actor, action, target, detail, target_type, target_id, details) VALUES (%s, 'login_success', 'session', '{}'::jsonb, 'session', 'login', '{}'::jsonb);",
                        (db_username,)
                    )
    except Exception as e:
        logger.error(f"Failed to update last login time: {e}")
        
    # Create signed session cookie
    session_data = json.dumps({"user_id": user_id, "role": role, "ts": int(time.time())})
    signed_value = signer.sign(session_data.encode()).decode()
    response.set_cookie(
        key="session",
        value=signed_value,
        httponly=True,
        secure=False,
        samesite="lax"
    )
    
    return {"role": role, "must_change_password": must_change}

@app.post("/api/logout")
def logout(response: Response, request: Request):
    # Retrieve user from session if possible to log the actor
    username = "anonymous"
    cookie = request.cookies.get("session")
    if cookie:
        try:
            unsigned = signer.unsign(cookie).decode()
            session_data = json.loads(unsigned)
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT username, active FROM users WHERE id = %s;", (session_data["user_id"],))
                    row = cur.fetchone()
                    if row and row[1]:
                        username = row[0]
        except Exception:
            pass
            
    # Audit logout
    try:
        with get_db_connection() as conn:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO audit_events (actor, action, target, detail, target_type, target_id, details) VALUES (%s, 'logout', 'session', '{}'::jsonb, 'session', 'logout', '{}'::jsonb);",
                        (username,)
                    )
    except Exception as e:
        logger.error(f"Failed to log logout audit: {e}")

    response.delete_cookie("session", httponly=True, secure=False, samesite="lax")
    return {"status": "success"}

@app.get("/api/me")
def get_me(request: Request):
    cookie = request.cookies.get("session")
    if not cookie:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        unsigned = signer.unsign(cookie).decode()
        session_data = json.loads(unsigned)
    except (BadSignature, Exception):
        raise HTTPException(status_code=401, detail="Not authenticated")
        
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT username, role, must_change_password, active FROM users WHERE id = %s;", (session_data["user_id"],))
            row = cur.fetchone()
            
    if not row or not row[3]:
        raise HTTPException(status_code=401, detail="User not found or inactive")
        
    return {
        "username": row[0],
        "role": row[1],
        "must_change_password": row[2]
    }

@app.post("/api/change-password")
async def change_password(payload: ChangePasswordRequest, request: Request):
    cookie = request.cookies.get("session")
    if not cookie:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        unsigned = signer.unsign(cookie).decode()
        session_data = json.loads(unsigned)
    except (BadSignature, Exception):
        raise HTTPException(status_code=401, detail="Not authenticated")
        
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, password_hash, username, active FROM users WHERE id = %s;", (session_data["user_id"],))
            row = cur.fetchone()
            
    if not row or not row[3]:
        raise HTTPException(status_code=401, detail="User not found or inactive")
        
    user_id, db_hash, username, db_active = row
    
    old_password = payload.old_password
    new_password = payload.new_password
            
    if not old_password or not new_password:
        raise HTTPException(status_code=400, detail="old_password and new_password are required")
        
    if not pwd_context.verify(old_password, db_hash):
        raise HTTPException(status_code=400, detail="Invalid old password")
        
    new_hash = pwd_context.hash(new_password)
    try:
        with get_db_connection() as conn:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE users SET password_hash = %s, must_change_password = false WHERE id = %s;",
                        (new_hash, user_id)
                    )
                    cur.execute(
                        "INSERT INTO audit_events (actor, action, target, detail, target_type, target_id, details) VALUES (%s, 'password_change_self', %s, '{}'::jsonb, 'user', %s, '{}'::jsonb);",
                        (username, f"user:{username}", str(user_id))
                    )
    except Exception as e:
        logger.error(f"Failed to update password: {e}")
        raise HTTPException(status_code=500, detail="Failed to update password")
        
    return {"status": "success", "message": "Password changed successfully"}

# Endpoints

@app.get("/healthz")
def healthz():
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1;")
                cur.fetchone()
        return {"status": "ok", "database": "connected"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database connection error: {e}")

@app.get("/approve/{triage_id}")
def approve_finding(triage_id: int, user: dict = Depends(require_role("manager"))):
    logger.info(f"Received manual approval for triage_id={triage_id}")
    
    # Check triage record existence & status
    check_query = "SELECT status FROM triage WHERE id = %s;"
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(check_query, (triage_id,))
                res = cur.fetchone()
                if not res:
                    raise HTTPException(status_code=404, detail="Triage record not found")
                
                status = res[0]
                if status != 'pending':
                    raise HTTPException(status_code=400, detail=f"Cannot approve record in '{status}' status")
                
                # Update status
                update_query = "UPDATE triage SET status = 'approved', updated_at = NOW() WHERE id = %s;"
                with conn:
                    execute_write(
                        conn,
                        action="approve",
                        target_type="triage",
                        target_id=triage_id,
                        details={"old_status": "pending", "new_status": "approved"},
                        write_query=update_query,
                        write_params=(triage_id,),
                        actor=user["username"],
                        target=f"triage:{triage_id}",
                        detail={"old_status": "pending", "new_status": "approved"}
                    )
        return {"status": "success", "message": f"Triage ID {triage_id} approved"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Approval error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/reject/{triage_id}")
def reject_finding(triage_id: int, user: dict = Depends(require_role("manager"))):
    logger.info(f"Received manual rejection for triage_id={triage_id}")
    
    check_query = "SELECT status FROM triage WHERE id = %s;"
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(check_query, (triage_id,))
                res = cur.fetchone()
                if not res:
                    raise HTTPException(status_code=404, detail="Triage record not found")
                
                status = res[0]
                if status != 'pending':
                    raise HTTPException(status_code=400, detail=f"Cannot reject record in '{status}' status")
                
                # Update status
                update_query = "UPDATE triage SET status = 'rejected', updated_at = NOW() WHERE id = %s;"
                with conn:
                    execute_write(
                        conn,
                        action="reject",
                        target_type="triage",
                        target_id=triage_id,
                        details={"old_status": "pending", "new_status": "rejected"},
                        write_query=update_query,
                        write_params=(triage_id,),
                        actor=user["username"],
                        target=f"triage:{triage_id}",
                        detail={"old_status": "pending", "new_status": "rejected"}
                    )
        return {"status": "success", "message": f"Triage ID {triage_id} rejected"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Rejection error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

def get_severity_from_cvss(cvss):
    if cvss >= 9.0: return 'Critical'
    elif cvss >= 7.0: return 'High'
    elif cvss >= 4.0: return 'Medium'
    return 'Low'

@app.post("/upload")
async def upload_csv(file: UploadFile = File(...), source: str = Form(...), user: dict = Depends(require_role("analyst"))):
    if source not in ['cavelo', 'blackpoint']:
        return {"asset_count": 0, "finding_count": 0, "errors": ["Invalid source. Must be 'cavelo' or 'blackpoint'."]}
        
    try:
        # Wrap stream
        text_wrapper = codecs.getreader("utf-8")(file.file)
        
        # Parse based on source
        if source == 'cavelo':
            parsed_items = list(cavelo.parse(text_wrapper))
        else:
            parsed_items = list(blackpoint.parse(text_wrapper))
            
        assets_seen = set()
        finding_ids = []
        
        # Save to DB
        with get_db_connection() as conn:
            with conn:
                # Sync sequences first to prevent pkey constraint violations
                with conn.cursor() as cur:
                    cur.execute("SELECT setval('assets_id_seq', COALESCE(MAX(id), 1)) FROM assets;")
                    cur.execute("SELECT setval('findings_id_seq', COALESCE(MAX(id), 1)) FROM findings;")
                
                # Insert the main upload audit log before writing data
                execute_write(
                    conn,
                    action="csv_upload",
                    target_type="source",
                    target_id=source,
                    details={
                        "filename": file.filename,
                        "asset_count": 0,
                        "finding_count": len(parsed_items)
                    },
                    write_query="SELECT 1;",
                    write_params=(),
                    actor=user["username"],
                    target=f"source:{source}",
                    detail={
                        "filename": file.filename,
                        "asset_count": 0,
                        "finding_count": len(parsed_items)
                    }
                )
                
                for item in parsed_items:
                    asset_hostname = item["asset_hostname"]
                    if not asset_hostname:
                        continue
                    assets_seen.add(asset_hostname)
                    
                    # 1. Upsert asset
                    execute_write(
                        conn,
                        action="upsert_asset",
                        target_type="asset",
                        target_id=asset_hostname,
                        details={"source": f"csv_upload_{source}"},
                        write_query="""
                            INSERT INTO assets (hostname, environment, business_crit)
                            VALUES (%s, 'dev', 1)
                            ON CONFLICT (hostname)
                            DO UPDATE SET environment = COALESCE(assets.environment, EXCLUDED.environment)
                            RETURNING id;
                        """,
                        write_params=(asset_hostname,),
                        actor=user["username"],
                        target=f"asset:{asset_hostname}",
                        detail={"source": f"csv_upload_{source}"}
                    )
                    
                    with conn.cursor() as cur:
                        cur.execute("SELECT id FROM assets WHERE hostname = %s;", (asset_hostname,))
                        asset_id = cur.fetchone()[0]
                        
                    # 2. Upsert finding
                    cve_db = item["cve"] if item["cve"] else ''
                    plugin_id_db = item["plugin_id"] if item["plugin_id"] else ''
                    cvss_base = float(item["cvss_base"])
                    severity = get_severity_from_cvss(cvss_base)
                    detected_at = item["first_seen"] if item["first_seen"] else (item["last_seen"] if item["last_seen"] else datetime.now())
                    
                    finding_query = """
                        INSERT INTO findings (asset_id, cve, plugin_id, title, description, cvss_base, cvss_vector, severity, detected_at, first_seen, last_seen, vendor_advisory, raw, scanner)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (asset_id, plugin_id, cve)
                        DO UPDATE SET last_seen = EXCLUDED.last_seen, raw = EXCLUDED.raw, scanner = EXCLUDED.scanner;
                    """
                    
                    execute_write(
                        conn,
                        action="upsert_finding",
                        target_type="finding",
                        target_id=f"{asset_id}:{cve_db}:{plugin_id_db}",
                        details={"source": f"csv_upload_{source}"},
                        write_query=finding_query,
                        write_params=(
                            asset_id,
                            cve_db,
                            plugin_id_db,
                            item["title"],
                            item["raw"].get("description", item["title"]),
                            cvss_base,
                            item["cvss_vector"],
                            severity,
                            detected_at,
                            item["first_seen"],
                            item["last_seen"],
                            item["vendor_advisory"],
                            json.dumps(item["raw"]),
                            item.get("scanner", "unknown")
                        ),
                        actor=user["username"],
                        target=f"finding:{asset_id}:{cve_db}:{plugin_id_db}",
                        detail={"source": f"csv_upload_{source}"}
                    )
                    
                    with conn.cursor() as cur:
                        cur.execute("SELECT id FROM findings WHERE asset_id = %s AND plugin_id = %s AND cve = %s;", (asset_id, plugin_id_db, cve_db))
                        finding_id = cur.fetchone()[0]
                        finding_ids.append(finding_id)
                
                # Trigger batch enrichment and correlation
                if finding_ids:
                    enrich_batch(conn, finding_ids)
                    correlate_batch(conn, finding_ids)
                    
                # Log final counts audit event
                execute_write(
                    conn,
                    action="csv_upload_complete",
                    target_type="source",
                    target_id=source,
                    details={
                        "filename": file.filename,
                        "asset_count": len(assets_seen),
                        "finding_count": len(finding_ids)
                    },
                    write_query="SELECT 1;",
                    write_params=(),
                    actor=user["username"],
                    target=f"source:{source}",
                    detail={
                        "filename": file.filename,
                        "asset_count": len(assets_seen),
                        "finding_count": len(finding_ids)
                    }
                )
                
        return {
            "asset_count": len(assets_seen),
            "finding_count": len(finding_ids),
            "errors": []
        }
    except Exception as e:
        logger.error(f"Error handling CSV upload: {e}")
        return {
            "asset_count": 0,
            "finding_count": 0,
            "errors": [str(e)]
        }

class BulkActionRequest(BaseModel):
    triage_ids: List[int]
    approver: str = "web-ui"

@app.get("/api/findings")
def get_findings_api(
    source: str = Query("all"),
    env: str = Query("all"),
    severity: str = Query("all"),
    in_kev: str = Query("any"),
    has_exploit: str = Query("any"),
    status: str = Query("pending"),
    q: str = Query(""),
    sort: str = Query("score_desc"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user: dict = Depends(require_role("analyst"))
):
    try:
        conditions = []
        params = []

        # 1. Source filter using new scanner column
        if source != "all":
            conditions.append("f.scanner = %s")
            params.append(source)

        # 2. Env filter
        if env != "all":
            conditions.append("a.environment = %s")
            params.append(env)

        # 3. Severity filter
        if severity != "all":
            if severity == "critical":
                conditions.append("f.cvss_base >= 9.0")
            elif severity == "high":
                conditions.append("f.cvss_base >= 7.0 AND f.cvss_base < 9.0")
            elif severity == "medium":
                conditions.append("f.cvss_base >= 4.0 AND f.cvss_base < 7.0")
            elif severity == "low":
                conditions.append("f.cvss_base < 4.0")

        # 4. KEV filter
        if in_kev != "any":
            if in_kev == "true":
                conditions.append("e.in_kev = TRUE")
            elif in_kev == "false":
                conditions.append("(e.in_kev = FALSE OR e.in_kev IS NULL)")

        # 5. Exploit filter
        if has_exploit != "any":
            if has_exploit == "true":
                conditions.append("e.public_exploit = TRUE")
            elif has_exploit == "false":
                conditions.append("(e.public_exploit = FALSE OR e.public_exploit IS NULL)")

        # 6. Status filter
        if status != "all":
            conditions.append("t.status = %s")
            params.append(status)

        # 7. Search query
        if q.strip():
            conditions.append("(f.cve ILIKE %s OR a.hostname ILIKE %s OR f.title ILIKE %s)")
            search_param = f"%{q.strip()}%"
            params.extend([search_param, search_param, search_param])

        # 8. Sort mapping
        sort_map = {
            "score_desc": "MAX(t.priority_score) DESC, MAX(f.cvss_base) DESC, f.cve DESC",
            "score_asc": "MAX(t.priority_score) ASC, MAX(f.cvss_base) ASC, f.cve ASC",
            "cvss_desc": "MAX(f.cvss_base) DESC, MAX(t.priority_score) DESC, f.cve DESC",
            "cvss_asc": "MAX(f.cvss_base) ASC, MAX(t.priority_score) ASC, f.cve ASC",
            "epss_desc": "COALESCE(e.epss, 0.0) DESC, MAX(t.priority_score) DESC, f.cve DESC",
            "last_seen_desc": "MAX(f.last_seen) DESC, MAX(t.priority_score) DESC, f.cve DESC",
            "cve_desc": "f.cve DESC, MAX(t.priority_score) DESC",
            "cve_asc": "f.cve ASC, MAX(t.priority_score) DESC"
        }
        order_by_clause = sort_map.get(sort, "MAX(t.priority_score) DESC, MAX(f.cvss_base) DESC, f.cve DESC")

        base_where = " WHERE " + " AND ".join(conditions) if conditions else ""

        # Total query for status (grouped)
        total_query = """
            SELECT COUNT(*) FROM (
                SELECT 1 
                FROM triage t 
                JOIN findings f ON t.finding_id = f.id 
                JOIN assets a ON f.asset_id = a.id
                {status_where}
                GROUP BY f.asset_id, f.cve
            ) AS sub
        """
        if status != "all":
            total_params = [status]
            total_query = total_query.format(status_where="WHERE t.status = %s")
        else:
            total_params = []
            total_query = total_query.format(status_where="")

        # Filtered query count (grouped)
        filtered_query = f"""
            SELECT COUNT(*) FROM (
                SELECT 1 
                FROM triage t 
                JOIN findings f ON t.finding_id = f.id 
                JOIN assets a ON f.asset_id = a.id
                LEFT JOIN enrichment e ON f.cve = e.cve
                {base_where}
                GROUP BY f.asset_id, f.cve
            ) AS sub
        """

        # Rows query
        rows_query = f"""
            SELECT 
                f.cve,
                f.asset_id,
                a.hostname,
                a.environment AS env,
                a.business_crit,
                a.owner_team,
                ARRAY_AGG(DISTINCT f.scanner ORDER BY f.scanner) AS sources,
                MAX(f.cvss_base) AS cvss,
                COALESCE(e.epss, 0.0) AS epss,
                COALESCE(e.in_kev, FALSE) AS in_kev,
                COALESCE(e.public_exploit, FALSE) AS has_exploit,
                MAX(t.priority_score) AS score,
                (ARRAY_AGG(t.status ORDER BY CASE t.status WHEN 'pending' THEN 1 WHEN 'approved' THEN 2 WHEN 'rejected' THEN 3 WHEN 'ticketed' THEN 4 ELSE 5 END))[1] AS status,
                (ARRAY_AGG(f.title ORDER BY LENGTH(f.title) DESC, f.title))[1] AS title,
                (ARRAY_AGG(f.description ORDER BY LENGTH(f.description) DESC, f.description))[1] AS description,
                (ARRAY_AGG(f.vendor_advisory ORDER BY LENGTH(COALESCE(f.vendor_advisory, '')) DESC, f.vendor_advisory))[1] AS vendor_advisory,
                MAX(f.last_seen) AS last_seen,
                ARRAY_AGG(t.id) AS triage_ids,
                ARRAY_AGG(f.id) AS finding_ids,
                (jsonb_agg(f.raw)->0) AS raw
            FROM triage t
            JOIN findings f ON t.finding_id = f.id
            JOIN assets a ON f.asset_id = a.id
            LEFT JOIN enrichment e ON f.cve = e.cve
            {base_where}
            GROUP BY f.asset_id, f.cve, a.hostname, a.environment, a.business_crit, a.owner_team, e.epss, e.in_kev, e.public_exploit
            ORDER BY {order_by_clause}
            LIMIT %s OFFSET %s
        """
        rows_params = params + [limit, offset]

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # 1. Total
                cur.execute(total_query, total_params)
                total = cur.fetchone()[0]

                # 2. Filtered
                cur.execute(filtered_query, params)
                filtered = cur.fetchone()[0]

                # 3. Rows
                cur.execute(rows_query, rows_params)
                cols = [desc[0] for desc in cur.description]
                db_rows = cur.fetchall()
                rows = []
                for db_row in db_rows:
                    row_dict = dict(zip(cols, db_row))
                    if row_dict["last_seen"]:
                        row_dict["last_seen"] = row_dict["last_seen"].isoformat()
                    row_dict["cvss"] = float(row_dict["cvss"]) if row_dict["cvss"] is not None else 0.0
                    row_dict["epss"] = float(row_dict["epss"]) if row_dict["epss"] is not None else 0.0
                    row_dict["score"] = float(row_dict["score"]) if row_dict["score"] is not None else 0.0
                    
                    # Convert psycopg2 arrays to list of int
                    row_dict["triage_ids"] = [int(x) for x in row_dict["triage_ids"]]
                    row_dict["finding_ids"] = [int(x) for x in row_dict["finding_ids"]]
                    row_dict["triage_id"] = row_dict["triage_ids"][0]
                    row_dict["finding_id"] = row_dict["finding_ids"][0]
                    
                    if isinstance(row_dict["raw"], str):
                        try:
                            row_dict["raw"] = json.loads(row_dict["raw"])
                        except Exception:
                            pass
                    rows.append(row_dict)

        return {
            "total": total,
            "filtered": filtered,
            "rows": rows
        }
    except Exception as e:
        logger.error(f"Error querying /api/findings: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/findings/bulk/approve")
def bulk_approve(req: BulkActionRequest, user: dict = Depends(require_role("manager"))):
    triage_ids = req.triage_ids
    approver = req.approver
    if not triage_ids:
        return {"status": "success", "approved_count": 0, "overflow_count": 0}
        
    try:
        with get_db_connection() as conn:
            with conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT COUNT(*) FROM tickets WHERE created_at >= NOW() - INTERVAL '24 hours';")
                    tickets_last_24h = cur.fetchone()[0]
                    cur.execute("SELECT COUNT(*) FROM triage WHERE status = 'approved';")
                    approved_count = cur.fetchone()[0]
                
                MAX_TICKETS_PER_DAY = 25
                allowed = max(0, MAX_TICKETS_PER_DAY - tickets_last_24h - approved_count)
                
                approved_ids = []
                overflow_count = 0
                
                for tid in triage_ids:
                    with conn.cursor() as cur:
                        cur.execute("SELECT status FROM triage WHERE id = %s;", (tid,))
                        res = cur.fetchone()
                    if not res or res[0] != 'pending':
                        continue
                        
                    if len(approved_ids) < allowed:
                        approved_ids.append(tid)
                    else:
                        overflow_count += 1
                        
                if approved_ids:
                    update_query = "UPDATE triage SET status = 'approved', updated_at = NOW() WHERE id = ANY(%s);"
                    execute_write(
                        conn,
                        action="bulk_approve",
                        target_type="triage_batch",
                        target_id=len(approved_ids),
                        details={"approved_ids": approved_ids, "approver": approver},
                        write_query=update_query,
                        write_params=(approved_ids,),
                        actor=user["username"],
                        target=f"triage_batch:{len(approved_ids)}",
                        detail={"approved_ids": approved_ids, "approver": approver, "overflow_count": overflow_count}
                    )
                        
        return {
            "status": "success",
            "approved_count": len(approved_ids),
            "overflow_count": overflow_count
        }
    except Exception as e:
        logger.error(f"Bulk approval error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/findings/bulk/reject")
def bulk_reject(req: BulkActionRequest, user: dict = Depends(require_role("manager"))):
    triage_ids = req.triage_ids
    approver = req.approver
    if not triage_ids:
        return {"status": "success", "rejected_count": 0}
        
    try:
        rejected_ids = []
        with get_db_connection() as conn:
            with conn:
                for tid in triage_ids:
                    with conn.cursor() as cur:
                        cur.execute("SELECT status FROM triage WHERE id = %s;", (tid,))
                        res = cur.fetchone()
                    if not res or res[0] != 'pending':
                        continue
                    rejected_ids.append(tid)
                    
                if rejected_ids:
                    update_query = "UPDATE triage SET status = 'rejected', updated_at = NOW() WHERE id = ANY(%s);"
                    execute_write(
                        conn,
                        action="bulk_reject",
                        target_type="triage_batch",
                        target_id=len(rejected_ids),
                        details={"rejected_ids": rejected_ids, "approver": approver},
                        write_query=update_query,
                        write_params=(rejected_ids,),
                        actor=user["username"],
                        target=f"triage_batch:{len(rejected_ids)}",
                        detail={"rejected_ids": rejected_ids, "approver": approver}
                    )
                    
        return {
            "status": "success",
            "rejected_count": len(rejected_ids)
        }
    except Exception as e:
        logger.error(f"Bulk rejection error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

class AssetPatchRequest(BaseModel):
    environment: str = None
    business_crit: int = None
    owner_team: str = None
    ip: str = None

@app.get("/api/assets")
def get_assets_api(
    q: str = Query(""),
    env: str = Query("all"),
    sort: str = Query("hostname_asc"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user: dict = Depends(require_role("manager"))
):
    try:
        conditions = []
        params = []

        if q.strip():
            conditions.append("a.hostname ILIKE %s")
            params.append(f"%{q.strip()}%")

        if env != "all":
            conditions.append("a.environment = %s")
            params.append(env)

        base_where = " WHERE " + " AND ".join(conditions) if conditions else ""

        # Sort mapping
        sort_map = {
            "hostname_asc": "a.hostname ASC",
            "finding_count_desc": "finding_count DESC, a.hostname ASC",
            "max_score_desc": "max_score DESC, a.hostname ASC"
        }
        order_by = sort_map.get(sort, "a.hostname ASC")

        count_query = f"SELECT COUNT(*) FROM assets a {base_where}"
        
        rows_query = f"""
            SELECT 
                a.id,
                a.hostname,
                a.ip,
                a.environment,
                a.business_crit,
                a.owner_team,
                COUNT(f.id) AS finding_count,
                COALESCE(MAX(t.priority_score), 0.0) AS max_score
            FROM assets a
            LEFT JOIN findings f ON a.id = f.asset_id
            LEFT JOIN triage t ON f.id = t.finding_id
            {base_where}
            GROUP BY a.id, a.hostname, a.ip, a.environment, a.business_crit, a.owner_team
            ORDER BY {order_by}
            LIMIT %s OFFSET %s
        """
        rows_params = params + [limit, offset]

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(count_query, params)
                total = cur.fetchone()[0]

                cur.execute(rows_query, rows_params)
                cols = [desc[0] for desc in cur.description]
                db_rows = cur.fetchall()
                rows = []
                for db_row in db_rows:
                    row_dict = dict(zip(cols, db_row))
                    row_dict["finding_count"] = int(row_dict["finding_count"])
                    row_dict["max_score"] = float(row_dict["max_score"])
                    rows.append(row_dict)

        return {
            "total": total,
            "rows": rows
        }
    except Exception as e:
        logger.error(f"Error querying /api/assets: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.patch("/api/assets/{asset_id}")
def patch_asset(asset_id: int, req: AssetPatchRequest, user: dict = Depends(require_role("admin"))):
    if req.environment is not None:
        if req.environment not in ('prod', 'staging', 'dev', 'sandbox', 'unknown'):
            raise HTTPException(status_code=400, detail="Invalid environment value")
            
    if req.business_crit is not None:
        if req.business_crit < 1 or req.business_crit > 5:
            raise HTTPException(status_code=400, detail="business_crit must be between 1 and 5")

    try:
        with get_db_connection() as conn:
            with conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT hostname, environment, business_crit, owner_team, ip FROM assets WHERE id = %s;", (asset_id,))
                    old_res = cur.fetchone()
                if not old_res:
                    raise HTTPException(status_code=404, detail="Asset not found")
                
                hostname, old_env, old_crit, old_team, old_ip = old_res
                old_meta = {
                    "environment": old_env,
                    "business_crit": old_crit,
                    "owner_team": old_team,
                    "ip": old_ip
                }

                update_fields = []
                update_params = []
                new_meta = {}

                if req.environment is not None:
                    update_fields.append("environment = %s")
                    update_params.append(req.environment)
                    new_meta["environment"] = req.environment
                else:
                    new_meta["environment"] = old_env

                if req.business_crit is not None:
                    update_fields.append("business_crit = %s")
                    update_params.append(req.business_crit)
                    new_meta["business_crit"] = req.business_crit
                else:
                    new_meta["business_crit"] = old_crit

                if req.owner_team is not None:
                    update_fields.append("owner_team = %s")
                    update_params.append(req.owner_team)
                    new_meta["owner_team"] = req.owner_team
                else:
                    new_meta["owner_team"] = old_team

                if req.ip is not None:
                    update_fields.append("ip = %s")
                    update_params.append(req.ip)
                    new_meta["ip"] = req.ip
                else:
                    new_meta["ip"] = old_ip

                if not update_fields:
                    return {"status": "success", "asset": {**new_meta, "id": asset_id, "hostname": hostname}, "findings_rescored": 0}

                update_fields.append("updated_at = NOW()")
                update_query = f"UPDATE assets SET {', '.join(update_fields)} WHERE id = %s;"
                update_params.append(asset_id)

                with conn.cursor() as cur:
                    cur.execute("SELECT id FROM findings WHERE asset_id = %s;", (asset_id,))
                    finding_ids = [r[0] for r in cur.fetchall()]

                execute_write(
                    conn,
                    action="asset_metadata_updated",
                    target_type="asset",
                    target_id=hostname,
                    details={
                        "old": old_meta,
                        "new": new_meta,
                        "findings_rescored": len(finding_ids)
                    },
                    write_query=update_query,
                    write_params=tuple(update_params),
                    actor=user["username"],
                    target=f"asset:{hostname}",
                    detail={
                        "old": old_meta,
                        "new": new_meta,
                        "findings_rescored": len(finding_ids)
                    }
                )

                if finding_ids:
                    correlate_batch(conn, finding_ids)

        return {
            "status": "success",
            "asset": {
                "id": asset_id,
                "hostname": hostname,
                "ip": new_meta["ip"],
                "environment": new_meta["environment"],
                "business_crit": new_meta["business_crit"],
                "owner_team": new_meta["owner_team"]
            },
            "findings_rescored": len(finding_ids)
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error patching asset: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/assets/bulk/upload")
async def bulk_assets_upload(file: UploadFile = File(...), user: dict = Depends(require_role("admin"))):
    try:
        text_wrapper = codecs.getreader("utf-8")(file.file)
        reader = csv.DictReader(text_wrapper)
        
        required_cols = {'hostname', 'environment', 'business_crit', 'owner_team'}
        if not required_cols.issubset(set(reader.fieldnames or [])):
            return {
                "updated_assets": 0,
                "findings_rescored": 0,
                "errors": ["CSV is missing required headers: hostname, environment, business_crit, owner_team"]
            }

        updated_assets = 0
        rescored_count = 0
        errors = []
        
        with get_db_connection() as conn:
            with conn:
                execute_write(
                    conn,
                    action="assets_bulk_upload_started",
                    target_type="source",
                    target_id=file.filename,
                    details={"filename": file.filename},
                    write_query="SELECT 1;",
                    write_params=(),
                    actor=user["username"],
                    target=f"source:{file.filename}",
                    detail={"filename": file.filename}
                )

                all_finding_ids = []
                
                for row_idx, row in enumerate(reader, start=2):
                    try:
                        hostname = row.get("hostname", "").strip()
                        environment = row.get("environment", "").strip().lower()
                        crit_str = row.get("business_crit", "").strip()
                        owner_team = row.get("owner_team", "").strip()
                        
                        if not hostname:
                            errors.append(f"Row {row_idx}: Missing hostname")
                            continue
                            
                        if environment not in ('prod', 'staging', 'dev', 'sandbox', 'unknown'):
                            errors.append(f"Row {row_idx}: Invalid environment '{environment}'")
                            continue
                            
                        try:
                            business_crit = int(crit_str)
                            if business_crit < 1 or business_crit > 5:
                                raise ValueError()
                        except ValueError:
                            errors.append(f"Row {row_idx}: Invalid business_crit '{crit_str}' (must be 1-5)")
                            continue
                            
                        upsert_query = """
                            INSERT INTO assets (hostname, environment, business_crit, owner_team, updated_at)
                            VALUES (%s, %s, %s, %s, NOW())
                            ON CONFLICT (hostname)
                            DO UPDATE SET environment = EXCLUDED.environment,
                                          business_crit = EXCLUDED.business_crit,
                                          owner_team = EXCLUDED.owner_team,
                                          updated_at = NOW()
                            RETURNING id;
                        """
                        execute_write(
                            conn,
                            action="upsert_asset_bulk",
                            target_type="asset",
                            target_id=hostname,
                            details={"environment": environment, "business_crit": business_crit, "owner_team": owner_team},
                            write_query=upsert_query,
                            write_params=(hostname, environment, business_crit, owner_team),
                            actor=user["username"],
                            target=f"asset:{hostname}",
                            detail={"environment": environment, "business_crit": business_crit, "owner_team": owner_team}
                        )
                        
                        with conn.cursor() as cur:
                            cur.execute("SELECT id FROM assets WHERE hostname = %s;", (hostname,))
                            asset_id = cur.fetchone()[0]
                            
                        with conn.cursor() as cur:
                            cur.execute("SELECT id FROM findings WHERE asset_id = %s;", (asset_id,))
                            finding_ids = [r[0] for r in cur.fetchall()]
                            all_finding_ids.extend(finding_ids)
                            
                        updated_assets += 1
                    except Exception as e:
                        errors.append(f"Row {row_idx}: Unexpected error: {str(e)}")
                        
                if all_finding_ids:
                    all_finding_ids = list(set(all_finding_ids))
                    correlate_batch(conn, all_finding_ids)
                    rescored_count = len(all_finding_ids)

                execute_write(
                    conn,
                    action="assets_bulk_upload_complete",
                    target_type="source",
                    target_id=file.filename,
                    details={
                        "updated_assets": updated_assets,
                        "findings_rescored": rescored_count,
                        "errors_count": len(errors)
                    },
                    write_query="SELECT 1;",
                    write_params=(),
                    actor=user["username"],
                    target=f"source:{file.filename}",
                    detail={
                        "updated_assets": updated_assets,
                        "findings_rescored": rescored_count,
                        "errors_count": len(errors)
                    }
                )

        return {
            "status": "success",
            "updated_assets": updated_assets,
            "findings_rescored": rescored_count,
            "errors": errors
        }
    except Exception as e:
        logger.error(f"Error handling bulk assets upload: {e}")
        return {
            "updated_assets": 0,
            "findings_rescored": 0,
            "errors": [str(e)]
        }

@app.post("/api/admin/reset")
def reset_system(request: Request, user: dict = Depends(require_role("admin"))):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM findings;")
                findings_n = cur.fetchone()[0]
                cur.execute("SELECT COUNT(*) FROM triage;")
                triage_n = cur.fetchone()[0]
                cur.execute("SELECT COUNT(*) FROM tickets;")
                tickets_n = cur.fetchone()[0]
                cur.execute("SELECT COUNT(*) FROM enrichment;")
                enrichment_n = cur.fetchone()[0]
                cur.execute("SELECT COUNT(*) FROM assets;")
                assets_n = cur.fetchone()[0]
                
            # Perform truncate inside a transaction
            with conn:
                with conn.cursor() as cur:
                    cur.execute("TRUNCATE findings, triage, tickets, enrichment, assets RESTART IDENTITY CASCADE;")
                    cur.execute(
                        "INSERT INTO audit_events (actor, action, target, detail, target_type, target_id, details) VALUES (%s, 'system_reset', 'all', '{}'::jsonb, 'system', 'all', '{}'::jsonb);",
                        (user["username"],)
                    )
                    
        return {
            "wiped": {
                "findings": findings_n,
                "triage": triage_n,
                "tickets": tickets_n,
                "enrichment": enrichment_n,
                "assets": assets_n
            }
        }
    except Exception as e:
        logger.error(f"Error resetting system: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# User creation/update request models
class UserCreateRequest(BaseModel):
    username: str
    full_name: str
    role: str
    password: str = None

class UserUpdateRequest(BaseModel):
    full_name: str = None
    role: str = None
    active: bool = None
    password: str = None

@app.get("/api/admin/users")
def list_admin_users(user: dict = Depends(require_role("admin"))):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT u1.id, u1.username, u1.full_name, u1.role, u1.active, 
                           u1.must_change_password, u1.last_login_at, u1.created_at, 
                           u2.username AS created_by_username
                    FROM users u1
                    LEFT JOIN users u2 ON u1.created_by = u2.id
                    ORDER BY u1.created_at DESC;
                    """
                )
                rows = cur.fetchall()
                
                users_list = []
                for r in rows:
                    users_list.append({
                        "id": r[0],
                        "username": r[1],
                        "full_name": r[2],
                        "role": r[3],
                        "active": r[4],
                        "must_change_password": r[5],
                        "last_login_at": r[6].isoformat() if r[6] else None,
                        "created_at": r[7].isoformat() if r[7] else None,
                        "created_by_username": r[8]
                    })
                return {"rows": users_list}
    except Exception as e:
        logger.error(f"Error fetching users: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/admin/users")
def create_admin_user(req: UserCreateRequest, user: dict = Depends(require_role("admin"))):
    if req.role not in ('admin', 'manager', 'analyst'):
        raise HTTPException(status_code=400, detail="Invalid role. Must be 'admin', 'manager', or 'analyst'.")
    if not req.username.strip():
        raise HTTPException(status_code=400, detail="Username cannot be empty.")
    if not req.full_name.strip():
        raise HTTPException(status_code=400, detail="Full name cannot be empty.")
        
    password = req.password if (req.password and req.password.strip()) else "changeme"
    hashed = pwd_context.hash(password)
    
    try:
        with get_db_connection() as conn:
            with conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT id FROM users WHERE username = %s;", (req.username.strip(),))
                    if cur.fetchone():
                        raise HTTPException(status_code=400, detail=f"Username '{req.username}' already exists.")
                    
                    cur.execute(
                        """
                        INSERT INTO users (username, password_hash, role, must_change_password, full_name, created_by)
                        VALUES (%s, %s, %s, true, %s, %s)
                        RETURNING id, username, full_name, role, active, must_change_password, created_at;
                        """,
                        (req.username.strip(), hashed, req.role, req.full_name.strip(), user["id"])
                    )
                    new_user_row = cur.fetchone()
                    
                    cur.execute(
                        """
                        INSERT INTO audit_events (actor, action, target, detail, target_type, target_id, details)
                        VALUES (%s, 'user_created', %s, %s, %s, %s, %s);
                        """,
                        (
                            user["username"], 
                            f"user:{req.username.strip()}", 
                            json.dumps({"username": req.username.strip(), "role": req.role, "full_name": req.full_name.strip()}), 
                            "user", 
                            str(new_user_row[0]), 
                            json.dumps({"username": req.username.strip(), "role": req.role, "full_name": req.full_name.strip()})
                        )
                    )
                    
                    return {
                        "id": new_user_row[0],
                        "username": new_user_row[1],
                        "full_name": new_user_row[2],
                        "role": new_user_row[3],
                        "active": new_user_row[4],
                        "must_change_password": new_user_row[5],
                        "created_at": new_user_row[6].isoformat() if new_user_row[6] else None,
                        "created_by_username": user["username"]
                    }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.patch("/api/admin/users/{user_id}")
def patch_admin_user(user_id: int, req: UserUpdateRequest, user: dict = Depends(require_role("admin"))):
    try:
        with get_db_connection() as conn:
            with conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT id, username, full_name, role, active FROM users WHERE id = %s;", (user_id,))
                    old_row = cur.fetchone()
                    if not old_row:
                        raise HTTPException(status_code=404, detail="User not found")
                        
                    _, db_username, db_fullname, db_role, db_active = old_row
                    
                    if req.active is False and user_id == user["id"]:
                        raise HTTPException(status_code=400, detail="Cannot deactivate yourself.")
                    
                    if req.active is False and db_role == 'admin':
                        cur.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND active = true;")
                        active_admin_count = cur.fetchone()[0]
                        if active_admin_count <= 1:
                            raise HTTPException(status_code=400, detail="Cannot deactivate the last active admin.")
                            
                    if req.role is not None and req.role != 'admin' and db_role == 'admin':
                        cur.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND active = true;")
                        active_admin_count = cur.fetchone()[0]
                        if active_admin_count <= 1:
                            raise HTTPException(status_code=400, detail="Cannot change role of the last active admin.")

                    update_fields = []
                    params = []
                    changes = {}
                    
                    if req.full_name is not None:
                        val = req.full_name.strip()
                        if val != db_fullname:
                            update_fields.append("full_name = %s")
                            params.append(val)
                            changes["full_name"] = {"old": db_fullname, "new": val}
                            
                    if req.role is not None:
                        if req.role not in ('admin', 'manager', 'analyst'):
                            raise HTTPException(status_code=400, detail="Invalid role. Must be 'admin', 'manager', or 'analyst'.")
                        if req.role != db_role:
                            update_fields.append("role = %s")
                            params.append(req.role)
                            changes["role"] = {"old": db_role, "new": req.role}
                            
                    if req.active is not None:
                        if req.active != db_active:
                            update_fields.append("active = %s")
                            params.append(req.active)
                            changes["active"] = {"old": db_active, "new": req.active}
                            
                    if req.password is not None and req.password.strip():
                        hashed = pwd_context.hash(req.password)
                        update_fields.append("password_hash = %s")
                        params.append(hashed)
                        update_fields.append("must_change_password = true")
                        changes["password"] = "changed"
                        
                    if not update_fields:
                        return {"status": "success", "message": "No changes made."}
                        
                    update_query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = %s;"
                    params.append(user_id)
                    cur.execute(update_query, tuple(params))
                    
                    cur.execute(
                        """
                        INSERT INTO audit_events (actor, action, target, detail, target_type, target_id, details)
                        VALUES (%s, 'user_updated', %s, %s, %s, %s, %s);
                        """,
                        (
                            user["username"], 
                            f"user:{db_username}", 
                            json.dumps(changes), 
                            "user", 
                            str(user_id), 
                            json.dumps(changes)
                        )
                    )
                    
                    return {"status": "success", "changes": changes}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating user: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/admin/users/{user_id}")
def delete_admin_user(user_id: int, user: dict = Depends(require_role("admin"))):
    try:
        with get_db_connection() as conn:
            with conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT id, username, role, active FROM users WHERE id = %s;", (user_id,))
                    db_row = cur.fetchone()
                    if not db_row:
                        raise HTTPException(status_code=404, detail="User not found")
                        
                    _, db_username, db_role, db_active = db_row
                    
                    if user_id == user["id"]:
                        raise HTTPException(status_code=400, detail="Cannot disable yourself.")
                        
                    if db_role == 'admin' and db_active:
                        cur.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND active = true;")
                        active_admin_count = cur.fetchone()[0]
                        if active_admin_count <= 1:
                            raise HTTPException(status_code=400, detail="Cannot disable the last active admin.")
                            
                    cur.execute("UPDATE users SET active = false WHERE id = %s;", (user_id,))
                    
                    cur.execute(
                        """
                        INSERT INTO audit_events (actor, action, target, detail, target_type, target_id, details)
                        VALUES (%s, 'user_disabled', %s, '{}'::jsonb, 'user', %s, '{}'::jsonb);
                        """,
                        (
                            user["username"], 
                            f"user:{db_username}", 
                            str(user_id)
                        )
                    )
                    
                    return {"status": "success", "message": f"User {db_username} disabled successfully."}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting/disabling user: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/audit")
def get_audit_logs(
    request: Request,
    actor: str = Query(None),
    action: str = Query(None),
    from_time: str = Query(None, alias="from"),
    to_time: str = Query(None, alias="to"),
    q: str = Query(None),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user: dict = Depends(require_role("admin"))
):
    try:
        conditions = []
        params = []
        
        if actor:
            conditions.append("COALESCE(actor, 'system') = %s")
            params.append(actor)
        if action:
            conditions.append("action = %s")
            params.append(action)
        if from_time:
            conditions.append("timestamp >= %s")
            params.append(from_time)
        if to_time:
            conditions.append("timestamp <= %s")
            params.append(to_time)
        if q:
            conditions.append("(target ILIKE %s OR COALESCE(detail, details)::text ILIKE %s)")
            params.append(f"%{q}%")
            params.append(f"%{q}%")
            
        where_clause = ""
        if conditions:
            where_clause = "WHERE " + " AND ".join(conditions)
            
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                count_query = f"SELECT COUNT(*) FROM audit_events {where_clause};"
                cur.execute(count_query, tuple(params))
                total = cur.fetchone()[0]
                
                rows_query = f"""
                    SELECT id, timestamp AS occurred_at, COALESCE(actor, 'system') AS actor, 
                           action, COALESCE(target, target_type || ':' || target_id) AS target, 
                           COALESCE(detail, details) AS detail
                    FROM audit_events
                    {where_clause}
                    ORDER BY timestamp DESC
                    LIMIT %s OFFSET %s;
                """
                cur.execute(rows_query, tuple(params + [limit, offset]))
                db_rows = cur.fetchall()
                
                rows = []
                for r in db_rows:
                    rows.append({
                        "id": r[0],
                        "occurred_at": r[1].isoformat() if r[1] else None,
                        "actor": r[2],
                        "action": r[3],
                        "target": r[4],
                        "detail": r[5]
                    })
                    
                return {"total": total, "rows": rows}
    except Exception as e:
        logger.error(f"Error fetching audit logs: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/audit/actors")
def get_audit_actors(user: dict = Depends(require_role("admin"))):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT DISTINCT COALESCE(actor, 'system') FROM audit_events ORDER BY 1;")
                actors = [r[0] for r in cur.fetchall()]
                return actors
    except Exception as e:
        logger.error(f"Error fetching audit actors: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/audit/actions")
def get_audit_actions(user: dict = Depends(require_role("admin"))):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT DISTINCT action FROM audit_events ORDER BY 1;")
                actions = [r[0] for r in cur.fetchall()]
                return actions
    except Exception as e:
        logger.error(f"Error fetching audit actions: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/audit/export.csv")
def export_audit_logs_csv(
    request: Request,
    actor: str = Query(None),
    action: str = Query(None),
    from_time: str = Query(None, alias="from"),
    to_time: str = Query(None, alias="to"),
    q: str = Query(None),
    user: dict = Depends(require_role("admin"))
):
    try:
        import io
        import csv
        conditions = []
        params = []
        
        if actor:
            conditions.append("COALESCE(actor, 'system') = %s")
            params.append(actor)
        if action:
            conditions.append("action = %s")
            params.append(action)
        if from_time:
            conditions.append("timestamp >= %s")
            params.append(from_time)
        if to_time:
            conditions.append("timestamp <= %s")
            params.append(to_time)
        if q:
            conditions.append("(target ILIKE %s OR COALESCE(detail, details)::text ILIKE %s)")
            params.append(f"%{q}%")
            params.append(f"%{q}%")
            
        where_clause = ""
        if conditions:
            where_clause = "WHERE " + " AND ".join(conditions)
            
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                rows_query = f"""
                    SELECT timestamp AS occurred_at, COALESCE(actor, 'system') AS actor, 
                           action, COALESCE(target, target_type || ':' || target_id) AS target, 
                           COALESCE(detail, details) AS detail
                    FROM audit_events
                    {where_clause}
                    ORDER BY timestamp DESC;
                """
                cur.execute(rows_query, tuple(params))
                db_rows = cur.fetchall()
                
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["occurred_at", "actor", "action", "target", "detail_json"])
        
        for r in db_rows:
            occurred_at = r[0].isoformat() if r[0] else ""
            actor_val = r[1]
            action_val = r[2]
            target_val = r[3]
            detail_json = json.dumps(r[4]) if r[4] is not None else "{}"
            writer.writerow([occurred_at, actor_val, action_val, target_val, detail_json])
            
        csv_data = output.getvalue()
        output.close()
        
        iso_date = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        filename = f"audit_{iso_date}.csv"
        
        return Response(
            content=csv_data,
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
    except Exception as e:
        logger.error(f"Error exporting audit logs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/login.html", response_class=HTMLResponse)
def get_login_html():
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Vulnerability Triage Gate</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Outfit:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --border-color: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --accent-green: #10b981;
            --accent-red: #ef4444;
        }
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .login-card {
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 2.5rem;
            width: 100%;
            max-width: 400px;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);
        }
        h1 {
            font-family: 'Outfit', sans-serif;
            font-size: 1.75rem;
            font-weight: 700;
            background: linear-gradient(135deg, #06b6d4 0%, #3b82f6 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
            text-align: center;
        }
        .subtitle {
            font-size: 0.85rem;
            color: var(--text-secondary);
            text-align: center;
            margin-bottom: 2rem;
        }
        .form-group {
            margin-bottom: 1.25rem;
        }
        label {
            display: block;
            font-size: 0.75rem;
            text-transform: uppercase;
            font-weight: 700;
            color: var(--text-secondary);
            margin-bottom: 0.5rem;
            letter-spacing: 0.05em;
        }
        .input-control {
            width: 100%;
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 0.75rem 1rem;
            border-radius: 6px;
            font-size: 0.9rem;
            outline: none;
            transition: border-color 0.2s;
        }
        .input-control:focus {
            border-color: var(--accent-cyan);
        }
        .btn {
            width: 100%;
            padding: 0.75rem;
            background: linear-gradient(135deg, #06b6d4 0%, #3b82f6 100%);
            border: none;
            border-radius: 6px;
            color: white;
            font-weight: 600;
            font-size: 0.95rem;
            cursor: pointer;
            transition: all 0.2s;
            margin-top: 1rem;
        }
        .btn:hover {
            opacity: 0.9;
            transform: translateY(-1px);
        }
        .error-message {
            background-color: rgba(239, 68, 68, 0.1);
            border: 1px solid var(--accent-red);
            color: var(--accent-red);
            padding: 0.75rem;
            border-radius: 6px;
            font-size: 0.85rem;
            margin-bottom: 1.25rem;
            display: none;
        }
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="login-card">
        <h1>Vulnerability Triage Gate</h1>
        <div class="subtitle">Secure Audit & Triage Environment</div>
        
        <div id="errorAlert" class="error-message"></div>
        
        <form id="loginForm" onsubmit="handleLogin(event)">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" class="input-control" required autocomplete="username" autofocus>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <div style="position: relative; display: flex; align-items: center;">
                    <input type="password" id="password" class="input-control" required autocomplete="current-password" style="padding-right: 2.5rem;">
                    <button type="button" id="togglePassword" style="position: absolute; right: 0.75rem; background: none; border: none; color: var(--text-secondary); cursor: pointer; display: flex; align-items: center; outline: none; padding: 0;">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" style="width: 1.25rem; height: 1.25rem;">
                            <path stroke-linecap="round" stroke-linejoin="round" d="M2.036 12.322a1.012 1.012 0 0 1 0-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178Z" />
                            <path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z" />
                        </svg>
                    </button>
                </div>
                <div id="capsLockWarning" style="color: var(--accent-red); font-size: 0.75rem; margin-top: 0.25rem; display: none; font-weight: 500;">⚠️ Caps Lock is active</div>
            </div>
            <button type="submit" class="btn">Log In</button>
        </form>
        <div style="margin-top: 1.5rem; text-align: center; font-size: 0.75rem; color: var(--text-secondary); border-top: 1px solid var(--border-color); padding-top: 1rem;">
            First time? Use the default credentials and change them after login.
        </div>
    </div>

    <script>
        const passwordInput = document.getElementById('password');
        const togglePassword = document.getElementById('togglePassword');
        togglePassword.onclick = () => {
            const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
            passwordInput.setAttribute('type', type);
            togglePassword.style.color = type === 'text' ? 'var(--accent-cyan)' : 'var(--text-secondary)';
        };

        function checkCapsLock(e) {
            if (e.getModifierState && e.getModifierState('CapsLock')) {
                document.getElementById('capsLockWarning').style.display = 'block';
            } else {
                document.getElementById('capsLockWarning').style.display = 'none';
            }
        }
        passwordInput.addEventListener('keyup', checkCapsLock);
        passwordInput.addEventListener('keydown', checkCapsLock);

        async function handleLogin(event) {
            event.preventDefault();
            const usernameInput = document.getElementById('username');
            const passwordInput = document.getElementById('password');
            const errorAlert = document.getElementById('errorAlert');
            const submitBtn = event.target.querySelector('button[type="submit"]');
            
            errorAlert.style.display = 'none';
            
            const originalText = submitBtn.innerText;
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="spinner" style="display: inline-block; width: 0.8rem; height: 0.8rem; border: 2px solid #fff; border-top-color: transparent; border-radius: 50%; animation: spin 0.8s linear infinite; margin-right: 0.5rem; vertical-align: middle;"></span>Saving...';
            
            try {
                // Using global apiFetch instead of raw fetch
                const response = await window.apiFetch('/api/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        username: usernameInput.value,
                        password: passwordInput.value
                    })
                });
                
                if (response.ok) {
                    const data = await response.json();
                    window.toast("Welcome " + usernameInput.value + "!", "success");
                    setTimeout(() => {
                        if (data.must_change_password) {
                            window.location.href = '/change-password.html';
                        } else {
                            // Check if intended path exists
                            const intended = localStorage.getItem('intended_path');
                            if (intended) {
                                localStorage.removeItem('intended_path');
                                window.location.href = intended;
                            } else {
                                window.location.href = '/brief.html'; // Default landing page
                            }
                        }
                    }, 500);
                } else {
                    const data = await response.json();
                    let errMsg = data.detail || 'Login failed';
                    if (typeof errMsg === 'object') {
                        errMsg = JSON.stringify(errMsg);
                    }
                    errorAlert.innerText = errMsg;
                    errorAlert.style.display = 'block';
                    submitBtn.disabled = false;
                    submitBtn.innerText = originalText;
                }
            } catch (err) {
                errorAlert.innerText = 'Network error occurred.';
                errorAlert.style.display = 'block';
                submitBtn.disabled = false;
                submitBtn.innerText = originalText;
            }
        }
    </script>
</body>
</html>"""
    return render_html(html_content)

@app.get("/change-password.html", response_class=HTMLResponse)
def get_change_password_html():
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Change Password - Vulnerability Triage Gate</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Outfit:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --border-color: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --accent-green: #10b981;
            --accent-red: #ef4444;
        }
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .login-card {
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 2.5rem;
            width: 100%;
            max-width: 400px;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);
        }
        h1 {
            font-family: 'Outfit', sans-serif;
            font-size: 1.75rem;
            font-weight: 700;
            background: linear-gradient(135deg, #06b6d4 0%, #3b82f6 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
            text-align: center;
        }
        .subtitle {
            font-size: 0.85rem;
            color: var(--text-secondary);
            text-align: center;
            margin-bottom: 2rem;
        }
        .form-group {
            margin-bottom: 1.25rem;
        }
        label {
            display: block;
            font-size: 0.75rem;
            text-transform: uppercase;
            font-weight: 700;
            color: var(--text-secondary);
            margin-bottom: 0.5rem;
            letter-spacing: 0.05em;
        }
        .input-control {
            width: 100%;
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 0.75rem 1rem;
            border-radius: 6px;
            font-size: 0.9rem;
            outline: none;
            transition: border-color 0.2s;
        }
        .input-control:focus {
            border-color: var(--accent-cyan);
        }
        .btn {
            width: 100%;
            padding: 0.75rem;
            background: linear-gradient(135deg, #06b6d4 0%, #3b82f6 100%);
            border: none;
            border-radius: 6px;
            color: white;
            font-weight: 600;
            font-size: 0.95rem;
            cursor: pointer;
            transition: all 0.2s;
            margin-top: 1rem;
        }
        .btn:hover {
            opacity: 0.9;
            transform: translateY(-1px);
        }
        .error-message {
            background-color: rgba(239, 68, 68, 0.1);
            border: 1px solid var(--accent-red);
            color: var(--accent-red);
            padding: 0.75rem;
            border-radius: 6px;
            font-size: 0.85rem;
            margin-bottom: 1.25rem;
            display: none;
        }
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="login-card">
        <h1>Change Password</h1>
        <div class="subtitle">Password change is required for security</div>
        
        <div id="errorAlert" class="error-message"></div>
        
        <form id="changePasswordForm" onsubmit="handleChangePassword(event)">
            <div class="form-group">
                <label for="oldPassword">Old Password</label>
                <input type="password" id="oldPassword" class="input-control" required autocomplete="current-password">
            </div>
            <div class="form-group">
                <label for="newPassword">New Password</label>
                <input type="password" id="newPassword" class="input-control" required autocomplete="new-password">
                <div id="newPasswordError" style="color: var(--accent-red); font-size: 0.75rem; margin-top: 0.25rem; display: none;">Min 8 characters</div>
            </div>
            <div class="form-group">
                <label for="confirmPassword">Confirm New Password</label>
                <input type="password" id="confirmPassword" class="input-control" required autocomplete="new-password">
                <div id="confirmPasswordError" style="color: var(--accent-red); font-size: 0.75rem; margin-top: 0.25rem; display: none;">Passwords don't match</div>
            </div>
            <button type="submit" class="btn">Change Password</button>
        </form>
    </div>

    <script>
        const newPasswordInput = document.getElementById('newPassword');
        const confirmPasswordInput = document.getElementById('confirmPassword');
        const newPasswordError = document.getElementById('newPasswordError');
        const confirmPasswordError = document.getElementById('confirmPasswordError');

        function validatePasswords() {
            let isValid = true;
            
            // Check length
            if (newPasswordInput.value.length < 8) {
                newPasswordError.style.display = 'block';
                newPasswordInput.style.borderColor = 'var(--accent-red)';
                isValid = false;
            } else {
                newPasswordError.style.display = 'none';
                newPasswordInput.style.borderColor = '';
            }
            
            // Check match
            if (confirmPasswordInput.value && newPasswordInput.value !== confirmPasswordInput.value) {
                confirmPasswordError.style.display = 'block';
                confirmPasswordInput.style.borderColor = 'var(--accent-red)';
                isValid = false;
            } else {
                confirmPasswordError.style.display = 'none';
                confirmPasswordInput.style.borderColor = '';
            }
            
            return isValid;
        }

        newPasswordInput.addEventListener('input', validatePasswords);
        confirmPasswordInput.addEventListener('input', validatePasswords);

        async function handleChangePassword(event) {
            event.preventDefault();
            const oldPassword = document.getElementById('oldPassword').value;
            const newPassword = document.getElementById('newPassword').value;
            const confirmPassword = document.getElementById('confirmPassword').value;
            const errorAlert = document.getElementById('errorAlert');
            const submitBtn = event.target.querySelector('button[type="submit"]');
            
            errorAlert.style.display = 'none';
            
            if (!validatePasswords()) {
                errorAlert.innerText = 'Please fix password requirements.';
                errorAlert.style.display = 'block';
                return;
            }
            
            const originalText = submitBtn.innerText;
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="spinner" style="display: inline-block; width: 0.8rem; height: 0.8rem; border: 2px solid #fff; border-top-color: transparent; border-radius: 50%; animation: spin 0.8s linear infinite; margin-right: 0.5rem; vertical-align: middle;"></span>Saving...';
            
            try {
                const response = await window.apiFetch('/api/change-password', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        old_password: oldPassword,
                        new_password: newPassword
                    })
                });
                
                if (response.ok) {
                    window.toast('Password updated', 'success');
                    setTimeout(() => {
                        window.location.href = '/';
                    }, 500);
                } else {
                    const data = await response.json();
                    let errMsg = data.detail || 'Password change failed.';
                    if (typeof errMsg === 'object') {
                        errMsg = JSON.stringify(errMsg);
                    }
                    errorAlert.innerText = errMsg;
                    errorAlert.style.display = 'block';
                    submitBtn.disabled = false;
                    submitBtn.innerText = originalText;
                }
            } catch (err) {
                errorAlert.innerText = 'Network error occurred.';
                errorAlert.style.display = 'block';
                submitBtn.disabled = false;
                submitBtn.innerText = originalText;
            }
        }
    </script>
</body>
</html>"""
    return render_html(html_content)

@app.get("/brief.html", response_class=HTMLResponse)
def get_brief_html():
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Triage Gate Monitor</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Outfit:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --border-color: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent-green: #10b981;
            --accent-red: #ef4444;
            --accent-warning: #f59e0b;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --accent-purple: #c084fc;
        }
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            padding: 2.5rem;
            display: flex;
            flex-direction: column;
            min-height: 100vh;
        }
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 1.5rem;
        }
        h1 {
            font-family: 'Outfit', sans-serif;
            font-size: 2rem;
            font-weight: 700;
            background: linear-gradient(135deg, #06b6d4 0%, #3b82f6 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .subtitle {
            font-size: 0.95rem;
            color: var(--text-secondary);
            margin-top: 0.25rem;
        }
        .container {
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3);
            margin-bottom: 2rem;
        }
        /* Sticky filter bar */
        .sticky-filters {
            position: sticky;
            top: 1rem;
            z-index: 100;
            background: rgba(30, 41, 59, 0.95);
            backdrop-filter: blur(8px);
            border: 1px solid var(--border-color);
            padding: 1rem 1.5rem;
            margin-bottom: 1.5rem;
            border-radius: 12px;
            display: flex;
            flex-wrap: wrap;
            gap: 1rem;
            align-items: center;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.4);
        }
        .filter-control {
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 0.5rem 2rem 0.5rem 0.75rem;
            border-radius: 6px;
            font-size: 0.85rem;
            outline: none;
            cursor: pointer;
            transition: border-color 0.2s;
            appearance: none;
            background-image: url("data:image/svg+xml;utf8,<svg fill='%2394a3b8' height='24' viewBox='0 0 24 24' width='24' xmlns='http://www.w3.org/2000/svg'><path d='M7 10l5 5 5-5z'/></svg>");
            background-repeat: no-repeat;
            background-position-x: 95%;
            background-position-y: 50%;
        }
        .filter-control:focus {
            border-color: var(--accent-cyan);
        }
        .search-input {
            flex-grow: 1;
            min-width: 200px;
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 0.5rem 0.75rem;
            border-radius: 6px;
            font-size: 0.85rem;
            outline: none;
            transition: border-color 0.2s;
        }
        .search-input:focus {
            border-color: var(--accent-cyan);
        }
        .toggle-chip {
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            user-select: none;
        }
        .toggle-chip:hover {
            color: var(--text-primary);
            border-color: var(--text-secondary);
        }
        .toggle-chip.active {
            background-color: rgba(6, 182, 212, 0.15);
            color: var(--accent-cyan);
            border-color: var(--accent-cyan);
            box-shadow: 0 0 8px rgba(6, 182, 212, 0.2);
        }
        .action-bar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
            padding: 0.75rem 1.25rem;
            background-color: rgba(30, 41, 59, 0.5);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            font-size: 0.9rem;
        }
        .action-bar-left {
            font-weight: 500;
            color: var(--text-secondary);
        }
        .action-bar-right {
            display: flex;
            gap: 0.75rem;
        }
        /* Table Styling */
        .table-container {
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3);
            margin-bottom: 1.5rem;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }
        th {
            position: sticky;
            top: 0;
            background-color: var(--bg-secondary);
            z-index: 10;
            padding: 1rem;
            font-family: 'Outfit', sans-serif;
            color: var(--text-secondary);
            border-bottom: 2px solid var(--border-color);
            font-weight: 600;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        th.sortable {
            cursor: pointer;
            user-select: none;
            transition: color 0.2s;
        }
        th.sortable:hover {
            color: var(--text-primary);
        }
        .sort-icon {
            font-size: 0.75rem;
            margin-left: 0.25rem;
            display: inline-block;
            width: 12px;
            color: var(--accent-cyan);
        }
        td {
            padding: 1rem;
            border-bottom: 1px solid var(--border-color);
            vertical-align: middle;
            font-size: 0.9rem;
        }
        tr.data-row {
            cursor: pointer;
            transition: background-color 0.2s;
        }
        tr.data-row:hover {
            background-color: rgba(255, 255, 255, 0.02);
        }
        tr.data-row.expanded {
            background-color: rgba(6, 182, 212, 0.03);
        }
        .checkbox-cell {
            text-align: center;
            width: 40px;
        }
        .checkbox-cell input[type="checkbox"] {
            cursor: pointer;
            accent-color: var(--accent-cyan);
            width: 16px;
            height: 16px;
        }
        .vuln-title {
            font-weight: 500;
            margin-bottom: 0.25rem;
            color: var(--text-primary);
        }
        .asset-desc {
            font-size: 0.85rem;
            color: var(--text-secondary);
        }
        .cvss-val {
            background-color: rgba(245, 158, 11, 0.15);
            color: var(--accent-warning);
            padding: 0.25rem 0.5rem;
            border-radius: 6px;
            font-weight: 600;
            font-size: 0.85rem;
        }
        .epss-val {
            color: var(--accent-cyan);
            font-weight: 500;
            font-size: 0.9rem;
        }
        .priority-score {
            background-color: rgba(239, 68, 68, 0.15);
            color: var(--accent-red);
            padding: 0.35rem 0.7rem;
            border-radius: 6px;
            font-weight: 700;
            font-size: 0.95rem;
            display: inline-block;
        }
        .badge {
            display: inline-block;
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
            margin-right: 0.25rem;
        }
        .badge-danger {
            background-color: var(--accent-red);
            color: white;
        }
        .badge-warning {
            background-color: var(--accent-warning);
            color: #0f172a;
        }
        .btn {
            padding: 0.5rem 0.9rem;
            border: none;
            border-radius: 6px;
            font-weight: 600;
            font-size: 0.85rem;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        .btn-approve {
            background-color: var(--accent-green);
            color: white;
        }
        .btn-approve:hover:not(:disabled) {
            background-color: #059669;
            transform: translateY(-1px);
        }
        .btn-reject {
            background-color: transparent;
            border: 1px solid var(--border-color);
            color: var(--text-primary);
        }
        .btn-reject:hover:not(:disabled) {
            background-color: rgba(239, 68, 68, 0.1);
            border-color: var(--accent-red);
            color: var(--accent-red);
            transform: translateY(-1px);
        }
        .btn-secondary {
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
        }
        .btn-secondary:hover:not(:disabled) {
            border-color: var(--text-secondary);
            transform: translateY(-1px);
        }
        .btn:disabled {
            opacity: 0.4;
            cursor: not-allowed;
            transform: none !important;
        }
        .status-banner {
            display: inline-block;
            padding: 0.3rem 0.6rem;
            border-radius: 6px;
            font-weight: 600;
            font-size: 0.8rem;
            text-align: center;
        }
        .status-approved {
            background-color: rgba(16, 185, 129, 0.15);
            color: var(--accent-green);
            border: 1px solid var(--accent-green);
        }
        .status-rejected {
            background-color: rgba(239, 68, 68, 0.15);
            color: var(--accent-red);
            border: 1px solid var(--accent-red);
        }
        .empty-state {
            text-align: center;
            color: var(--text-secondary);
            padding: 4rem;
            font-size: 1.1rem;
        }
        /* Detail Drawer Row */
        .detail-row td {
            padding: 0;
            background-color: #0b0f19;
            border-bottom: 1px solid var(--border-color);
        }
        .detail-content {
            padding: 1.5rem 2rem;
            border-left: 4px solid var(--accent-cyan);
            display: flex;
            flex-direction: column;
            gap: 1rem;
            animation: slideDown 0.2s ease-out;
        }
        @keyframes slideDown {
            from { opacity: 0; transform: translateY(-5px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .detail-header-title {
            font-family: 'Outfit', sans-serif;
            font-size: 1.15rem;
            font-weight: 700;
            color: var(--text-primary);
        }
        .detail-sections-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.5rem;
        }
        @media(max-width: 768px) {
            .detail-sections-grid {
                grid-template-columns: 1fr;
            }
        }
        .detail-sect-title {
            font-size: 0.75rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            font-weight: 700;
            letter-spacing: 0.05em;
            margin-bottom: 0.35rem;
        }
        .detail-sect-body {
            font-size: 0.9rem;
            line-height: 1.5;
            color: #cbd5e1;
            white-space: pre-wrap;
        }
        /* Pagination */
        .pagination-container {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem 1.5rem;
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            font-size: 0.9rem;
        }
        .pagination-left {
            color: var(--text-secondary);
        }
        .pagination-center {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .pagination-right {
            display: flex;
            gap: 0.5rem;
        }
        /* Toast style */
        .toast {
            background: rgba(15, 23, 42, 0.9);
            backdrop-filter: blur(8px);
            border: 1px solid var(--border-color);
            border-left: 4px solid var(--accent-green);
            padding: 1rem 1.5rem;
            border-radius: 8px;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.6);
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-family: 'Outfit', sans-serif;
            font-size: 0.9rem;
            min-width: 320px;
            animation: toastIn 0.3s cubic-bezier(0.16, 1, 0.3, 1);
            transition: opacity 0.3s, transform 0.3s;
        }
        .toast.warning {
            border-left-color: var(--accent-warning);
        }
        @keyframes toastIn {
            from { opacity: 0; transform: translateX(50px); }
            to { opacity: 1; transform: translateX(0); }
        }
        .toast-icon {
            font-size: 1.25rem;
        }
        footer {
            margin-top: 3rem;
            text-align: center;
            font-size: 0.85rem;
            color: var(--text-secondary);
            border-top: 1px solid var(--border-color);
            padding-top: 1.5rem;
        }
        header a:hover {
            color: var(--accent-cyan) !important;
        }
    </style>
</head>
<body>
    <header>
        <div>
            <h1>Vulnerability Triage Gate Monitor</h1>
            <div class="subtitle">Coordinator Dashboard - Strict Audit Control</div>
        </div>
        <div style="display: flex; align-items: center; gap: 1rem; flex-wrap: wrap;">
            <nav style="display: flex; align-items: center; gap: 0.75rem;">
                <a href="/brief.html" id="navFindings" style="color: var(--text-primary); text-decoration: none; font-weight: 600; font-size: 0.9rem; transition: color 0.2s;">Findings</a>
                <span style="color: var(--border-color); font-size: 0.9rem;">|</span>
                <a href="/assets.html" id="navAssets" style="color: var(--text-primary); text-decoration: none; font-weight: 600; font-size: 0.9rem; transition: color 0.2s;">Assets</a>
                <span id="navDividerAssets" style="color: var(--border-color); font-size: 0.9rem;">|</span>
                <span id="navDividerUsers" style="color: var(--border-color); font-size: 0.9rem; display: none;">|</span>
                <a href="/users.html" id="navUsers" style="color: var(--text-primary); text-decoration: none; font-weight: 600; font-size: 0.9rem; display: none; transition: color 0.2s;">Users</a>
                <span id="navDividerAudit" style="color: var(--border-color); font-size: 0.9rem; display: none;">|</span>
                <a href="/audit.html" id="navAudit" style="color: var(--text-primary); text-decoration: none; font-weight: 600; font-size: 0.9rem; display: none; transition: color 0.2s;">Audit</a>
                <span id="navDividerSettings" style="color: var(--border-color); font-size: 0.9rem; display: none;">|</span>
                <a href="/settings.html" id="navSettings" style="color: var(--text-primary); text-decoration: none; font-weight: 600; font-size: 0.9rem; display: none; transition: color 0.2s;">Settings</a>
            </nav>
            <span style="color: var(--border-color); font-size: 0.9rem;">|</span>
            <div style="display: flex; align-items: center; gap: 0.75rem;">
                <span class="asset-desc" id="headerUserInfo" style="font-weight: 500; color: var(--text-primary); font-size: 0.9rem;"></span>
                <span class="asset-desc" style="color: var(--text-secondary); font-size: 0.9rem;">|</span>
                <a href="/change-password.html" class="asset-desc" style="color: var(--accent-cyan); text-decoration: none; font-weight: 500; font-size: 0.9rem;">Change password</a>
                <span class="asset-desc" style="color: var(--text-secondary); font-size: 0.9rem;">|</span>
                <a href="#" onclick="handleLogout(event)" class="asset-desc" style="color: var(--accent-red); text-decoration: none; font-weight: 500; font-size: 0.9rem;">Logout</a>
                <span class="asset-desc" style="color: var(--text-secondary); font-size: 0.9rem;">|</span>
                <span class="asset-desc" style="font-size: 0.9rem;">Last updated: <span id="refreshTime">--:--:--</span></span>
            </div>
        </div>
    </header>

    <!-- Import findings upload card -->
    <div class="container" style="flex-grow: 0;">
        <h2 style="font-family: 'Outfit', sans-serif; font-size: 1.25rem; margin-bottom: 1rem; border-bottom: 1px solid var(--border-color); padding-bottom: 0.5rem; color: var(--accent-cyan);">Import findings</h2>
        <form id="uploadForm" onsubmit="handleUpload(event)" style="display: flex; flex-direction: column; gap: 1rem;">
            <div style="display: flex; gap: 2rem; align-items: center; font-size: 0.9rem;">
                <label style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer;">
                    <input type="radio" name="source" value="cavelo" checked style="accent-color: var(--accent-cyan);">
                    Cavelo Endpoint Vulnerability Results
                </label>
                <label style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer;">
                    <input type="radio" name="source" value="blackpoint" style="accent-color: var(--accent-cyan);">
                    Blackpoint Cyber export
                </label>
            </div>
            <div style="display: flex; gap: 1rem; align-items: center;">
                <input type="file" id="csvFile" accept=".csv" required style="
                    background-color: var(--bg-primary);
                    border: 1px solid var(--border-color);
                    padding: 0.5rem;
                    border-radius: 6px;
                    color: var(--text-primary);
                    font-size: 0.85rem;
                    cursor: pointer;
                ">
                <button type="submit" class="btn btn-approve" style="padding: 0.6rem 1.2rem; font-family: 'Outfit', sans-serif; font-size: 0.9rem; margin-right: 0;">Upload</button>
                <span id="uploadStatus" class="status-banner" style="display: none; padding: 0.5rem 1rem; font-size: 0.85rem;"></span>
            </div>
            <div id="uploadErrors" style="display: none; color: var(--accent-red); font-size: 0.85rem; margin-top: 0.5rem;"></div>
        </form>
    </div>

    <!-- Sticky Filter Bar -->
    <div class="sticky-filters">
        <select id="filterSource" class="filter-control" onchange="handleFilterChange()">
            <option value="all">All Sources</option>
            <option value="cavelo">Cavelo</option>
            <option value="blackpoint">Blackpoint</option>
            <option value="seed">Seed</option>
        </select>
        <select id="filterEnv" class="filter-control" onchange="handleFilterChange()">
            <option value="all">All Environments</option>
            <option value="prod">Prod</option>
            <option value="staging">Staging</option>
            <option value="dev">Dev</option>
            <option value="sandbox">Sandbox</option>
        </select>
        <select id="filterSeverity" class="filter-control" onchange="handleFilterChange()">
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
        </select>
        <div class="toggle-chip" id="chipKev" onclick="toggleChip('in_kev')">KEV</div>
        <div class="toggle-chip" id="chipExploit" onclick="toggleChip('has_exploit')">Exploit</div>
        <select id="filterStatus" class="filter-control" onchange="handleFilterChange()">
            <option value="all">All Statuses</option>
            <option value="pending" selected>Pending</option>
            <option value="approved">Approved</option>
            <option value="rejected">Rejected</option>
            <option value="ticketed">Ticketed</option>
            <option value="closed">Closed</option>
        </select>
        <input type="text" id="searchInput" class="search-input" placeholder="Search CVE, hostname, title..." oninput="handleSearchInput(event)">
    </div>

    <!-- Action Bar -->
    <div class="action-bar">
        <div class="action-bar-left" id="filteredCountText">
            0 of 0 findings
        </div>
        <div class="action-bar-right">
            <button id="btnSelectAllVisible" class="btn btn-secondary" onclick="selectAllVisible()">Select All Visible</button>
            <button id="btnBulkApprove" class="btn btn-approve" onclick="handleBulkAction('approve')" disabled>Bulk Approve</button>
            <button id="btnBulkReject" class="btn btn-reject" onclick="handleBulkAction('reject')" disabled>Bulk Reject</button>
        </div>
    </div>

    <!-- Data Table Container -->
    <div class="table-container">
        <table id="findingsTable">
            <thead>
                <tr>
                    <th class="checkbox-cell"><input type="checkbox" id="selectAllCheckbox" onclick="toggleSelectAllHeader(this)"></th>
                    <th class="sortable" onclick="handleHeaderSort('cve')">CVE <span id="sort-cve" class="sort-icon"></span></th>
                    <th style="width: 25%;">Vulnerability & Asset</th>
                    <th>Source</th>
                    <th>Env</th>
                    <th class="sortable" onclick="handleHeaderSort('cvss')">CVSS <span id="sort-cvss" class="sort-icon"></span></th>
                    <th class="sortable" onclick="handleHeaderSort('epss')">EPSS <span id="sort-epss" class="sort-icon"></span></th>
                    <th>Enrichment</th>
                    <th class="sortable" onclick="handleHeaderSort('score')">Score <span id="sort-score" class="sort-icon"></span></th>
                    <th class="sortable" onclick="handleHeaderSort('status')">Status <span id="sort-status" class="sort-icon"></span></th>
                    <th style="width: 180px;" class="action-col">Action</th>
                </tr>
            </thead>
            <tbody id="tableBody">
                <!-- Loaded dynamically -->
            </tbody>
        </table>
    </div>

    <!-- Pagination -->
    <div class="pagination-container">
        <div class="pagination-left" id="paginationRangeText">
            Showing 0-0 of 0
        </div>
        <div class="pagination-center">
            <span>Page Size:</span>
            <select id="pageSizeSelect" class="filter-control" style="padding: 0.3rem 1.5rem 0.3rem 0.5rem;" onchange="handlePageSizeChange()">
                <option value="25">25</option>
                <option value="50" selected>50</option>
                <option value="100">100</option>
                <option value="250">250</option>
            </select>
        </div>
        <div class="pagination-right">
            <button id="btnPrev" class="btn btn-secondary" onclick="handlePageNavigate(-1)">Prev</button>
            <button id="btnNext" class="btn btn-secondary" onclick="handlePageNavigate(1)">Next</button>
        </div>
    </div>

    <!-- External Secrets List -->
    <div class="container" style="margin-top: 2rem; background-color: rgba(30, 41, 59, 0.5); flex-grow: 0;">
        <h2 style="font-family: 'Outfit', sans-serif; font-size: 1.25rem; margin-bottom: 1rem; border-bottom: 1px solid var(--border-color); padding-bottom: 0.5rem; color: var(--accent-cyan);">External Secrets Still Required</h2>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; font-size: 0.85rem; color: var(--text-secondary); line-height: 1.6;">
            <div>
                <h3 style="color: var(--text-primary); font-size: 0.95rem; margin-bottom: 0.5rem;">Cavelo Integration</h3>
                <ul style="list-style-type: none; padding-left: 0;">
                    <li>• <code style="color: var(--accent-warning);">CAVELO_API_TOKEN</code></li>
                </ul>
                <h3 style="color: var(--text-primary); font-size: 0.95rem; margin-top: 0.75rem; margin-bottom: 0.5rem;">Slack Alerts</h3>
                <ul style="list-style-type: none; padding-left: 0;">
                    <li>• <code style="color: var(--accent-warning);">SLACK_WEBHOOK_URL</code></li>
                </ul>
            </div>
            <div>
                <h3 style="color: var(--text-primary); font-size: 0.95rem; margin-bottom: 0.5rem;">Datto Autotask PSA Integration</h3>
                <ul style="list-style-type: none; padding-left: 0;">
                    <li>• <code style="color: var(--accent-warning);">AUTOTASK_API_INTEGRATION_CODE</code></li>
                    <li>• <code style="color: var(--accent-warning);">AUTOTASK_USERNAME</code></li>
                    <li>• <code style="color: var(--accent-warning);">AUTOTASK_SECRET</code></li>
                    <li>• <code style="color: var(--accent-warning);">AUTOTASK_QUEUE_ID</code></li>
                    <li>• <code style="color: var(--accent-warning);">AUTOTASK_ACCOUNT_ID</code></li>
                    <li>• <code style="color: var(--accent-warning);">AUTOTASK_DEFAULT_ASSIGNEE_RESOURCE_ID</code></li>
                </ul>
            </div>
        </div>
    </div>

    <!-- Toast Container -->
    <div id="toastContainer" style="position: fixed; top: 1.5rem; right: 1.5rem; z-index: 1000; display: flex; flex-direction: column; gap: 0.75rem;"></div>

    <footer>
        Vulnerability Triage Co-Pilot v1.0 • Under Strict Audit Control
    </footer>

    <script>
        // State
        const state = {
            filters: {
                source: 'all',
                env: 'all',
                severity: 'all',
                in_kev: 'any',
                has_exploit: 'any',
                status: 'pending',
                q: ''
            },
            pagination: {
                limit: 50,
                offset: 0
            },
            sort: {
                field: 'score',
                direction: 'desc'
            },
            selectedIds: new Set(),
            data: {
                total: 0,
                filtered: 0,
                rows: []
            },
            expandedRows: new Set(),
            role: 'analyst'
        };

        // Debounce timer
        let searchDebounceTimer = null;

        // On load
        window.addEventListener('DOMContentLoaded', () => {
            checkAuthAndInit();
        });

        async function checkAuthAndInit() {
            try {
                const response = await fetch('/api/me');
                if (!response.ok) {
                    window.location.href = '/login.html';
                    return;
                }
                const user = await response.json();
                document.getElementById('headerUserInfo').innerText = `${user.username} (${user.role})`;
                
                if (user.role === 'admin') {
                    const navUsers = document.getElementById('navUsers');
                    if (navUsers) navUsers.style.display = 'inline';
                    const navDividerUsers = document.getElementById('navDividerUsers');
                    if (navDividerUsers) navDividerUsers.style.display = 'inline';
                    const navAudit = document.getElementById('navAudit');
                    if (navAudit) navAudit.style.display = 'inline';
                    const navDividerAudit = document.getElementById('navDividerAudit');
                    if (navDividerAudit) navDividerAudit.style.display = 'inline';
                    const navSettings = document.getElementById('navSettings');
                    if (navSettings) navSettings.style.display = 'inline';
                    const navDividerSettings = document.getElementById('navDividerSettings');
                    if (navDividerSettings) navDividerSettings.style.display = 'inline';
                }
                if (user.role === 'analyst') {
                    const navAssets = document.getElementById('navAssets');
                    if (navAssets) navAssets.style.display = 'none';
                    const navDividerAssets = document.getElementById('navDividerAssets');
                    if (navDividerAssets) navDividerAssets.style.display = 'none';
                }
                
                applyRoleUI(user.role);
                fetchData();
            } catch (err) {
                window.location.href = '/login.html';
            }
        }

        async function handleLogout(event) {
            event.preventDefault();
            try {
                await fetch('/api/logout', { method: 'POST' });
            } catch (err) {}
            window.location.href = '/login.html';
        }

        function applyRoleUI(role) {
            state.role = role;
            if (role === 'analyst') {
                // Hide Bulk action elements
                document.getElementById('btnBulkApprove').style.display = 'none';
                document.getElementById('btnBulkReject').style.display = 'none';
                document.getElementById('btnSelectAllVisible').style.display = 'none';
                
                // Hide header select all checkbox cell
                const selectAllHeader = document.querySelector('th.checkbox-cell');
                if (selectAllHeader) selectAllHeader.style.display = 'none';
                
                // Hide action column header
                const actionHeader = document.querySelector('.action-col');
                if (actionHeader) actionHeader.style.display = 'none';
                
                // Hide Assets link for analysts
                const navAssets = document.getElementById('navAssets');
                if (navAssets) navAssets.style.display = 'none';
                const navDividerAssets = document.getElementById('navDividerAssets');
                if (navDividerAssets) navDividerAssets.style.display = 'none';
            }
        }

        // Fetch data from API
        async function fetchData() {
            const params = new URLSearchParams();
            
            // Filters
            Object.entries(state.filters).forEach(([key, val]) => {
                params.append(key, val);
            });
            
            // Pagination
            params.append('limit', state.pagination.limit);
            params.append('offset', state.pagination.offset);
            
            // Sort
            params.append('sort', `${state.sort.field}_${state.sort.direction}`);

            const tbody = document.getElementById('tableBody');
            const colSpanVal = state.role === 'analyst' ? 9 : 11;
            tbody.innerHTML = `
                <tr>
                    <td colspan="${colSpanVal}" style="text-align: center; padding: 3rem 0; color: var(--text-secondary);">
                        <div class="spinner" style="display: inline-block; width: 1.5rem; height: 1.5rem; border: 3px solid var(--border-color); border-top-color: var(--accent-cyan); border-radius: 50%; animation: spin 0.8s linear infinite; margin-bottom: 0.5rem;"></div>
                        <div style="font-weight: 500;" class="text-muted">Loading findings...</div>
                    </td>
                </tr>
            `;

            try {
                const response = await window.apiFetch(`/api/findings?${params.toString()}`);
                if (!response.ok) {
                    throw new Error(`HTTP Error ${response.status}`);
                }
                const resData = await response.json();
                state.data = resData;
                
                // Update timestamp
                document.getElementById('refreshTime').innerText = new Date().toLocaleTimeString();
                
                renderTable();
                renderPagination();
                updateActionBar();
            } catch (err) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="${colSpanVal}" style="text-align: center; padding: 3rem 0; color: var(--accent-red);">
                            Failed to load findings.
                        </td>
                    </tr>
                `;
            }
        }

        // Render data rows in table
        function renderTable() {
            const tbody = document.getElementById('tableBody');
            tbody.innerHTML = '';

            // Update sort indicators
            const sortFields = ['cve', 'cvss', 'epss', 'score', 'status'];
            sortFields.forEach(field => {
                const el = document.getElementById(`sort-${field}`);
                if (el) {
                    if (state.sort.field === field) {
                        el.innerText = state.sort.direction === 'desc' ? ' ▼' : ' ▲';
                    } else {
                        el.innerText = '';
                    }
                }
            });

            const colSpanVal = state.role === 'analyst' ? 9 : 11;
            if (state.data.rows.length === 0) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="${colSpanVal}" style="text-align: center; padding: 4rem 1rem;">
                            <div style="font-size: 2.5rem; margin-bottom: 1rem;">📦</div>
                            <h3 style="font-family: 'Outfit'; font-size: 1.25rem; margin-bottom: 0.5rem; color: var(--text-primary);">No findings yet</h3>
                            <p style="color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 1.5rem;">Upload a Cavelo or Blackpoint CSV to get started</p>
                            <button class="btn" style="width: auto; padding: 0.5rem 1.5rem;" onclick="document.getElementById('csvFile').click()">Upload CSV</button>
                        </td>
                    </tr>
                `;
                return;
            }

            state.data.rows.forEach(item => {
                const isChecked = item.triage_ids.every(id => state.selectedIds.has(id));
                const isExpanded = state.expandedRows.has(item.triage_id);

                // Source badges styling
                let sourceBadges = '';
                if (item.sources && item.sources.length > 0) {
                    sourceBadges = item.sources.map(src => {
                        const srcLower = src.toLowerCase();
                        if (srcLower === 'cavelo') {
                            return `<span class="badge" style="background-color: rgba(13, 148, 136, 0.15); color: #2dd4bf; border: 1px solid #2dd4bf; margin-right: 0.25rem;">Cavelo</span>`;
                        } else if (srcLower === 'blackpoint') {
                            return `<span class="badge" style="background-color: rgba(168, 85, 247, 0.15); color: var(--accent-purple); border: 1px solid var(--accent-purple); margin-right: 0.25rem;">Blackpoint</span>`;
                        } else if (srcLower === 'seed') {
                            return `<span class="badge" style="background-color: rgba(100, 116, 139, 0.15); color: #94a3b8; border: 1px solid #94a3b8; margin-right: 0.25rem;">Seed</span>`;
                        } else {
                            return `<span class="badge" style="background-color: rgba(245, 158, 11, 0.15); color: var(--accent-warning); border: 1px solid var(--accent-warning); margin-right: 0.25rem;">${src}</span>`;
                        }
                    }).join('');
                } else {
                    sourceBadges = `<span class="badge" style="background-color: rgba(100, 116, 139, 0.15); color: #94a3b8; border: 1px solid #94a3b8;">Unknown</span>`;
                }

                // Env badge styling
                let envBadge = '';
                const envStr = (item.env || '').toLowerCase();
                if (envStr === 'prod') {
                    envBadge = `<span class="badge" style="background-color: rgba(239, 68, 68, 0.15); color: var(--accent-red); border: 1px solid var(--accent-red);">PROD</span>`;
                } else if (envStr === 'staging') {
                    envBadge = `<span class="badge" style="background-color: rgba(245, 158, 11, 0.15); color: var(--accent-warning); border: 1px solid var(--accent-warning);">STAGING</span>`;
                } else if (envStr === 'dev') {
                    envBadge = `<span class="badge" style="background-color: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid #60a5fa;">DEV</span>`;
                } else {
                    envBadge = `<span class="badge" style="background-color: rgba(100, 116, 139, 0.15); color: #94a3b8; border: 1px solid #94a3b8;">SANDBOX</span>`;
                }

                // Enrichment pills
                const enrichmentBadges = [];
                if (item.in_kev) {
                    enrichmentBadges.push('<span class="badge badge-danger">KEV</span>');
                }
                if (item.has_exploit) {
                    enrichmentBadges.push('<span class="badge badge-warning">EXPLOIT</span>');
                }
                const enrichmentStr = enrichmentBadges.length > 0 ? enrichmentBadges.join(' ') : '<span style="color: var(--text-secondary); font-size: 0.8rem;">None</span>';

                // Status banner
                let statusBadge = '';
                const statStr = (item.status || '').toLowerCase();
                if (statStr === 'pending') {
                    statusBadge = `<span class="status-banner" style="background-color: rgba(245, 158, 11, 0.12); color: var(--accent-warning); border: 1px solid rgba(245, 158, 11, 0.3);">Pending</span>`;
                } else if (statStr === 'approved') {
                    statusBadge = `<span class="status-banner status-approved">Approved</span>`;
                } else if (statStr === 'rejected') {
                    statusBadge = `<span class="status-banner status-rejected">Rejected</span>`;
                } else if (statStr === 'ticketed') {
                    statusBadge = `<span class="status-banner" style="background-color: rgba(59, 130, 246, 0.12); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3);">Ticketed</span>`;
                } else {
                    statusBadge = `<span class="status-banner" style="background-color: rgba(100, 116, 139, 0.12); color: #94a3b8; border: 1px solid rgba(100, 116, 139, 0.3);">${item.status}</span>`;
                }

                // Row action buttons - passing the array of triage_ids
                const triageIdsStr = JSON.stringify(item.triage_ids);
                const rowActionsHtml = (state.role !== 'analyst' && statStr === 'pending') ? `
                    <button class="btn btn-approve" style="padding: 0.35rem 0.65rem; font-size: 0.8rem;" onclick="actionSingleTriage(event, ${triageIdsStr}, 'approve')">Approve</button>
                    <button class="btn btn-reject" style="padding: 0.35rem 0.65rem; font-size: 0.8rem;" onclick="actionSingleTriage(event, ${triageIdsStr}, 'reject')">Reject</button>
                ` : `<span style="font-size: 0.8rem; color: var(--text-secondary);">${statStr === 'pending' ? 'Pending' : 'Locked'}</span>`;

                // Main data row
                const dataRow = document.createElement('tr');
                dataRow.id = `row-${item.triage_id}`;
                dataRow.className = `data-row ${isExpanded ? 'expanded' : ''}`;
                dataRow.onclick = (e) => handleRowClick(e, item.triage_id);
                
                let rowHtml = '';
                if (state.role !== 'analyst') {
                    rowHtml += `
                        <td class="checkbox-cell" onclick="event.stopPropagation()">
                            <input type="checkbox" ${isChecked ? 'checked' : ''} onchange="toggleRowSelection(${triageIdsStr}, this.checked)">
                        </td>
                    `;
                }
                
                rowHtml += `
                    <td><strong>${item.cve}</strong></td>
                    <td>
                        <div class="vuln-title">${item.title}</div>
                        <div class="asset-desc" style="cursor: pointer; text-decoration: underline dotted var(--accent-cyan); font-weight: 500;" data-asset-id="${item.asset_id}" data-hostname="${item.hostname}" data-env="${item.env || 'unknown'}" data-crit="${item.business_crit || 3}" data-team="${item.owner_team || ''}" onclick="openAssetPopover(event, this)">${item.hostname}</div>
                    </td>
                    <td><div style="display: flex; gap: 0.25rem; flex-wrap: wrap;">${sourceBadges}</div></td>
                    <td>${envBadge}</td>
                    <td><span class="cvss-val">${item.cvss}</span></td>
                    <td><span class="epss-val">${(item.epss * 100).toFixed(3)}%</span></td>
                    <td>${enrichmentStr}</td>
                    <td><span class="priority-score">${item.score}</span></td>
                    <td>${statusBadge}</td>
                `;
                
                if (state.role !== 'analyst') {
                    rowHtml += `<td onclick="event.stopPropagation()">${rowActionsHtml}</td>`;
                }
                
                dataRow.innerHTML = rowHtml;
                tbody.appendChild(dataRow);

                // Expanded detail row
                if (isExpanded) {
                    const detailRow = document.createElement('tr');
                    detailRow.className = 'detail-row';
                    
                    const descText = item.description || 'No description provided.';
                    const solutionText = item.vendor_advisory || 'No remediation details available.';
                    const prettyRaw = JSON.stringify(item.raw || {}, null, 2);

                    detailRow.innerHTML = `
                        <td colspan="${colSpanVal}">
                            <div class="detail-content">
                                <div class="detail-header-title">${item.cve} Detailed Findings</div>
                                <div class="detail-sections-grid">
                                    <div>
                                        <div class="detail-section">
                                            <div class="detail-sect-title">Description</div>
                                            <div class="detail-sect-body">${descText}</div>
                                        </div>
                                        <div class="detail-section" style="margin-top: 1rem;">
                                            <div class="detail-sect-title">Remediation / Solution</div>
                                            <div class="detail-sect-body">${solutionText}</div>
                                        </div>
                                    </div>
                                    <div>
                                        <div class="detail-sect-title">Raw Scanner JSON Payload</div>
                                        <pre class="raw-json"><code>${prettyRaw}</code></pre>
                                    </div>
                                </div>
                            </div>
                        </td>
                    `;
                    tbody.appendChild(detailRow);
                }
            });
        }

        // Render pagination controls
        function renderPagination() {
            const total = state.data.filtered;
            const limit = state.pagination.limit;
            const offset = state.pagination.offset;

            const startIdx = total === 0 ? 0 : offset + 1;
            const endIdx = Math.min(total, offset + limit);
            document.getElementById('filteredCountText').innerText = `${state.data.filtered} of ${state.data.total} findings`;
            document.getElementById('paginationRangeText').innerText = `Showing ${startIdx}-${endIdx} of ${total}`;

            // Buttons enable/disable
            document.getElementById('btnPrev').disabled = offset === 0;
            document.getElementById('btnNext').disabled = endIdx >= total;
        }

        // Filter triggers
        function handleFilterChange() {
            state.filters.source = document.getElementById('filterSource').value;
            state.filters.env = document.getElementById('filterEnv').value;
            state.filters.severity = document.getElementById('filterSeverity').value;
            state.filters.status = document.getElementById('filterStatus').value;
            
            // Reset offset and reload
            state.pagination.offset = 0;
            state.selectedIds.clear();
            fetchData();
        }

        function toggleChip(field) {
            const chip = document.getElementById(field === 'in_kev' ? 'chipKev' : 'chipExploit');
            const current = state.filters[field];
            const next = current === 'any' ? 'true' : (current === 'true' ? 'false' : 'any');
            
            state.filters[field] = next;
            
            if (next === 'true') {
                chip.className = 'toggle-chip active';
                chip.innerText = (field === 'in_kev' ? 'KEV: True' : 'Exploit: Yes');
            } else if (next === 'false') {
                chip.className = 'toggle-chip active';
                chip.style.backgroundColor = 'rgba(239, 68, 68, 0.12)';
                chip.style.color = 'var(--accent-red)';
                chip.style.borderColor = 'rgba(239, 68, 68, 0.4)';
                chip.innerText = (field === 'in_kev' ? 'KEV: False' : 'Exploit: No');
            } else {
                chip.className = 'toggle-chip';
                chip.style = '';
                chip.innerText = (field === 'in_kev' ? 'KEV' : 'Exploit');
            }
            
            state.pagination.offset = 0;
            state.selectedIds.clear();
            fetchData();
        }

        // Search trigger with debounce
        function handleSearchInput(event) {
            if (searchDebounceTimer) {
                clearTimeout(searchDebounceTimer);
            }
            searchDebounceTimer = setTimeout(() => {
                state.filters.q = event.target.value;
                state.pagination.offset = 0;
                state.selectedIds.clear();
                fetchData();
            }, 300);
        }

        // Sorting trigger
        function handleHeaderSort(field) {
            if (state.sort.field === field) {
                state.sort.direction = state.sort.direction === 'desc' ? 'asc' : 'desc';
            } else {
                state.sort.field = field;
                state.sort.direction = 'desc';
            }
            state.pagination.offset = 0;
            fetchData();
        }

        // Selection triggers
        function toggleRowSelection(triageIds, checked) {
            triageIds.forEach(id => {
                if (checked) {
                    state.selectedIds.add(id);
                } else {
                    state.selectedIds.delete(id);
                }
            });
            updateActionBar();
        }

        function toggleSelectAllHeader(checkbox) {
            toggleSelectAll(checkbox.checked);
        }

        function selectAllVisible() {
            toggleSelectAll(true);
            const selectAllCheck = document.getElementById('selectAllCheckbox');
            if (selectAllCheck) selectAllCheck.checked = true;
        }

        function toggleSelectAll(checked) {
            state.data.rows.forEach(item => {
                item.triage_ids.forEach(id => {
                    if (checked) {
                        state.selectedIds.add(id);
                    } else {
                        state.selectedIds.delete(id);
                    }
                });
            });
            
            // Re-render only inputs
            const inputs = document.querySelectorAll('#tableBody input[type="checkbox"]');
            inputs.forEach(input => {
                input.checked = checked;
            });
            
            updateActionBar();
        }

        // Action Bar updates
        function updateActionBar() {
            const count = state.selectedIds.size;
            
            // Enable/disable bulk buttons
            const btnApprove = document.getElementById('btnBulkApprove');
            const btnReject = document.getElementById('btnBulkReject');
            
            if (count > 0) {
                btnApprove.disabled = false;
                btnApprove.innerText = `Bulk Approve (${count})`;
                btnReject.disabled = false;
                btnReject.innerText = `Bulk Reject (${count})`;
            } else {
                btnApprove.disabled = true;
                btnApprove.innerText = 'Bulk Approve';
                btnReject.disabled = true;
                btnReject.innerText = 'Bulk Reject';
            }
            
            // Sync header select all checkbox
            const headerCheckbox = document.getElementById('selectAllCheckbox');
            if (headerCheckbox && state.data.rows.length > 0) {
                const allVisibleChecked = state.data.rows.every(item => item.triage_ids.every(id => state.selectedIds.has(id)));
                headerCheckbox.checked = allVisibleChecked;
            }
        }

        // Row Expand/Collapse
        function handleRowClick(event, triageId) {
            if (event.target.closest('input[type="checkbox"]') || event.target.closest('button') || event.target.closest('.asset-desc')) {
                return;
            }
            if (state.expandedRows.has(triageId)) {
                state.expandedRows.delete(triageId);
            } else {
                state.expandedRows.add(triageId);
            }
            renderTable();
        }

        // Page navigation
        function handlePageSizeChange() {
            state.pagination.limit = parseInt(document.getElementById('pageSizeSelect').value);
            state.pagination.offset = 0;
            fetchData();
        }

        function handlePageNavigate(dir) {
            const newOffset = state.pagination.offset + (dir * state.pagination.limit);
            if (newOffset >= 0 && newOffset < state.data.filtered) {
                state.pagination.offset = newOffset;
                fetchData();
            }
        }

        // Single Row Actions (calls bulk endpoints with all associated triage IDs)
        async function actionSingleTriage(event, triageIds, action) {
            event.stopPropagation();
            const btnApprove = event.target.parentNode.querySelector('.btn-approve');
            const btnReject = event.target.parentNode.querySelector('.btn-reject');
            if (btnApprove) btnApprove.disabled = true;
            if (btnReject) btnReject.disabled = true;

            try {
                const response = await window.apiFetch(`/api/findings/bulk/${action}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        triage_ids: triageIds,
                        approver: 'web-ui'
                    })
                });
                if (response.ok) {
                    const result = await response.json();
                    if (action === 'approve') {
                        const approved = result.approved_count;
                        const overflow = result.overflow_count;
                        if (overflow > 0) {
                            showToast('warning', `⚠ Approved ${approved}, ${overflow} hit daily cap`);
                        } else {
                            showToast('success', `✓ Approved ${approved} findings`);
                        }
                    } else {
                        showToast('success', `✓ Rejected ${result.rejected_count} findings`);
                    }
                    fetchData();
                } else {
                    if (btnApprove) btnApprove.disabled = false;
                    if (btnReject) btnReject.disabled = false;
                }
            } catch (err) {
                if (btnApprove) btnApprove.disabled = false;
                if (btnReject) btnReject.disabled = false;
            }
        }

        // Bulk Actions
        async function handleBulkAction(action) {
            const count = state.selectedIds.size;
            if (count === 0) return;

            const confirmed = await window.confirmDialog({
                title: `Bulk ${action.charAt(0).toUpperCase() + action.slice(1)} Confirmation`,
                message: `Are you sure you want to bulk ${action} ${count} vulnerabilities?`,
                confirmText: `Bulk ${action.charAt(0).toUpperCase() + action.slice(1)}`,
                confirmStyle: action === 'reject' ? 'danger' : 'primary'
            });
            if (!confirmed) return;

            const triageIds = Array.from(state.selectedIds);
            const payload = {
                triage_ids: triageIds,
                approver: 'web-ui'
            };

            const btnApprove = document.getElementById('btnBulkApprove');
            const btnReject = document.getElementById('btnBulkReject');
            btnApprove.disabled = true;
            btnReject.disabled = true;

            try {
                const response = await window.apiFetch(`/api/findings/bulk/${action}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(payload)
                });

                if (response.ok) {
                    const result = await response.json();
                    if (action === 'approve') {
                        const approved = result.approved_count;
                        const overflow = result.overflow_count;
                        if (overflow > 0) {
                            showToast('warning', `⚠ Approved ${approved}, ${overflow} hit daily cap`);
                        } else {
                            showToast('success', `✓ Approved ${approved} findings`);
                        }
                    } else {
                        showToast('success', `✓ Rejected ${result.rejected_count} findings`);
                    }
                    
                    // Clear selection and refetch
                    state.selectedIds.clear();
                    fetchData();
                } else {
                    btnApprove.disabled = false;
                    btnReject.disabled = false;
                }
            } catch (err) {
                btnApprove.disabled = false;
                btnReject.disabled = false;
            }
        }

        // Toasts
        function showToast(type, message) {
            window.toast(message, type === 'warning' ? 'warning' : type === 'success' ? 'success' : 'info');
        }

        // CSV File upload
        async function handleUpload(event) {
            event.preventDefault();
            const form = document.getElementById('uploadForm');
            const fileInput = document.getElementById('csvFile');
            const source = form.elements['source'].value;
            const statusPill = document.getElementById('uploadStatus');
            const errorsDiv = document.getElementById('uploadErrors');
            const submitBtn = event.target.querySelector('button[type="submit"]');
            
            const originalText = submitBtn.innerText;
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="spinner" style="display: inline-block; width: 0.8rem; height: 0.8rem; border: 2px solid #fff; border-top-color: transparent; border-radius: 50%; animation: spin 0.8s linear infinite; margin-right: 0.5rem; vertical-align: middle;"></span>Saving...';

            statusPill.style.display = 'inline-block';
            statusPill.className = 'status-banner';
            statusPill.style.backgroundColor = 'rgba(6, 182, 212, 0.15)';
            statusPill.style.color = 'var(--accent-cyan)';
            statusPill.style.border = '1px solid var(--accent-cyan)';
            statusPill.innerText = 'Uploading...';
            errorsDiv.style.display = 'none';
            
            const formData = new FormData();
            formData.append('file', fileInput.files[0]);
            formData.append('source', source);
            
            try {
                const response = await window.apiFetch('/upload', {
                    method: 'POST',
                    body: formData
                });
                const data = await response.json();
                
                if (response.ok && (!data.errors || data.errors.length === 0)) {
                    statusPill.style.backgroundColor = 'rgba(16, 185, 129, 0.15)';
                    statusPill.style.color = 'var(--accent-green)';
                    statusPill.style.border = '1px solid var(--accent-green)';
                    statusPill.innerText = `Parsed ${data.finding_count} findings across ${data.asset_count} assets → Done`;
                    
                    showToast('success', `✓ Successfully parsed CSV: ${data.finding_count} findings`);
                    setTimeout(() => {
                        statusPill.style.display = 'none';
                        fileInput.value = '';
                        submitBtn.disabled = false;
                        submitBtn.innerText = originalText;
                        fetchData();
                    }, 2500);
                } else {
                    statusPill.style.backgroundColor = 'rgba(239, 68, 68, 0.15)';
                    statusPill.style.color = 'var(--accent-red)';
                    statusPill.style.border = '1px solid var(--accent-red)';
                    statusPill.innerText = 'Failed';
                    
                    const errs = data.errors || ['Unknown error occurred.'];
                    errorsDiv.innerHTML = errs.map(e => `• ${e}`).join('<br>');
                    errorsDiv.style.display = 'block';
                    showToast('warning', `⚠ CSV Upload failed`);
                    submitBtn.disabled = false;
                    submitBtn.innerText = originalText;
                }
            } catch (e) {
                statusPill.style.backgroundColor = 'rgba(239, 68, 68, 0.15)';
                statusPill.style.color = 'var(--accent-red)';
                statusPill.style.border = '1px solid var(--accent-red)';
                statusPill.innerText = 'Error';
                errorsDiv.innerText = 'Network error: ' + e;
                errorsDiv.style.display = 'block';
                showToast('warning', `⚠ Upload network error`);
                submitBtn.disabled = false;
                submitBtn.innerText = originalText;
            }
        }

        function openAssetPopover(event, element) {
            event.stopPropagation();
            const assetId = element.getAttribute('data-asset-id');
            const hostname = element.getAttribute('data-hostname');
            const env = element.getAttribute('data-env');
            const businessCrit = element.getAttribute('data-crit');
            const ownerTeam = element.getAttribute('data-team');

            const popover = document.getElementById('assetPopover');
            document.getElementById('popoverHostname').innerText = hostname;
            document.getElementById('popoverAssetId').value = assetId;
            document.getElementById('popoverEnv').value = env;
            document.getElementById('popoverCrit').value = businessCrit;
            document.getElementById('popoverTeam').value = ownerTeam;

            // Position it
            const rect = element.getBoundingClientRect();
            const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
            const scrollLeft = window.pageXOffset || document.documentElement.scrollLeft;
            
            popover.style.top = `${rect.bottom + scrollTop + 8}px`;
            popover.style.left = `${rect.left + scrollLeft}px`;
            popover.style.display = 'block';
        }

        function closeAssetPopover() {
            document.getElementById('assetPopover').style.display = 'none';
        }

        async function saveAssetPopover() {
            const assetId = document.getElementById('popoverAssetId').value;
            const env = document.getElementById('popoverEnv').value;
            const crit = parseInt(document.getElementById('popoverCrit').value);
            const team = document.getElementById('popoverTeam').value;

            try {
                const response = await fetch(`/api/assets/${assetId}`, {
                    method: 'PATCH',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ environment: env, business_crit: crit, owner_team: team })
                });

                if (response.ok) {
                    const data = await response.json();
                    showToast('success', `✓ Asset updated! Rescored ${data.findings_rescored} findings`);
                    closeAssetPopover();
                    fetchData(); // Refetch findings
                } else {
                    const err = await response.json();
                    showToast('warning', `Failed to update asset: ${err.detail}`);
                }
            } catch (err) {
                showToast('warning', `Network error: ${err.message}`);
            }
        }

        // Close popover when clicking anywhere else
        document.addEventListener('click', (e) => {
            const popover = document.getElementById('assetPopover');
            if (popover && popover.style.display === 'block') {
                if (!popover.contains(e.target)) {
                    closeAssetPopover();
                }
            }
        });
    </script>
    
    <!-- Asset Metadata Popover -->
    <div id="assetPopover" style="
        display: none;
        position: absolute;
        z-index: 1000;
        background-color: var(--bg-secondary);
        border: 1px solid var(--border-color);
        border-radius: 12px;
        padding: 1.25rem;
        box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.7);
        width: 320px;
    ">
        <h3 id="popoverHostname" style="font-family: 'Outfit', sans-serif; font-size: 1.1rem; margin-bottom: 0.75rem; color: var(--accent-cyan);">Hostname</h3>
        <input type="hidden" id="popoverAssetId">
        <div style="display: flex; flex-direction: column; gap: 0.75rem;">
            <div>
                <label style="font-size: 0.75rem; color: var(--text-secondary); text-transform: uppercase; font-weight: 700; display: block; margin-bottom: 0.25rem;">Environment</label>
                <select id="popoverEnv" class="filter-control" style="width: 100%; box-sizing: border-box; background-image: url(&quot;data:image/svg+xml;utf8,&lt;svg fill='%2394a3b8' height='24' viewBox='0 0 24 24' width='24' xmlns='http://www.w3.org/2000/svg'&gt;&lt;path d='M7 10l5 5 5-5z'/&gt;&lt;/svg&gt;&quot;);">
                    <option value="prod">Prod</option>
                    <option value="staging">Staging</option>
                    <option value="dev">Dev</option>
                    <option value="sandbox">Sandbox</option>
                    <option value="unknown">Unknown</option>
                </select>
            </div>
            <div>
                <label style="font-size: 0.75rem; color: var(--text-secondary); text-transform: uppercase; font-weight: 700; display: block; margin-bottom: 0.25rem;">Business Criticality</label>
                <select id="popoverCrit" class="filter-control" style="width: 100%; box-sizing: border-box; background-image: url(&quot;data:image/svg+xml;utf8,&lt;svg fill='%2394a3b8' height='24' viewBox='0 0 24 24' width='24' xmlns='http://www.w3.org/2000/svg'&gt;&lt;path d='M7 10l5 5 5-5z'/&gt;&lt;/svg&gt;&quot;);">
                    <option value="1">1 - Low</option>
                    <option value="2">2 - Medium-Low</option>
                    <option value="3">3 - Medium</option>
                    <option value="4">4 - High</option>
                    <option value="5">5 - Critical</option>
                </select>
            </div>
            <div>
                <label style="font-size: 0.75rem; color: var(--text-secondary); text-transform: uppercase; font-weight: 700; display: block; margin-bottom: 0.25rem;">Owner Team</label>
                <input type="text" id="popoverTeam" class="search-input" style="width: 100%; box-sizing: border-box; padding: 0.5rem;" placeholder="e.g. SecOps">
            </div>
            <div style="display: flex; gap: 0.5rem; justify-content: flex-end; margin-top: 0.5rem;">
                <button class="btn btn-secondary" onclick="closeAssetPopover()" style="padding: 0.4rem 0.8rem; font-size: 0.8rem;">Cancel</button>
                <button class="btn btn-approve" onclick="saveAssetPopover()" style="padding: 0.4rem 0.8rem; font-size: 0.8rem;">Save</button>
            </div>
        </div>
    </div>
</body>
</html>"""
    return render_html(html_content)

@app.get("/assets.html", response_class=HTMLResponse)
def get_assets_html(user: dict = Depends(require_role("manager"))):
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Asset Metadata Management</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Outfit:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --border-color: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent-green: #10b981;
            --accent-red: #ef4444;
            --accent-warning: #f59e0b;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --accent-purple: #c084fc;
        }
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            padding: 2.5rem;
            display: flex;
            flex-direction: column;
            min-height: 100vh;
        }
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 1.5rem;
        }
        h1 {
            font-family: 'Outfit', sans-serif;
            font-size: 2rem;
            font-weight: 700;
            background: linear-gradient(135deg, #06b6d4 0%, #3b82f6 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .subtitle {
            font-size: 0.95rem;
            color: var(--text-secondary);
            margin-top: 0.25rem;
        }
        .container {
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3);
            margin-bottom: 2rem;
        }
        .filter-bar {
            background: rgba(30, 41, 59, 0.95);
            backdrop-filter: blur(8px);
            border: 1px solid var(--border-color);
            padding: 1rem 1.5rem;
            margin-bottom: 1.5rem;
            border-radius: 12px;
            display: flex;
            flex-wrap: wrap;
            gap: 1rem;
            align-items: center;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.4);
        }
        .filter-control {
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 0.5rem 2rem 0.5rem 0.75rem;
            border-radius: 6px;
            font-size: 0.85rem;
            outline: none;
            cursor: pointer;
            transition: border-color 0.2s;
            appearance: none;
            background-image: url("data:image/svg+xml;utf8,<svg fill='%2394a3b8' height='24' viewBox='0 0 24 24' width='24' xmlns='http://www.w3.org/2000/svg'><path d='M7 10l5 5 5-5z'/></svg>");
            background-repeat: no-repeat;
            background-position-x: 95%;
            background-position-y: 50%;
        }
        .filter-control:focus {
            border-color: var(--accent-cyan);
        }
        .search-input {
            flex-grow: 1;
            min-width: 200px;
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 0.5rem 0.75rem;
            border-radius: 6px;
            font-size: 0.85rem;
            outline: none;
            transition: border-color 0.2s;
        }
        .search-input:focus {
            border-color: var(--accent-cyan);
        }
        /* Table Styling */
        .table-container {
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3);
            margin-bottom: 1.5rem;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }
        th {
            position: sticky;
            top: 0;
            background-color: var(--bg-secondary);
            z-index: 10;
            padding: 1rem;
            font-family: 'Outfit', sans-serif;
            color: var(--text-secondary);
            border-bottom: 2px solid var(--border-color);
            font-weight: 600;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        th.sortable {
            cursor: pointer;
            user-select: none;
            transition: color 0.2s;
        }
        th.sortable:hover {
            color: var(--text-primary);
        }
        .sort-icon {
            font-size: 0.75rem;
            margin-left: 0.25rem;
            display: inline-block;
            width: 12px;
            color: var(--accent-cyan);
        }
        td {
            padding: 1rem;
            border-bottom: 1px solid var(--border-color);
            vertical-align: middle;
            font-size: 0.9rem;
        }
        tr.data-row {
            transition: background-color 0.2s;
        }
        tr.data-row:hover {
            background-color: rgba(255, 255, 255, 0.02);
        }
        .btn {
            padding: 0.5rem 0.9rem;
            border: none;
            border-radius: 6px;
            font-weight: 600;
            font-size: 0.85rem;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        .btn-approve {
            background-color: var(--accent-green);
            color: white;
        }
        .btn-approve:hover:not(:disabled) {
            background-color: #059669;
            transform: translateY(-1px);
        }
        .btn-secondary {
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
        }
        .btn-secondary:hover:not(:disabled) {
            border-color: var(--text-secondary);
            transform: translateY(-1px);
        }
        .btn:disabled {
            opacity: 0.4;
            cursor: not-allowed;
            transform: none !important;
        }
        .status-banner {
            display: inline-block;
            padding: 0.3rem 0.6rem;
            border-radius: 6px;
            font-weight: 600;
            font-size: 0.8rem;
            text-align: center;
        }
        .empty-state {
            text-align: center;
            color: var(--text-secondary);
            padding: 4rem;
            font-size: 1.1rem;
        }
        .badge {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 6px;
            font-size: 0.8rem;
            font-weight: 700;
        }
        .badge-info {
            background-color: rgba(6, 182, 212, 0.15);
            color: var(--accent-cyan);
            border: 1px solid var(--accent-cyan);
        }
        .badge-danger {
            background-color: rgba(239, 68, 68, 0.15);
            color: var(--accent-red);
            border: 1px solid var(--accent-red);
        }
        .badge-warning {
            background-color: rgba(245, 158, 11, 0.15);
            color: var(--accent-warning);
            border: 1px solid var(--accent-warning);
        }
        /* Inline input styling */
        .inline-select {
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 0.35rem 1.75rem 0.35rem 0.5rem;
            border-radius: 6px;
            font-size: 0.85rem;
            outline: none;
            cursor: pointer;
            transition: border-color 0.2s;
            appearance: none;
            background-image: url("data:image/svg+xml;utf8,<svg fill='%2394a3b8' height='20' viewBox='0 0 24 24' width='20' xmlns='http://www.w3.org/2000/svg'><path d='M7 10l5 5 5-5z'/></svg>");
            background-repeat: no-repeat;
            background-position-x: 95%;
            background-position-y: 50%;
        }
        .inline-select:focus {
            border-color: var(--accent-cyan);
        }
        .inline-input {
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 0.35rem 0.5rem;
            border-radius: 6px;
            font-size: 0.85rem;
            outline: none;
            width: 140px;
            transition: border-color 0.2s;
        }
        .inline-input:focus {
            border-color: var(--accent-cyan);
        }
        /* Pagination */
        .pagination-container {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem 1.5rem;
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            font-size: 0.9rem;
        }
        .pagination-left {
            color: var(--text-secondary);
        }
        .pagination-center {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .pagination-right {
            display: flex;
            gap: 0.5rem;
        }
        /* Toast style */
        .toast {
            background: rgba(15, 23, 42, 0.9);
            backdrop-filter: blur(8px);
            border: 1px solid var(--border-color);
            border-left: 4px solid var(--accent-green);
            padding: 1rem 1.5rem;
            border-radius: 8px;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.6);
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-family: 'Outfit', sans-serif;
            font-size: 0.9rem;
            min-width: 320px;
            animation: toastIn 0.3s cubic-bezier(0.16, 1, 0.3, 1);
            transition: opacity 0.3s, transform 0.3s;
        }
        .toast.warning {
            border-left-color: var(--accent-warning);
        }
        @keyframes toastIn {
            from { opacity: 0; transform: translateX(50px); }
            to { opacity: 1; transform: translateX(0); }
        }
        .toast-icon {
            font-size: 1.25rem;
        }
        footer {
            margin-top: 3rem;
            text-align: center;
            font-size: 0.85rem;
            color: var(--text-secondary);
            border-top: 1px solid var(--border-color);
            padding-top: 1.5rem;
        }
        header a:hover {
            color: var(--accent-cyan) !important;
        }
    </style>
</head>
<body>
    <header>
        <div>
            <h1>Asset Metadata Management</h1>
            <div class="subtitle">Update asset priority factors under strict audit control</div>
        </div>
        <div style="display: flex; align-items: center; gap: 1rem; flex-wrap: wrap;">
            <nav style="display: flex; align-items: center; gap: 0.75rem;">
                <a href="/brief.html" id="navFindings" style="color: var(--text-primary); text-decoration: none; font-weight: 600; font-size: 0.9rem; transition: color 0.2s;">Findings</a>
                <span style="color: var(--border-color); font-size: 0.9rem;">|</span>
                <a href="/assets.html" id="navAssets" style="color: var(--text-primary); text-decoration: none; font-weight: 600; font-size: 0.9rem; transition: color 0.2s;">Assets</a>
                <span id="navDividerAssets" style="color: var(--border-color); font-size: 0.9rem;">|</span>
                <span id="navDividerUsers" style="color: var(--border-color); font-size: 0.9rem; display: none;">|</span>
                <a href="/users.html" id="navUsers" style="color: var(--text-primary); text-decoration: none; font-weight: 600; font-size: 0.9rem; display: none; transition: color 0.2s;">Users</a>
                <span id="navDividerAudit" style="color: var(--border-color); font-size: 0.9rem; display: none;">|</span>
                <a href="/audit.html" id="navAudit" style="color: var(--text-primary); text-decoration: none; font-weight: 600; font-size: 0.9rem; display: none; transition: color 0.2s;">Audit</a>
                <span id="navDividerSettings" style="color: var(--border-color); font-size: 0.9rem; display: none;">|</span>
                <a href="/settings.html" id="navSettings" style="color: var(--text-primary); text-decoration: none; font-weight: 600; font-size: 0.9rem; display: none; transition: color 0.2s;">Settings</a>
            </nav>
            <span style="color: var(--border-color); font-size: 0.9rem;">|</span>
            <div style="display: flex; align-items: center; gap: 0.75rem;">
                <span id="headerUserInfo" style="font-weight: 500; color: var(--text-primary); font-size: 0.9rem;"></span>
                <span style="color: var(--text-secondary); font-size: 0.9rem;">|</span>
                <a href="/change-password.html" style="color: var(--accent-cyan); text-decoration: none; font-weight: 500; font-size: 0.9rem;">Change password</a>
                <span style="color: var(--text-secondary); font-size: 0.9rem;">|</span>
                <a href="#" onclick="handleLogout(event)" style="color: var(--accent-red); text-decoration: none; font-weight: 500; font-size: 0.9rem;">Logout</a>
            </div>
        </div>
    </header>

    <!-- Import assets upload card -->
    <div id="importAssetsCard" class="container" style="flex-grow: 0;">
        <h2 style="font-family: 'Outfit', sans-serif; font-size: 1.25rem; margin-bottom: 1rem; border-bottom: 1px solid var(--border-color); padding-bottom: 0.5rem; color: var(--accent-cyan);">Import Assets CSV</h2>
        <form id="uploadAssetsForm" onsubmit="handleAssetsUpload(event)" style="display: flex; flex-direction: column; gap: 1rem;">
            <div style="font-size: 0.85rem; color: var(--text-secondary);">
                Expected headers: <code style="color: var(--accent-warning);">hostname,environment,business_crit,owner_team</code>
            </div>
            <div style="display: flex; gap: 1rem; align-items: center;">
                <input type="file" id="assetsCsvFile" accept=".csv" required style="
                    background-color: var(--bg-primary);
                    border: 1px solid var(--border-color);
                    padding: 0.5rem;
                    border-radius: 6px;
                    color: var(--text-primary);
                    font-size: 0.85rem;
                    cursor: pointer;
                ">
                <button type="submit" class="btn btn-approve" style="padding: 0.6rem 1.2rem; font-family: 'Outfit', sans-serif; font-size: 0.9rem; margin-right: 0;">Upload CSV</button>
                <span id="uploadStatus" class="status-banner" style="display: none; padding: 0.5rem 1rem; font-size: 0.85rem;"></span>
            </div>
            <div id="uploadErrors" style="display: none; color: var(--accent-red); font-size: 0.85rem; margin-top: 0.5rem;"></div>
        </form>
    </div>

    <!-- Filter Bar -->
    <div class="filter-bar">
        <select id="filterEnv" class="filter-control" onchange="handleFilterChange()">
            <option value="all">All Environments</option>
            <option value="prod">Prod</option>
            <option value="staging">Staging</option>
            <option value="dev">Dev</option>
            <option value="sandbox">Sandbox</option>
            <option value="unknown">Unknown</option>
        </select>
        <input type="text" id="searchInput" class="search-input" placeholder="Search hostname..." oninput="handleSearchInput(event)">
    </div>

    <!-- Data Table Container -->
    <div class="table-container">
        <table id="assetsTable">
            <thead>
                <tr>
                    <th class="sortable" onclick="handleHeaderSort('hostname')">Hostname <span id="sort-hostname" class="sort-icon"></span></th>
                    <th>IP Address</th>
                    <th>Environment</th>
                    <th>Business Criticality</th>
                    <th>Owner Team</th>
                    <th class="sortable" onclick="handleHeaderSort('finding_count')">Finding Count <span id="sort-finding_count" class="sort-icon"></span></th>
                    <th class="sortable" onclick="handleHeaderSort('max_score')">Max Score <span id="sort-max_score" class="sort-icon"></span></th>
                    <th style="width: 100px;">Action</th>
                </tr>
            </thead>
            <tbody id="tableBody">
                <!-- Loaded dynamically -->
            </tbody>
        </table>
    </div>

    <!-- Pagination -->
    <div class="pagination-container">
        <div class="pagination-left" id="paginationRangeText">
            Showing 0-0 of 0
        </div>
        <div class="pagination-center">
            <span>Page Size:</span>
            <select id="pageSizeSelect" class="filter-control" style="padding: 0.3rem 1.5rem 0.3rem 0.5rem;" onchange="handlePageSizeChange()">
                <option value="25">25</option>
                <option value="50" selected>50</option>
                <option value="100">100</option>
                <option value="250">250</option>
            </select>
        </div>
        <div class="pagination-right">
            <button id="btnPrev" class="btn btn-secondary" onclick="handlePageNavigate(-1)">Prev</button>
            <button id="btnNext" class="btn btn-secondary" onclick="handlePageNavigate(1)">Next</button>
        </div>
    </div>

    <!-- Toast Container -->
    <div id="toastContainer" style="position: fixed; top: 1.5rem; right: 1.5rem; z-index: 1000; display: flex; flex-direction: column; gap: 0.75rem;"></div>

    <footer>
        Vulnerability Triage Co-Pilot v1.0 • Under Strict Audit Control
    </footer>

    <script>
        const state = {
            filters: {
                env: 'all',
                q: ''
            },
            pagination: {
                limit: 50,
                offset: 0
            },
            sort: {
                field: 'hostname',
                direction: 'asc'
            },
            data: {
                total: 0,
                rows: []
            },
            role: null
        };

        let searchDebounceTimer = null;

        window.addEventListener('DOMContentLoaded', () => {
            checkAuthAndInit();
        });

        async function checkAuthAndInit() {
            try {
                const response = await fetch('/api/me');
                if (!response.ok) {
                    window.location.href = '/login.html';
                    return;
                }
                const user = await response.json();
                document.getElementById('headerUserInfo').innerText = `${user.username} (${user.role})`;
                
                if (user.role === 'admin') {
                    const navUsers = document.getElementById('navUsers');
                    if (navUsers) navUsers.style.display = 'inline';
                    const navDividerUsers = document.getElementById('navDividerUsers');
                    if (navDividerUsers) navDividerUsers.style.display = 'inline';
                    const navAudit = document.getElementById('navAudit');
                    if (navAudit) navAudit.style.display = 'inline';
                    const navDividerAudit = document.getElementById('navDividerAudit');
                    if (navDividerAudit) navDividerAudit.style.display = 'inline';
                    const navSettings = document.getElementById('navSettings');
                    if (navSettings) navSettings.style.display = 'inline';
                    const navDividerSettings = document.getElementById('navDividerSettings');
                    if (navDividerSettings) navDividerSettings.style.display = 'inline';
                }
                if (user.role === 'analyst') {
                    const navAssets = document.getElementById('navAssets');
                    if (navAssets) navAssets.style.display = 'none';
                    const navDividerAssets = document.getElementById('navDividerAssets');
                    if (navDividerAssets) navDividerAssets.style.display = 'none';
                }
                
                applyRoleUI(user.role);
                fetchData();
            } catch (err) {
                window.location.href = '/login.html';
            }
        }

        async function handleLogout(event) {
            event.preventDefault();
            try {
                await fetch('/api/logout', { method: 'POST' });
            } catch (err) {}
            window.location.href = '/login.html';
        }

        function applyRoleUI(role) {
            state.role = role;
            if (role !== 'admin') {
                const importCard = document.getElementById('importAssetsCard');
                if (importCard) importCard.style.display = 'none';
            }
        }

        async function fetchData() {
            const params = new URLSearchParams();
            params.append('q', state.filters.q);
            params.append('env', state.filters.env);
            params.append('limit', state.pagination.limit);
            params.append('offset', state.pagination.offset);
            params.append('sort', `${state.sort.field}_${state.sort.direction}`);

            const tbody = document.getElementById('tableBody');
            tbody.innerHTML = `
                <tr>
                    <td colspan="8" style="text-align: center; padding: 3rem 0; color: var(--text-secondary);">
                        <div class="spinner" style="display: inline-block; width: 1.5rem; height: 1.5rem; border: 3px solid var(--border-color); border-top-color: var(--accent-cyan); border-radius: 50%; animation: spin 0.8s linear infinite; margin-bottom: 0.5rem;"></div>
                        <div style="font-weight: 500;" class="text-muted">Loading assets...</div>
                    </td>
                </tr>
            `;

            try {
                const response = await window.apiFetch(`/api/assets?${params.toString()}`);
                if (!response.ok) {
                    throw new Error(`HTTP Error ${response.status}`);
                }
                const resData = await response.json();
                state.data = resData;
                
                renderTable();
                renderPagination();
            } catch (err) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="8" style="text-align: center; padding: 3rem 0; color: var(--accent-red);">
                            Failed to load assets.
                        </td>
                    </tr>
                `;
            }
        }

        function renderTable() {
            const tbody = document.getElementById('tableBody');
            tbody.innerHTML = '';

            const sortFields = ['hostname', 'finding_count', 'max_score'];
            sortFields.forEach(field => {
                const el = document.getElementById(`sort-${field}`);
                if (el) {
                    if (state.sort.field === field) {
                        el.innerText = state.sort.direction === 'desc' ? ' ▼' : ' ▲';
                    } else {
                        el.innerText = '';
                    }
                }
            });

            if (state.data.rows.length === 0) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="8" style="text-align: center; padding: 4rem 1rem;">
                            <div style="font-size: 2.5rem; margin-bottom: 1rem;">✨</div>
                            <h3 style="font-family: 'Outfit'; font-size: 1.25rem; margin-bottom: 0.5rem; color: var(--text-primary);">No assets found</h3>
                            <p style="color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 1.5rem;">Try adjusting search terms or filters</p>
                        </td>
                    </tr>
                `;
                return;
            }

            const isManager = (state.role === 'manager');
            const disabledAttr = isManager ? 'disabled' : '';

            state.data.rows.forEach(item => {
                const row = document.createElement('tr');
                row.className = 'data-row';
                
                const maxScore = item.max_score || 0.0;
                
                row.innerHTML = `
                    <td><strong>${item.hostname}</strong></td>
                    <td><span style="font-family: monospace;">${item.ip || 'N/A'}</span></td>
                    <td>
                        <select id="env-${item.id}" class="inline-select" onchange="saveRow(${item.id})" ${disabledAttr}>
                            <option value="prod" ${item.environment === 'prod' ? 'selected' : ''}>Prod</option>
                            <option value="staging" ${item.environment === 'staging' ? 'selected' : ''}>Staging</option>
                            <option value="dev" ${item.environment === 'dev' ? 'selected' : ''}>Dev</option>
                            <option value="sandbox" ${item.environment === 'sandbox' ? 'selected' : ''}>Sandbox</option>
                            <option value="unknown" ${item.environment === 'unknown' ? 'selected' : ''}>Unknown</option>
                        </select>
                    </td>
                    <td>
                        <select id="crit-${item.id}" class="inline-select" onchange="saveRow(${item.id})" ${disabledAttr}>
                            <option value="1" ${item.business_crit === 1 ? 'selected' : ''}>1 - Low</option>
                            <option value="2" ${item.business_crit === 2 ? 'selected' : ''}>2 - Medium-Low</option>
                            <option value="3" ${item.business_crit === 3 ? 'selected' : ''}>3 - Medium</option>
                            <option value="4" ${item.business_crit === 4 ? 'selected' : ''}>4 - High</option>
                            <option value="5" ${item.business_crit === 5 ? 'selected' : ''}>5 - Critical</option>
                        </select>
                    </td>
                    <td>
                        <input type="text" id="team-${item.id}" class="inline-input" value="${item.owner_team || ''}" onchange="saveRow(${item.id})" ${disabledAttr}>
                    </td>
                    <td><span class="badge badge-info">${item.finding_count} findings</span></td>
                    <td><span class="badge ${maxScore >= 9.0 ? 'badge-danger' : (maxScore >= 7.0 ? 'badge-warning' : 'badge-info')}">${maxScore.toFixed(2)}</span></td>
                    <td>
                        <button id="btn-${item.id}" class="btn btn-approve" style="padding: 0.35rem 0.65rem; font-size: 0.8rem;" onclick="saveRow(${item.id})" ${disabledAttr}>Save</button>
                    </td>
                `;
                tbody.appendChild(row);
            });
        }

        async function saveRow(id) {
            if (state.role === 'manager') {
                showToast('warning', 'Permission denied: managers cannot edit assets.');
                return;
            }

            const envVal = document.getElementById(`env-${id}`).value;
            const critVal = parseInt(document.getElementById(`crit-${id}`).value);
            const teamVal = document.getElementById(`team-${id}`).value;
            
            const btn = document.getElementById(`btn-${id}`);
            btn.disabled = true;
            btn.innerText = 'Saving...';
            
            try {
                const response = await window.apiFetch(`/api/assets/${id}`, {
                    method: 'PATCH',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ environment: envVal, business_crit: critVal, owner_team: teamVal })
                });
                if (response.ok) {
                    const data = await response.json();
                    showToast('success', `✓ Saved asset metadata! Rescored ${data.findings_rescored} findings`);
                    btn.innerText = 'Saved!';
                    setTimeout(() => {
                        btn.innerText = 'Save';
                        btn.disabled = false;
                    }, 1000);
                    fetchData();
                } else {
                    btn.innerText = 'Save';
                    btn.disabled = false;
                }
            } catch (e) {
                btn.innerText = 'Save';
                btn.disabled = false;
            }
        }

        function renderPagination() {
            const total = state.data.total;
            const limit = state.pagination.limit;
            const offset = state.pagination.offset;

            const startIdx = total === 0 ? 0 : offset + 1;
            const endIdx = Math.min(total, offset + limit);

            document.getElementById('paginationRangeText').innerText = `Showing ${startIdx}-${endIdx} of ${total}`;

            document.getElementById('btnPrev').disabled = offset === 0;
            document.getElementById('btnNext').disabled = endIdx >= total;
        }

        function handleFilterChange() {
            state.filters.env = document.getElementById('filterEnv').value;
            state.pagination.offset = 0;
            fetchData();
        }

        function handleSearchInput(event) {
            if (searchDebounceTimer) {
                clearTimeout(searchDebounceTimer);
            }
            searchDebounceTimer = setTimeout(() => {
                state.filters.q = event.target.value;
                state.pagination.offset = 0;
                fetchData();
            }, 300);
        }

        function handleHeaderSort(field) {
            if (state.sort.field === field) {
                state.sort.direction = state.sort.direction === 'desc' ? 'asc' : 'desc';
            } else {
                state.sort.field = field;
                state.sort.direction = 'desc';
            }
            state.pagination.offset = 0;
            fetchData();
        }

        function handlePageSizeChange() {
            state.pagination.limit = parseInt(document.getElementById('pageSizeSelect').value);
            state.pagination.offset = 0;
            fetchData();
        }

        function handlePageNavigate(dir) {
            const newOffset = state.pagination.offset + (dir * state.pagination.limit);
            if (newOffset >= 0 && newOffset < state.data.total) {
                state.pagination.offset = newOffset;
                fetchData();
            }
        }

        function showToast(type, message) {
            window.toast(message, type === 'warning' ? 'warning' : type === 'success' ? 'success' : 'info');
        }

        async function handleAssetsUpload(event) {
            event.preventDefault();
            const form = document.getElementById('uploadAssetsForm');
            const fileInput = document.getElementById('assetsCsvFile');
            const statusPill = document.getElementById('uploadStatus');
            const errorsDiv = document.getElementById('uploadErrors');
            const submitBtn = event.target.querySelector('button[type="submit"]');
            
            const originalText = submitBtn.innerText;
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="spinner" style="display: inline-block; width: 0.8rem; height: 0.8rem; border: 2px solid #fff; border-top-color: transparent; border-radius: 50%; animation: spin 0.8s linear infinite; margin-right: 0.5rem; vertical-align: middle;"></span>Saving...';

            statusPill.style.display = 'inline-block';
            statusPill.className = 'status-banner';
            statusPill.style.backgroundColor = 'rgba(6, 182, 212, 0.15)';
            statusPill.style.color = 'var(--accent-cyan)';
            statusPill.style.border = '1px solid var(--accent-cyan)';
            statusPill.innerText = 'Uploading...';
            errorsDiv.style.display = 'none';
            
            const formData = new FormData();
            formData.append('file', fileInput.files[0]);
            
            try {
                const response = await window.apiFetch('/api/assets/bulk/upload', {
                    method: 'POST',
                    body: formData
                });
                const data = await response.json();
                
                if (response.ok && (!data.errors || data.errors.length === 0)) {
                    statusPill.style.backgroundColor = 'rgba(16, 185, 129, 0.15)';
                    statusPill.style.color = 'var(--accent-green)';
                    statusPill.style.border = '1px solid var(--accent-green)';
                    statusPill.innerText = `Uploaded ${data.updated_assets} assets → Done`;
                    
                    showToast('success', `✓ Successfully imported ${data.updated_assets} assets`);
                    setTimeout(() => {
                        statusPill.style.display = 'none';
                        fileInput.value = '';
                        submitBtn.disabled = false;
                        submitBtn.innerText = originalText;
                        fetchData();
                    }, 2500);
                } else {
                    statusPill.style.backgroundColor = 'rgba(239, 68, 68, 0.15)';
                    statusPill.style.color = 'var(--accent-red)';
                    statusPill.style.border = '1px solid var(--accent-red)';
                    statusPill.innerText = 'Failed';
                    
                    const errs = data.errors || ['Unknown error occurred.'];
                    errorsDiv.innerHTML = errs.map(e => `• ${e}`).join('<br>');
                    errorsDiv.style.display = 'block';
                    showToast('warning', `⚠ Assets CSV Upload failed`);
                    submitBtn.disabled = false;
                    submitBtn.innerText = originalText;
                }
            } catch (e) {
                statusPill.style.backgroundColor = 'rgba(239, 68, 68, 0.15)';
                statusPill.style.color = 'var(--accent-red)';
                statusPill.style.border = '1px solid var(--accent-red)';
                statusPill.innerText = 'Error';
                errorsDiv.innerText = 'Network error: ' + e;
                errorsDiv.style.display = 'block';
                showToast('warning', `⚠ Upload network error`);
                submitBtn.disabled = false;
                submitBtn.innerText = originalText;
            }
        }
    </script>
</body>
</html>"""
    return render_html(html_content)


@app.get("/users.html", response_class=HTMLResponse)
def get_users_html(user: dict = Depends(require_role("admin"))):
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Management</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Outfit:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --border-color: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent-green: #10b981;
            --accent-red: #ef4444;
            --accent-warning: #f59e0b;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --accent-purple: #c084fc;
        }
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            padding: 2.5rem;
            display: flex;
            flex-direction: column;
            min-height: 100vh;
        }
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 1.5rem;
            flex-wrap: wrap;
            gap: 1rem;
        }
        header a:hover {
            color: var(--accent-cyan) !important;
        }
        h1 {
            font-family: 'Outfit', sans-serif;
            font-size: 2rem;
            font-weight: 700;
            background: linear-gradient(135deg, #06b6d4 0%, #3b82f6 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .subtitle {
            font-size: 0.95rem;
            color: var(--text-secondary);
            margin-top: 0.25rem;
        }
        .container {
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3);
            margin-bottom: 2rem;
        }
        /* Table Styling */
        .table-container {
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3);
            margin-bottom: 1.5rem;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }
        th {
            position: sticky;
            top: 0;
            background-color: var(--bg-secondary);
            z-index: 10;
            padding: 1rem;
            font-family: 'Outfit', sans-serif;
            color: var(--text-secondary);
            border-bottom: 2px solid var(--border-color);
            font-weight: 600;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        td {
            padding: 1rem;
            border-bottom: 1px solid var(--border-color);
            vertical-align: middle;
            font-size: 0.9rem;
        }
        tr.data-row {
            transition: background-color 0.2s;
        }
        tr.data-row:hover {
            background-color: rgba(255, 255, 255, 0.02);
        }
        .btn {
            padding: 0.5rem 0.9rem;
            border: none;
            border-radius: 6px;
            font-weight: 600;
            font-size: 0.85rem;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        .btn-approve {
            background-color: var(--accent-green);
            color: white;
        }
        .btn-approve:hover:not(:disabled) {
            background-color: #059669;
            transform: translateY(-1px);
        }
        .btn-secondary {
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
        }
        .btn-secondary:hover:not(:disabled) {
            border-color: var(--text-secondary);
            transform: translateY(-1px);
        }
        .btn:disabled {
            opacity: 0.4;
            cursor: not-allowed;
            transform: none !important;
        }
        .status-banner {
            display: inline-block;
            padding: 0.3rem 0.6rem;
            border-radius: 6px;
            font-weight: 600;
            font-size: 0.8rem;
            text-align: center;
        }
        .empty-state {
            text-align: center;
            color: var(--text-secondary);
            padding: 4rem;
            font-size: 1.1rem;
        }
        .badge {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 6px;
            font-size: 0.8rem;
            font-weight: 700;
        }
        .badge-info {
            background-color: rgba(6, 182, 212, 0.15);
            color: var(--accent-cyan);
            border: 1px solid var(--accent-cyan);
        }
        .badge-danger {
            background-color: rgba(239, 68, 68, 0.15);
            color: var(--accent-red);
            border: 1px solid var(--accent-red);
        }
        .badge-warning {
            background-color: rgba(245, 158, 11, 0.15);
            color: var(--accent-warning);
            border: 1px solid var(--accent-warning);
        }
        /* Modal Styling */
        .modal {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(15, 23, 42, 0.85);
            backdrop-filter: blur(8px);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 2000;
        }
        .modal-content {
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 2rem;
            width: 100%;
            max-width: 480px;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.7);
            display: flex;
            flex-direction: column;
            gap: 1.25rem;
        }
        .form-group {
            display: flex;
            flex-direction: column;
            gap: 0.35rem;
        }
        .form-group label {
            font-size: 0.75rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            font-weight: 700;
            display: block;
        }
        .form-control {
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 0.6rem 0.8rem;
            border-radius: 6px;
            font-size: 0.9rem;
            outline: none;
            width: 100%;
            transition: border-color 0.2s;
        }
        .form-control:focus {
            border-color: var(--accent-cyan);
        }
        /* Toast style */
        .toast {
            background: rgba(15, 23, 42, 0.9);
            backdrop-filter: blur(8px);
            border: 1px solid var(--border-color);
            border-left: 4px solid var(--accent-green);
            padding: 1rem 1.5rem;
            border-radius: 8px;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.6);
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-family: 'Outfit', sans-serif;
            font-size: 0.9rem;
            min-width: 320px;
            animation: toastIn 0.3s cubic-bezier(0.16, 1, 0.3, 1);
            transition: opacity 0.3s, transform 0.3s;
        }
        .toast.warning {
            border-left-color: var(--accent-warning);
        }
        @keyframes toastIn {
            from { opacity: 0; transform: translateX(50px); }
            to { opacity: 1; transform: translateX(0); }
        }
        .toast-icon {
            font-size: 1.25rem;
        }
        footer {
            margin-top: 3rem;
            text-align: center;
            font-size: 0.85rem;
            color: var(--text-secondary);
            border-top: 1px solid var(--border-color);
            padding-top: 1.5rem;
        }
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <header>
        <div>
            <h1>User Management</h1>
            <div class="subtitle">Admin Control Panel for RBAC Dashboard Users</div>
        </div>
        <div style="display: flex; align-items: center; gap: 1rem; flex-wrap: wrap;">
            <nav style="display: flex; align-items: center; gap: 0.75rem;">
                <a href="/brief.html" id="navFindings" style="color: var(--text-primary); text-decoration: none; font-weight: 600; font-size: 0.9rem; transition: color 0.2s;">Findings</a>
                <span style="color: var(--border-color); font-size: 0.9rem;">|</span>
                <a href="/assets.html" id="navAssets" style="color: var(--text-primary); text-decoration: none; font-weight: 600; font-size: 0.9rem; transition: color 0.2s;">Assets</a>
                <span id="navDividerAssets" style="color: var(--border-color); font-size: 0.9rem;">|</span>
                <span id="navDividerUsers" style="color: var(--border-color); font-size: 0.9rem; display: none;">|</span>
                <a href="/users.html" id="navUsers" style="color: var(--text-primary); text-decoration: none; font-weight: 600; font-size: 0.9rem; display: none; transition: color 0.2s;">Users</a>
                <span id="navDividerAudit" style="color: var(--border-color); font-size: 0.9rem; display: none;">|</span>
                <a href="/audit.html" id="navAudit" style="color: var(--text-primary); text-decoration: none; font-weight: 600; font-size: 0.9rem; display: none; transition: color 0.2s;">Audit</a>
                <span id="navDividerSettings" style="color: var(--border-color); font-size: 0.9rem; display: none;">|</span>
                <a href="/settings.html" id="navSettings" style="color: var(--text-primary); text-decoration: none; font-weight: 600; font-size: 0.9rem; display: none; transition: color 0.2s;">Settings</a>
            </nav>
            <span style="color: var(--border-color); font-size: 0.9rem;">|</span>
            <div style="display: flex; align-items: center; gap: 0.75rem;">
                <span id="headerUserInfo" style="font-weight: 500; color: var(--text-primary); font-size: 0.9rem;"></span>
                <span style="color: var(--text-secondary); font-size: 0.9rem;">|</span>
                <a href="/change-password.html" style="color: var(--accent-cyan); text-decoration: none; font-weight: 500; font-size: 0.9rem;">Change password</a>
                <span style="color: var(--text-secondary); font-size: 0.9rem;">|</span>
                <a href="#" onclick="handleLogout(event)" style="color: var(--accent-red); text-decoration: none; font-weight: 500; font-size: 0.9rem;">Logout</a>
            </div>
        </div>
    </header>

    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; flex-wrap: wrap; gap: 1rem;">
        <div style="display: flex; align-items: center; gap: 1rem; flex-wrap: wrap;">
            <input type="text" id="userSearch" class="form-control" style="max-width: 250px; background-color: var(--bg-secondary); border: 1px solid var(--border-color); color: var(--text-primary); padding: 0.5rem; border-radius: 6px;" placeholder="Search users..." oninput="handleSearchInput()">
            <label style="display: flex; align-items: center; gap: 0.5rem; font-size: 0.85rem; color: var(--text-secondary); cursor: pointer; user-select: none;">
                <input type="checkbox" id="showInactive" onchange="handleSearchInput()" style="accent-color: var(--accent-cyan);">
                Show Inactive
            </label>
        </div>
        <div style="display: flex; align-items: center; gap: 1rem;">
            <span id="rowCountBadge" style="font-size: 0.85rem; color: var(--text-secondary);">Showing 0-0 of 0</span>
            <button class="btn btn-approve" onclick="openAddModal()" style="font-family: 'Outfit', sans-serif;">Add User</button>
        </div>
    </div>

    <!-- User Table -->
    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Username</th>
                    <th>Full Name</th>
                    <th>Role</th>
                    <th>Status</th>
                    <th>Must Change Password</th>
                    <th>Last Login</th>
                    <th>Created At</th>
                    <th>Created By</th>
                    <th style="width: 150px;">Actions</th>
                </tr>
            </thead>
            <tbody id="tableBody">
                <!-- Dynamically populated -->
            </tbody>
        </table>
    </div>

    <!-- Add User Modal -->
    <div id="addModal" class="modal">
        <form class="modal-content" onsubmit="submitAddUser(event)">
            <h2 style="font-family: 'Outfit', sans-serif; font-size: 1.3rem; color: var(--accent-cyan);">Create New User</h2>
            
            <div class="form-group">
                <label>Username</label>
                <input type="text" id="addUsername" class="form-control" placeholder="e.g. jdoe" required>
            </div>

            <div class="form-group">
                <label>Full Name</label>
                <input type="text" id="addFullName" class="form-control" placeholder="e.g. Jane Doe" required>
            </div>

            <div class="form-group">
                <label>Role</label>
                <select id="addRole" class="form-control" style="cursor: pointer;">
                    <option value="analyst">Analyst</option>
                    <option value="manager">Manager</option>
                    <option value="admin">Admin</option>
                </select>
            </div>

            <div class="form-group">
                <label>Password (Optional)</label>
                <input type="password" id="addPassword" class="form-control" placeholder="Leave blank for 'changeme'">
            </div>

            <div style="display: flex; gap: 0.5rem; justify-content: flex-end; margin-top: 0.5rem;">
                <button type="button" class="btn btn-secondary" onclick="closeAddModal()">Cancel</button>
                <button type="submit" class="btn btn-approve">Create</button>
            </div>
        </form>
    </div>

    <!-- Edit User Modal -->
    <div id="editModal" class="modal">
        <form class="modal-content" onsubmit="submitEditUser(event)">
            <h2 style="font-family: 'Outfit', sans-serif; font-size: 1.3rem; color: var(--accent-cyan);">Edit User</h2>
            
            <div class="form-group">
                <label>Full Name</label>
                <input type="text" id="editFullName" class="form-control" required>
            </div>

            <div class="form-group">
                <label>Role</label>
                <select id="editRole" class="form-control" style="cursor: pointer;">
                    <option value="analyst">Analyst</option>
                    <option value="manager">Manager</option>
                    <option value="admin">Admin</option>
                </select>
            </div>

            <div class="form-group" style="flex-direction: row; align-items: center; gap: 0.5rem;">
                <input type="checkbox" id="editActive" style="width: 18px; height: 18px; cursor: pointer; accent-color: var(--accent-cyan);">
                <label for="editActive" style="text-transform: none; font-size: 0.9rem; font-weight: 500; color: var(--text-primary); cursor: pointer;">User Account Active</label>
            </div>

            <div class="form-group">
                <label>Reset Password (Optional)</label>
                <input type="password" id="editPassword" class="form-control" placeholder="Enter new password to reset">
            </div>

            <div style="display: flex; gap: 0.5rem; justify-content: flex-end; margin-top: 0.5rem;">
                <button type="button" class="btn btn-secondary" onclick="closeEditModal()">Cancel</button>
                <button type="submit" class="btn btn-approve">Save Changes</button>
            </div>
        </form>
    </div>

    <div id="toastContainer" style="position: fixed; top: 1.5rem; right: 1.5rem; z-index: 2500; display: flex; flex-direction: column; gap: 0.75rem;"></div>

    <footer>
        Vulnerability Triage Co-Pilot v1.0 • Under Strict Audit Control
    </footer>

    <script>
        const state = {
            data: {
                rows: []
            },
            role: null,
            currentUser: null,
            filters: {
                q: '',
                showInactive: false
            }
        };

        window.addEventListener('DOMContentLoaded', () => {
            checkAuthAndInit();
        });

        async function checkAuthAndInit() {
            try {
                const response = await window.apiFetch('/api/me');
                if (!response.ok) {
                    window.location.href = '/login.html';
                    return;
                }
                const user = await response.json();
                state.currentUser = user;
                document.getElementById('headerUserInfo').innerText = `${user.username} (${user.role})`;
                
                if (user.role === 'admin') {
                    const navUsers = document.getElementById('navUsers');
                    if (navUsers) navUsers.style.display = 'inline';
                    const navDividerUsers = document.getElementById('navDividerUsers');
                    if (navDividerUsers) navDividerUsers.style.display = 'inline';
                    const navAudit = document.getElementById('navAudit');
                    if (navAudit) navAudit.style.display = 'inline';
                    const navDividerAudit = document.getElementById('navDividerAudit');
                    if (navDividerAudit) navDividerAudit.style.display = 'inline';
                    const navSettings = document.getElementById('navSettings');
                    if (navSettings) navSettings.style.display = 'inline';
                    const navDividerSettings = document.getElementById('navDividerSettings');
                    if (navDividerSettings) navDividerSettings.style.display = 'inline';
                } else {
                    window.location.href = '/brief.html';
                    return;
                }
                
                fetchUsers();
            } catch (err) {
                window.location.href = '/login.html';
            }
        }

        async function handleLogout(event) {
            event.preventDefault();
            try {
                await window.apiFetch('/api/logout', { method: 'POST' });
            } catch (err) {}
            window.location.href = '/login.html';
        }

        async function fetchUsers() {
            const tbody = document.getElementById('tableBody');
            tbody.innerHTML = `
                <tr>
                    <td colspan="10" style="text-align: center; padding: 3rem 0; color: var(--text-secondary);">
                        <div class="spinner" style="display: inline-block; width: 1.5rem; height: 1.5rem; border: 3px solid var(--border-color); border-top-color: var(--accent-cyan); border-radius: 50%; animation: spin 0.8s linear infinite; margin-bottom: 0.5rem;"></div>
                        <div style="font-weight: 500;" class="text-muted">Loading users...</div>
                    </td>
                </tr>
            `;
            try {
                const response = await window.apiFetch('/api/admin/users');
                if (!response.ok) {
                    return;
                }
                const data = await response.json();
                state.data.rows = data.rows;
                renderTable();
            } catch (e) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="10" style="text-align: center; padding: 3rem 0; color: var(--accent-red);">
                            Failed to load users.
                        </td>
                    </tr>
                `;
            }
        }

        function handleSearchInput() {
            state.filters.q = document.getElementById('userSearch').value.toLowerCase().trim();
            state.filters.showInactive = document.getElementById('showInactive').checked;
            renderTable();
        }

        function renderTable() {
            const tbody = document.getElementById('tableBody');
            tbody.innerHTML = '';

            const query = state.filters.q;
            const filtered = state.data.rows.filter(item => {
                const matchQuery = !query || 
                    (item.username && item.username.toLowerCase().includes(query)) ||
                    (item.full_name && item.full_name.toLowerCase().includes(query));
                const matchActive = state.filters.showInactive || item.active;
                return matchQuery && matchActive;
            });

            const totalCount = state.data.rows.length;
            const filteredCount = filtered.length;
            document.getElementById('rowCountBadge').innerText = `Showing ${filteredCount} of ${totalCount}`;

            if (filteredCount === 0) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="10" style="text-align: center; padding: 4rem 1rem;">
                            <div style="font-size: 2.5rem; margin-bottom: 1rem;">🔍</div>
                            <h3 style="font-family: 'Outfit'; font-size: 1.25rem; margin-bottom: 0.5rem; color: var(--text-primary);">No users found</h3>
                            <p style="color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 1.5rem;">Try adjusting search terms or clearing filters</p>
                        </td>
                    </tr>
                `;
                return;
            }

            filtered.forEach(item => {
                const row = document.createElement('tr');
                row.className = 'data-row';
                
                const isSelf = item.id === state.currentUser.id;
                const isAdmin = item.role === 'admin';
                
                const activeAdmins = state.data.rows.filter(u => u.role === 'admin' && u.active).length;
                const canDisable = !isSelf && (!isAdmin || activeAdmins > 1);

                row.innerHTML = `
                    <td><strong>${item.id}</strong></td>
                    <td><strong>${item.username}</strong></td>
                    <td>${item.full_name}</td>
                    <td><span class="badge ${item.role === 'admin' ? 'badge-danger' : (item.role === 'manager' ? 'badge-warning' : 'badge-info')}">${item.role}</span></td>
                    <td>
                        <span class="status-banner" style="
                            background-color: ${item.active ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)'};
                            color: ${item.active ? 'var(--accent-green)' : 'var(--accent-red)'};
                            border: 1px solid ${item.active ? 'var(--accent-green)' : 'var(--accent-red)'};
                        ">
                            ${item.active ? 'Active' : 'Inactive'}
                        </span>
                    </td>
                    <td><span style="color: ${item.must_change_password ? 'var(--accent-warning)' : 'var(--text-secondary)'}; font-weight: 600;">${item.must_change_password ? 'Yes' : 'No'}</span></td>
                    <td><span style="font-size: 0.8rem; font-family: monospace;">${item.last_login_at ? new Date(item.last_login_at).toLocaleString() : 'Never'}</span></td>
                    <td><span style="font-size: 0.8rem; font-family: monospace;">${item.created_at ? new Date(item.created_at).toLocaleString() : 'N/A'}</span></td>
                    <td>${item.created_by_username || 'System'}</td>
                    <td>
                        <div style="display: flex; gap: 0.5rem;">
                            <button class="btn btn-secondary" style="padding: 0.35rem 0.65rem; font-size: 0.8rem;" onclick="openEditModal(${item.id})">Edit</button>
                            <button class="btn btn-secondary" style="
                                padding: 0.35rem 0.65rem; 
                                font-size: 0.8rem;
                                color: var(--accent-red);
                                border-color: rgba(239, 68, 68, 0.3);
                            " 
                            onclick="handleDisableUser(${item.id}, '${item.username}')"
                            ${(canDisable && item.active) ? '' : 'disabled'}
                            >Disable</button>
                        </div>
                    </td>
                `;
                tbody.appendChild(row);
            });
        }

        function openAddModal() {
            document.getElementById('addModal').style.display = 'flex';
            document.getElementById('addUsername').value = '';
            document.getElementById('addFullName').value = '';
            document.getElementById('addRole').value = 'analyst';
            document.getElementById('addPassword').value = '';
            document.getElementById('addUsername').focus();
        }

        function closeAddModal() {
            document.getElementById('addModal').style.display = 'none';
        }

        async function submitAddUser(e) {
            e.preventDefault();
            const username = document.getElementById('addUsername').value.trim();
            const fullName = document.getElementById('addFullName').value.trim();
            const role = document.getElementById('addRole').value;
            const password = document.getElementById('addPassword').value;

            const submitBtn = e.target.querySelector('button[type="submit"]');
            const originalText = submitBtn.innerText;
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="spinner" style="display: inline-block; width: 0.8rem; height: 0.8rem; border: 2px solid #fff; border-top-color: transparent; border-radius: 50%; animation: spin 0.8s linear infinite; margin-right: 0.5rem; vertical-align: middle;"></span>Saving...';

            try {
                const response = await window.apiFetch('/api/admin/users', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, full_name: fullName, role, password })
                });

                if (response.ok) {
                    const data = await response.json();
                    closeAddModal();
                    showCredentialsToast(username, password || 'changeme');
                    fetchUsers();
                }
            } catch (err) {
                // apiFetch will show toast automatically
            } finally {
                submitBtn.disabled = false;
                submitBtn.innerText = originalText;
            }
        }

        let editingUserId = null;

        function openEditModal(id) {
            editingUserId = id;
            const user = state.data.rows.find(u => u.id === id);
            if (!user) return;

            document.getElementById('editModal').style.display = 'flex';
            document.getElementById('editFullName').value = user.full_name;
            document.getElementById('editRole').value = user.role;
            document.getElementById('editActive').checked = user.active;
            document.getElementById('editPassword').value = '';
            
            const isSelf = user.id === state.currentUser.id;
            
            const activeCheckbox = document.getElementById('editActive');
            if (isSelf) {
                activeCheckbox.disabled = true;
                document.getElementById('editRole').disabled = true;
            } else {
                activeCheckbox.disabled = false;
                document.getElementById('editRole').disabled = false;
            }
            
            document.getElementById('editFullName').focus();
        }

        function closeEditModal() {
            document.getElementById('editModal').style.display = 'none';
        }

        async function submitEditUser(e) {
            e.preventDefault();
            const fullName = document.getElementById('editFullName').value.trim();
            const role = document.getElementById('editRole').value;
            const active = document.getElementById('editActive').checked;
            const password = document.getElementById('editPassword').value;

            const submitBtn = e.target.querySelector('button[type="submit"]');
            const originalText = submitBtn.innerText;
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="spinner" style="display: inline-block; width: 0.8rem; height: 0.8rem; border: 2px solid #fff; border-top-color: transparent; border-radius: 50%; animation: spin 0.8s linear infinite; margin-right: 0.5rem; vertical-align: middle;"></span>Saving...';

            const body = {
                full_name: fullName,
                role: role,
                active: active
            };
            if (password) {
                body.password = password;
            }

            try {
                const response = await window.apiFetch(`/api/admin/users/${editingUserId}`, {
                    method: 'PATCH',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body)
                });

                if (response.ok) {
                    closeEditModal();
                    window.toast('✓ User updated successfully', 'success');
                    if (password) {
                        const user = state.data.rows.find(u => u.id === editingUserId);
                        showCredentialsToast(user.username, password);
                    }
                    fetchUsers();
                }
            } catch (err) {
                // apiFetch will show toast automatically
            } finally {
                submitBtn.disabled = false;
                submitBtn.innerText = originalText;
            }
        }

        async function handleDisableUser(id, username) {
            const confirmed = await window.confirmDialog({
                title: 'Disable User',
                message: `Are you sure you want to disable user ${username}?`,
                confirmText: 'Disable',
                confirmStyle: 'danger'
            });
            if (!confirmed) return;

            try {
                const response = await window.apiFetch(`/api/admin/users/${id}`, {
                    method: 'DELETE'
                });
                if (response.ok) {
                    window.toast(`✓ Disabled user ${username}`, 'success');
                    fetchUsers();
                }
            } catch (e) {
                // apiFetch will show toast automatically
            }
        }

        // Generic Esc and Backdrop click modal close logic
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                closeAddModal();
                closeEditModal();
            }
        });
        document.getElementById('addModal').addEventListener('click', function(e) {
            if (e.target === this) {
                closeAddModal();
            }
        });
        document.getElementById('editModal').addEventListener('click', function(e) {
            if (e.target === this) {
                closeEditModal();
            }
        });

        function showCredentialsToast(username, password) {
            const container = document.getElementById('toastContainer');
            const toast = document.createElement('div');
            toast.className = 'toast';
            toast.style.borderLeftColor = 'var(--accent-cyan)';
            toast.style.minWidth = '400px';
            toast.style.flexDirection = 'column';
            toast.style.alignItems = 'flex-start';
            toast.style.gap = '0.5rem';
            
            toast.innerHTML = `
                <div style="display: flex; align-items: center; gap: 0.5rem; width: 100%;">
                    <span class="toast-icon">🔐</span>
                    <strong style="color: var(--accent-cyan);">Credentials Generated</strong>
                    <button onclick="this.parentElement.parentElement.remove()" style="margin-left: auto; background: none; border: none; color: var(--text-secondary); cursor: pointer; font-size: 1.1rem;">×</button>
                </div>
                <div style="font-size: 0.85rem; color: var(--text-primary); margin-top: 0.25rem; width: 100%;">
                    <p>Provide these credentials to the user. They must change their password upon first login.</p>
                    <div style="background-color: var(--bg-primary); border: 1px solid var(--border-color); padding: 0.5rem; border-radius: 4px; margin-top: 0.5rem; display: flex; flex-direction: column; gap: 0.25rem;">
                        <div>Username: <code style="color: var(--accent-warning); font-weight: bold; font-family: monospace;">${username}</code></div>
                        <div>Password: <code style="color: var(--accent-warning); font-weight: bold; font-family: monospace;">${password}</code></div>
                    </div>
                </div>
            `;
            container.appendChild(toast);
        }
    </script>
</body>
</html>"""
    return render_html(html_content)


@app.get("/audit.html", response_class=HTMLResponse)
def get_audit_html(user: dict = Depends(require_role("admin"))):
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Audit Logs</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Outfit:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --border-color: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent-green: #10b981;
            --accent-red: #ef4444;
            --accent-warning: #f59e0b;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --accent-purple: #c084fc;
        }
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            padding: 2.5rem;
            display: flex;
            flex-direction: column;
            min-height: 100vh;
        }
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 1.5rem;
            flex-wrap: wrap;
            gap: 1rem;
        }
        header a:hover {
            color: var(--accent-cyan) !important;
        }
        h1 {
            font-family: 'Outfit', sans-serif;
            font-size: 2rem;
            font-weight: 700;
            background: linear-gradient(135deg, #06b6d4 0%, #3b82f6 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .subtitle {
            font-size: 0.95rem;
            color: var(--text-secondary);
            margin-top: 0.25rem;
        }
        .container {
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3);
            margin-bottom: 2rem;
        }
        .filter-bar {
            background: rgba(30, 41, 59, 0.95);
            backdrop-filter: blur(8px);
            border: 1px solid var(--border-color);
            padding: 1rem 1.5rem;
            margin-bottom: 1.5rem;
            border-radius: 12px;
            display: flex;
            flex-wrap: wrap;
            gap: 1rem;
            align-items: center;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.4);
        }
        .filter-control {
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 0.5rem 2rem 0.5rem 0.75rem;
            border-radius: 6px;
            font-size: 0.85rem;
            outline: none;
            cursor: pointer;
            transition: border-color 0.2s;
            appearance: none;
            background-repeat: no-repeat;
            background-position-x: 95%;
            background-position-y: 50%;
        }
        select.filter-control {
            background-image: url("data:image/svg+xml;utf8,<svg fill='%2394a3b8' height='24' viewBox='0 0 24 24' width='24' xmlns='http://www.w3.org/2000/svg'><path d='M7 10l5 5 5-5z'/></svg>");
        }
        .filter-control:focus {
            border-color: var(--accent-cyan);
        }
        .search-input {
            flex-grow: 1;
            min-width: 200px;
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 0.5rem 0.75rem;
            border-radius: 6px;
            font-size: 0.85rem;
            outline: none;
            transition: border-color 0.2s;
        }
        .search-input:focus {
            border-color: var(--accent-cyan);
        }
        .datetime-input {
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 0.45rem 0.75rem;
            border-radius: 6px;
            font-size: 0.85rem;
            outline: none;
            transition: border-color 0.2s;
        }
        .datetime-input:focus {
            border-color: var(--accent-cyan);
        }
        /* Table Styling */
        .table-container {
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3);
            margin-bottom: 1.5rem;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }
        th {
            position: sticky;
            top: 0;
            background-color: var(--bg-secondary);
            z-index: 10;
            padding: 1rem;
            font-family: 'Outfit', sans-serif;
            color: var(--text-secondary);
            border-bottom: 2px solid var(--border-color);
            font-weight: 600;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        td {
            padding: 1rem;
            border-bottom: 1px solid var(--border-color);
            vertical-align: middle;
            font-size: 0.9rem;
        }
        tr.data-row {
            transition: background-color 0.2s;
        }
        tr.data-row:hover {
            background-color: rgba(255, 255, 255, 0.02);
        }
        .btn {
            padding: 0.5rem 0.9rem;
            border: none;
            border-radius: 6px;
            font-weight: 600;
            font-size: 0.85rem;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        .btn-approve {
            background-color: var(--accent-green);
            color: white;
        }
        .btn-approve:hover:not(:disabled) {
            background-color: #059669;
            transform: translateY(-1px);
        }
        .btn-secondary {
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
        }
        .btn-secondary:hover:not(:disabled) {
            border-color: var(--text-secondary);
            transform: translateY(-1px);
        }
        .btn:disabled {
            opacity: 0.4;
            cursor: not-allowed;
            transform: none !important;
        }
        .status-banner {
            display: inline-block;
            padding: 0.3rem 0.6rem;
            border-radius: 6px;
            font-weight: 600;
            font-size: 0.8rem;
            text-align: center;
        }
        .empty-state {
            text-align: center;
            color: var(--text-secondary);
            padding: 4rem;
            font-size: 1.1rem;
        }
        .badge {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 6px;
            font-size: 0.8rem;
            font-weight: 700;
        }
        .badge-info {
            background-color: rgba(6, 182, 212, 0.15);
            color: var(--accent-cyan);
            border: 1px solid var(--accent-cyan);
        }
        .badge-danger {
            background-color: rgba(239, 68, 68, 0.15);
            color: var(--accent-red);
            border: 1px solid var(--accent-red);
        }
        .badge-warning {
            background-color: rgba(245, 158, 11, 0.15);
            color: var(--accent-warning);
            border: 1px solid var(--accent-warning);
        }
        .badge-purple {
            background-color: rgba(192, 132, 252, 0.15);
            color: var(--accent-purple);
            border: 1px solid var(--accent-purple);
        }
        /* Pagination */
        .pagination-container {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem 1.5rem;
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            font-size: 0.9rem;
        }
        .pagination-left {
            color: var(--text-secondary);
        }
        .pagination-center {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .pagination-right {
            display: flex;
            gap: 0.5rem;
        }
        /* Toast style */
        .toast {
            background: rgba(15, 23, 42, 0.9);
            backdrop-filter: blur(8px);
            border: 1px solid var(--border-color);
            border-left: 4px solid var(--accent-green);
            padding: 1rem 1.5rem;
            border-radius: 8px;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.6);
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-family: 'Outfit', sans-serif;
            font-size: 0.9rem;
            min-width: 320px;
            animation: toastIn 0.3s cubic-bezier(0.16, 1, 0.3, 1);
            transition: opacity 0.3s, transform 0.3s;
        }
        .toast.warning {
            border-left-color: var(--accent-warning);
        }
        @keyframes toastIn {
            from { opacity: 0; transform: translateX(50px); }
            to { opacity: 1; transform: translateX(0); }
        }
        .toast-icon {
            font-size: 1.25rem;
        }
        footer {
            margin-top: 3rem;
            text-align: center;
            font-size: 0.85rem;
            color: var(--text-secondary);
            border-top: 1px solid var(--border-color);
            padding-top: 1.5rem;
        }
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <header>
        <div>
            <h1>Audit Logs</h1>
            <div class="subtitle">System activity and security log history under strict compliance control</div>
        </div>
        <div style="display: flex; align-items: center; gap: 1rem; flex-wrap: wrap;">
            <nav style="display: flex; align-items: center; gap: 0.75rem;">
                <a href="/brief.html" id="navFindings" style="color: var(--text-primary); text-decoration: none; font-weight: 600; font-size: 0.9rem; transition: color 0.2s;">Findings</a>
                <span style="color: var(--border-color); font-size: 0.9rem;">|</span>
                <a href="/assets.html" id="navAssets" style="color: var(--text-primary); text-decoration: none; font-weight: 600; font-size: 0.9rem; transition: color 0.2s;">Assets</a>
                <span id="navDividerAssets" style="color: var(--border-color); font-size: 0.9rem;">|</span>
                <span id="navDividerUsers" style="color: var(--border-color); font-size: 0.9rem; display: none;">|</span>
                <a href="/users.html" id="navUsers" style="color: var(--text-primary); text-decoration: none; font-weight: 600; font-size: 0.9rem; display: none; transition: color 0.2s;">Users</a>
                <span id="navDividerAudit" style="color: var(--border-color); font-size: 0.9rem; display: none;">|</span>
                <a href="/audit.html" id="navAudit" style="color: var(--text-primary); text-decoration: none; font-weight: 600; font-size: 0.9rem; display: none; transition: color 0.2s;">Audit</a>
                <span id="navDividerSettings" style="color: var(--border-color); font-size: 0.9rem; display: none;">|</span>
                <a href="/settings.html" id="navSettings" style="color: var(--text-primary); text-decoration: none; font-weight: 600; font-size: 0.9rem; display: none; transition: color 0.2s;">Settings</a>
            </nav>
            <span style="color: var(--border-color); font-size: 0.9rem;">|</span>
            <div style="display: flex; align-items: center; gap: 0.75rem;">
                <span id="headerUserInfo" style="font-weight: 500; color: var(--text-primary); font-size: 0.9rem;"></span>
                <span style="color: var(--text-secondary); font-size: 0.9rem;">|</span>
                <a href="/change-password.html" style="color: var(--accent-cyan); text-decoration: none; font-weight: 500; font-size: 0.9rem;">Change password</a>
                <span style="color: var(--text-secondary); font-size: 0.9rem;">|</span>
                <a href="#" onclick="handleLogout(event)" style="color: var(--accent-red); text-decoration: none; font-weight: 500; font-size: 0.9rem;">Logout</a>
            </div>
        </div>
    </header>

    <!-- Filters Section -->
    <div class="filter-bar">
        <select id="filterActor" class="filter-control" style="padding-right: 1.5rem;" onchange="handleFilterChange()">
            <option value="">All Actors</option>
        </select>
        <select id="filterAction" class="filter-control" style="padding-right: 1.5rem;" onchange="handleFilterChange()">
            <option value="">All Actions</option>
        </select>
        <div style="display: flex; align-items: center; gap: 0.5rem;">
            <span style="font-size: 0.8rem; color: var(--text-secondary); text-transform: uppercase; font-weight: bold;">From:</span>
            <input type="datetime-local" id="filterFrom" class="datetime-input" onchange="handleFilterChange()">
        </div>
        <div style="display: flex; align-items: center; gap: 0.5rem;">
            <span style="font-size: 0.8rem; color: var(--text-secondary); text-transform: uppercase; font-weight: bold;">To:</span>
            <input type="datetime-local" id="filterTo" class="datetime-input" onchange="handleFilterChange()">
        </div>
        <input type="text" id="searchInput" class="search-input" placeholder="Search details..." oninput="handleSearchInput(event)">
        <button class="btn btn-secondary" onclick="resetFilters()">Reset</button>
        <button class="btn btn-approve" onclick="exportCSV()">Export CSV</button>
    </div>

    <!-- Audit Logs Table -->
    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th style="width: 220px;">Time</th>
                    <th>Actor</th>
                    <th>Action</th>
                    <th>Target</th>
                    <th style="text-align: right; width: 150px;">Details</th>
                </tr>
            </thead>
            <tbody id="tableBody">
                <!-- Dynamically populated -->
            </tbody>
        </table>
    </div>

    <!-- Pagination -->
    <div class="pagination-container">
        <div class="pagination-left" id="paginationRangeText">
            Showing 0-0 of 0
        </div>
        <div class="pagination-center">
            <span>Page Size:</span>
            <select id="pageSizeSelect" class="filter-control" style="padding: 0.3rem 1.5rem 0.3rem 0.5rem; background-image: url(&quot;data:image/svg+xml;utf8,&lt;svg fill='%2394a3b8' height='20' viewBox='0 0 24 24' width='20' xmlns='http://www.w3.org/2000/svg'&gt;&lt;path d='M7 10l5 5 5-5z'/&gt;&lt;/svg&gt;&quot;);" onchange="handlePageSizeChange()">
                <option value="25" selected>25</option>
                <option value="50">50</option>
                <option value="100">100</option>
            </select>
        </div>
        <div class="pagination-right">
            <button id="btnPrev" class="btn btn-secondary" onclick="handlePageNavigate(-1)">Prev</button>
            <button id="btnNext" class="btn btn-secondary" onclick="handlePageNavigate(1)">Next</button>
        </div>
    </div>

    <div id="toastContainer" style="position: fixed; top: 1.5rem; right: 1.5rem; z-index: 2500; display: flex; flex-direction: column; gap: 0.75rem;"></div>

    <footer>
        Vulnerability Triage Co-Pilot v1.0 • Under Strict Audit Control
    </footer>

    <script>
        const state = {
            filters: {
                actor: '',
                action: '',
                from: '',
                to: '',
                q: ''
            },
            pagination: {
                limit: 25,
                offset: 0
            },
            data: {
                total: 0,
                rows: []
            }
        };

        let searchDebounceTimer = null;

        window.addEventListener('DOMContentLoaded', () => {
            checkAuthAndInit();
        });

        async function checkAuthAndInit() {
            try {
                const response = await window.apiFetch('/api/me');
                if (!response.ok) {
                    window.location.href = '/login.html';
                    return;
                }
                const user = await response.json();
                document.getElementById('headerUserInfo').innerText = `${user.username} (${user.role})`;
                
                if (user.role === 'admin') {
                    const navUsers = document.getElementById('navUsers');
                    if (navUsers) navUsers.style.display = 'inline';
                    const navDividerUsers = document.getElementById('navDividerUsers');
                    if (navDividerUsers) navDividerUsers.style.display = 'inline';
                    const navAudit = document.getElementById('navAudit');
                    if (navAudit) navAudit.style.display = 'inline';
                    const navDividerAudit = document.getElementById('navDividerAudit');
                    if (navDividerAudit) navDividerAudit.style.display = 'inline';
                    const navSettings = document.getElementById('navSettings');
                    if (navSettings) navSettings.style.display = 'inline';
                    const navDividerSettings = document.getElementById('navDividerSettings');
                    if (navDividerSettings) navDividerSettings.style.display = 'inline';
                } else {
                    window.location.href = '/brief.html';
                    return;
                }
                
                loadFilters();
                fetchData();
            } catch (err) {
                window.location.href = '/login.html';
            }
        }

        async function handleLogout(event) {
            event.preventDefault();
            try {
                await window.apiFetch('/api/logout', { method: 'POST' });
            } catch (err) {}
            window.location.href = '/login.html';
        }

        async function loadFilters() {
            try {
                const actorsRes = await window.apiFetch('/api/audit/actors');
                if (actorsRes.ok) {
                    const actors = await actorsRes.json();
                    const select = document.getElementById('filterActor');
                    actors.forEach(act => {
                        const opt = document.createElement('option');
                        opt.value = act;
                        opt.innerText = act;
                        select.appendChild(opt);
                    });
                }
                const actionsRes = await window.apiFetch('/api/audit/actions');
                if (actionsRes.ok) {
                    const actions = await actionsRes.json();
                    const select = document.getElementById('filterAction');
                    actions.forEach(act => {
                        const opt = document.createElement('option');
                        opt.value = act;
                        opt.innerText = act;
                        select.appendChild(opt);
                    });
                }
            } catch (e) {
                console.error("Error loading filters", e);
            }
        }

        async function fetchData() {
            const params = new URLSearchParams();
            if (state.filters.actor) params.append('actor', state.filters.actor);
            if (state.filters.action) params.append('action', state.filters.action);
            if (state.filters.from) params.append('from', new Date(state.filters.from).toISOString());
            if (state.filters.to) params.append('to', new Date(state.filters.to).toISOString());
            if (state.filters.q) params.append('q', state.filters.q);
            
            params.append('limit', state.pagination.limit);
            params.append('offset', state.pagination.offset);

            const tbody = document.getElementById('tableBody');
            tbody.innerHTML = `
                <tr>
                    <td colspan="5" style="text-align: center; padding: 3rem 0; color: var(--text-secondary);">
                        <div class="spinner" style="display: inline-block; width: 1.5rem; height: 1.5rem; border: 3px solid var(--border-color); border-top-color: var(--accent-cyan); border-radius: 50%; animation: spin 0.8s linear infinite; margin-bottom: 0.5rem;"></div>
                        <div style="font-weight: 500;" class="text-muted">Loading audit logs...</div>
                    </td>
                </tr>
            `;

            try {
                const response = await window.apiFetch(`/api/audit?${params.toString()}`);
                if (!response.ok) {
                    throw new Error(`HTTP Error ${response.status}`);
                }
                const resData = await response.json();
                state.data = resData;
                
                renderTable();
                renderPagination();
            } catch (err) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="5" style="text-align: center; padding: 3rem 0; color: var(--accent-red);">
                            Failed to load audit logs.
                        </td>
                    </tr>
                `;
            }
        }

        function formatAuditTime(isoStr) {
            const d = new Date(isoStr);
            const now = new Date();
            
            const isToday = d.getDate() === now.getDate() &&
                            d.getMonth() === now.getMonth() &&
                            d.getFullYear() === now.getFullYear();
                            
            const pad = (num) => String(num).padStart(2, '0');
            const timeStr = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
            
            if (isToday) {
                return timeStr;
            } else {
                const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
                return `${months[d.getMonth()]} ${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
            }
        }

        function renderTable() {
            const tbody = document.getElementById('tableBody');
            tbody.innerHTML = '';

            if (state.data.rows.length === 0) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="5" style="text-align: center; padding: 4rem 1rem;">
                            <div style="font-size: 2.5rem; margin-bottom: 1rem;">🔍</div>
                            <h3 style="font-family: 'Outfit'; font-size: 1.25rem; margin-bottom: 0.5rem; color: var(--text-primary);">No audit events found</h3>
                            <p style="color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 1.5rem;">No audit events match these filters</p>
                        </td>
                    </tr>
                `;
                return;
            }

            state.data.rows.forEach((item, index) => {
                const row = document.createElement('tr');
                row.className = 'data-row';
                row.style.cursor = 'pointer';
                row.onclick = () => toggleDetails(index);
                
                let badgeStyleClass = 'badge-warning';
                const action = item.action || '';
                if (action.includes('approve') || action.includes('success')) {
                    badgeStyleClass = 'badge-info';
                } else if (action.includes('reject') || action.includes('failed') || action.includes('disabled') || action.includes('reset')) {
                    badgeStyleClass = 'badge-danger';
                } else if (action.includes('user')) {
                    badgeStyleClass = 'badge-purple';
                }

                const formattedTime = formatAuditTime(item.occurred_at);
                const fullTime = new Date(item.occurred_at).toLocaleString();
                
                row.innerHTML = `
                    <td style="font-family: monospace; font-size: 0.85rem;" title="${fullTime}">${formattedTime}</td>
                    <td><strong>${item.actor || 'anonymous'}</strong></td>
                    <td><span class="badge ${badgeStyleClass}">${action}</span></td>
                    <td><span style="font-family: monospace; font-size: 0.85rem;">${item.target || 'N/A'}</span></td>
                    <td style="text-align: right; color: var(--accent-cyan); font-weight: 600; font-size: 0.85rem;">Click to expand</td>
                `;
                
                tbody.appendChild(row);

                const detailRow = document.createElement('tr');
                detailRow.id = `detail-${index}`;
                detailRow.style.display = 'none';
                detailRow.style.backgroundColor = 'rgba(15, 23, 42, 0.4)';
                
                const detailData = item.detail || item.details || {};
                
                detailRow.innerHTML = `
                    <td colspan="5" style="padding: 1.5rem; border-bottom: 1px solid var(--border-color);">
                        <pre style="
                            margin: 0;
                            padding: 1rem;
                            background-color: var(--bg-primary);
                            border: 1px solid var(--border-color);
                            border-radius: 8px;
                            overflow-x: auto;
                            font-family: monospace;
                            font-size: 0.85rem;
                            color: var(--text-primary);
                        ">${JSON.stringify(detailData, null, 2)}</pre>
                    </td>
                `;
                tbody.appendChild(detailRow);
            });
        }

        function toggleDetails(index) {
            const el = document.getElementById(`detail-${index}`);
            if (el.style.display === 'none') {
                el.style.display = 'table-row';
            } else {
                el.style.display = 'none';
            }
        }

        function handleFilterChange() {
            state.filters.actor = document.getElementById('filterActor').value;
            state.filters.action = document.getElementById('filterAction').value;
            state.filters.from = document.getElementById('filterFrom').value;
            state.filters.to = document.getElementById('filterTo').value;
            state.pagination.offset = 0;
            fetchData();
        }

        function handleSearchInput(event) {
            if (searchDebounceTimer) {
                clearTimeout(searchDebounceTimer);
            }
            searchDebounceTimer = setTimeout(() => {
                state.filters.q = event.target.value;
                state.pagination.offset = 0;
                fetchData();
            }, 300);
        }

        function resetFilters() {
            document.getElementById('filterActor').value = '';
            document.getElementById('filterAction').value = '';
            document.getElementById('filterFrom').value = '';
            document.getElementById('filterTo').value = '';
            document.getElementById('searchInput').value = '';
            state.filters = { actor: '', action: '', from: '', to: '', q: '' };
            state.pagination.offset = 0;
            fetchData();
        }

        function exportCSV() {
            const params = new URLSearchParams();
            if (state.filters.actor) params.append('actor', state.filters.actor);
            if (state.filters.action) params.append('action', state.filters.action);
            if (state.filters.from) params.append('from', new Date(state.filters.from).toISOString());
            if (state.filters.to) params.append('to', new Date(state.filters.to).toISOString());
            if (state.filters.q) params.append('q', state.filters.q);
            
            window.location.href = `/api/audit/export.csv?${params.toString()}`;
        }

        function renderPagination() {
            const total = state.data.total;
            const limit = state.pagination.limit;
            const offset = state.pagination.offset;

            const startIdx = total === 0 ? 0 : offset + 1;
            const endIdx = Math.min(total, offset + limit);

            document.getElementById('paginationRangeText').innerText = `Showing ${startIdx}-${endIdx} of ${total}`;

            document.getElementById('btnPrev').disabled = offset === 0;
            document.getElementById('btnNext').disabled = endIdx >= total;
        }

        function handlePageSizeChange() {
            state.pagination.limit = parseInt(document.getElementById('pageSizeSelect').value);
            state.pagination.offset = 0;
            fetchData();
        }

        function handlePageNavigate(dir) {
            const newOffset = state.pagination.offset + (dir * state.pagination.limit);
            if (newOffset >= 0 && newOffset < state.data.total) {
                state.pagination.offset = newOffset;
                fetchData();
            }
        }
    </script>
</body>
</html>"""
    return render_html(html_content)


# Integrations API Models
class IntegrationUpdateRequest(BaseModel):
    config: dict
    secrets: dict
    enabled: bool

@app.get("/api/admin/integrations")
def get_integrations_list(user: dict = Depends(require_role("manager"))):
    try:
        from _lib.integrations import decrypt_secrets
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT i.integration_key, i.config, i.enabled, i.last_test_status, 
                           i.last_test_message, i.last_tested_at, i.updated_at, 
                           u.username AS updated_by_username, i.secrets_encrypted
                    FROM integration_settings i
                    LEFT JOIN users u ON i.updated_by = u.id
                    ORDER BY i.integration_key;
                    """
                )
                rows = cur.fetchall()
                res = []
                for r in rows:
                    key = r[0]
                    config = r[1] or {}
                    enabled = r[2]
                    last_test_status = r[3] or 'never'
                    last_test_message = r[4] or ''
                    last_tested_at = r[5].isoformat() if r[5] else None
                    updated_at = r[6].isoformat() if r[6] else None
                    updated_by_username = r[7]
                    secrets_encrypted = r[8]
                    
                    secrets_dict = {}
                    if secrets_encrypted is not None:
                        secrets_dict = decrypt_secrets(secrets_encrypted)
                    else:
                        from _lib.integrations import get_env_secrets_fallback
                        secrets_dict = get_env_secrets_fallback(key)
                        
                    secret_keys_set = [k for k, v in secrets_dict.items() if v]
                    has_secrets = len(secret_keys_set) > 0
                    
                    res.append({
                        "integration_key": key,
                        "config": config,
                        "enabled": enabled,
                        "last_test_status": last_test_status,
                        "last_test_message": last_test_message,
                        "last_tested_at": last_tested_at,
                        "updated_at": updated_at,
                        "updated_by_username": updated_by_username,
                        "has_secrets": has_secrets,
                        "secret_keys_set": secret_keys_set
                    })
                return res
    except Exception as e:
        logger.error(f"Error listing integrations: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/admin/integrations/{key}")
def get_integration_single(key: str, user: dict = Depends(require_role("manager"))):
    if key not in ("cavelo", "autotask", "slack"):
        raise HTTPException(status_code=404, detail="Integration not found")
    try:
        from _lib.integrations import decrypt_secrets
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT i.integration_key, i.config, i.enabled, i.last_test_status, 
                           i.last_test_message, i.last_tested_at, i.updated_at, 
                           u.username AS updated_by_username, i.secrets_encrypted
                    FROM integration_settings i
                    LEFT JOIN users u ON i.updated_by = u.id
                    WHERE i.integration_key = %s;
                    """,
                    (key,)
                )
                r = cur.fetchone()
                if not r:
                    raise HTTPException(status_code=404, detail="Integration not found")
                
                config = r[1] or {}
                enabled = r[2]
                last_test_status = r[3] or 'never'
                last_test_message = r[4] or ''
                last_tested_at = r[5].isoformat() if r[5] else None
                updated_at = r[6].isoformat() if r[6] else None
                updated_by_username = r[7]
                secrets_encrypted = r[8]
                
                secrets_dict = {}
                if secrets_encrypted is not None:
                    secrets_dict = decrypt_secrets(secrets_encrypted)
                else:
                    from _lib.integrations import get_env_secrets_fallback
                    secrets_dict = get_env_secrets_fallback(key)
                    
                secret_keys_set = [k for k, v in secrets_dict.items() if v]
                has_secrets = len(secret_keys_set) > 0
                
                return {
                    "integration_key": key,
                    "config": config,
                    "enabled": enabled,
                    "last_test_status": last_test_status,
                    "last_test_message": last_test_message,
                    "last_tested_at": last_tested_at,
                    "updated_at": updated_at,
                    "updated_by_username": updated_by_username,
                    "has_secrets": has_secrets,
                    "secret_keys_set": secret_keys_set
                }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching integration {key}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/admin/integrations/{key}")
def update_integration_settings(key: str, req: IntegrationUpdateRequest, user: dict = Depends(require_role("admin"))):
    if key not in ("cavelo", "autotask", "slack"):
        raise HTTPException(status_code=404, detail="Integration not found")
    try:
        from _lib.integrations import decrypt_secrets, encrypt_secrets, invalidate_cache
        
        with get_db_connection() as conn:
            with conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT secrets_encrypted FROM integration_settings WHERE integration_key = %s;", (key,))
                    row = cur.fetchone()
                if not row:
                    raise HTTPException(status_code=404, detail="Integration not found")
                
                secrets_encrypted = row[0]
                existing_secrets = {}
                if secrets_encrypted is not None:
                    existing_secrets = decrypt_secrets(secrets_encrypted)
                else:
                    from _lib.integrations import get_env_secrets_fallback
                    existing_secrets = {k: v for k, v in get_env_secrets_fallback(key).items() if v}
                
                fields_changed = []
                for skey, sval in req.secrets.items():
                    sval_str = str(sval).strip() if sval is not None else ""
                    if sval_str:
                        old_val = existing_secrets.get(skey)
                        if old_val != sval_str:
                            existing_secrets[skey] = sval_str
                            fields_changed.append(skey)
                
                # Check config changes
                for ckey in req.config.keys():
                    fields_changed.append(f"config:{ckey}")
                
                new_config = req.config
                new_secrets_encrypted = encrypt_secrets(existing_secrets)
                
                update_query = """
                    UPDATE integration_settings 
                    SET config = %s, secrets_encrypted = %s, enabled = %s, 
                        updated_at = NOW(), updated_by = %s 
                    WHERE integration_key = %s;
                """
                
                execute_write(
                    conn,
                    action="integration_updated",
                    target_type="integration",
                    target_id=key,
                    details={"integration_key": key, "fields_changed": fields_changed},
                    write_query=update_query,
                    write_params=(json.dumps(new_config), new_secrets_encrypted, req.enabled, user["id"], key),
                    actor=user["username"],
                    target=f"integration:{key}",
                    detail={"integration_key": key, "fields_changed": fields_changed}
                )
                
        invalidate_cache(key)
        return {"status": "success", "fields_changed": fields_changed}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating integration {key}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/admin/integrations/{key}/test")
def test_integration_connection(key: str, user: dict = Depends(require_role("admin"))):
    if key not in ("cavelo", "autotask", "slack"):
        raise HTTPException(status_code=404, detail="Integration not found")
    try:
        from _lib.integrations import get_integration
        integration = get_integration(key)
        config = integration.get("config", {})
        secrets = integration.get("secrets", {})
        
        status = 'failed'
        message = ''
        
        if key == "cavelo":
            api_url = config.get("api_url", "").strip()
            if not api_url:
                api_url = "https://api.cavelo.com"
            api_token = secrets.get("api_token", "").strip()
            
            if not api_token:
                status = 'failed'
                message = "Error: Missing Cavelo API token"
            else:
                test_url = f"{api_url}/api/v1/health"
                try:
                    r = requests.get(test_url, headers={"Authorization": f"Bearer {api_token}"}, timeout=5)
                    if r.ok:
                        status = 'success'
                    message = f"HTTP {r.status_code}: {r.text[:200]}"
                except Exception as ex:
                    status = 'failed'
                    message = f"Error: {str(ex)[:200]}"
                    
        elif key == "autotask":
            api_url = config.get("api_url", "").strip()
            if not api_url:
                api_url = "https://webservices.autotask.net/atservicesrest/v1.0"
            api_integration_code = secrets.get("api_integration_code", "").strip()
            username = secrets.get("username", "").strip()
            secret = secrets.get("secret", "").strip()
            
            if not api_integration_code or not username or not secret:
                status = 'failed'
                message = "Error: Missing one or more Autotask credentials"
            else:
                test_url = api_url
                if not test_url.endswith("/"):
                    test_url += "/"
                if "v1.0" in test_url:
                    test_url = f"{test_url}CompanyTypes"
                else:
                    test_url = f"{test_url}v1.0/CompanyTypes"
                    
                headers = {
                    "ApiIntegrationCode": api_integration_code,
                    "UserName": username,
                    "Secret": secret,
                    "Content-Type": "application/json"
                }
                try:
                    r = requests.get(test_url, headers=headers, timeout=5)
                    if r.ok:
                        status = 'success'
                    message = f"HTTP {r.status_code}: {r.text[:200]}"
                except Exception as ex:
                    status = 'failed'
                    message = f"Error: {str(ex)[:200]}"
                    
        elif key == "slack":
            webhook_url = secrets.get("webhook_url", "").strip()
            if not webhook_url:
                status = 'failed'
                message = "Error: Missing Slack Webhook URL"
            else:
                payload = {"text": f"Test from Vulnerability Triage Gate by {user['username']}"}
                try:
                    r = requests.post(webhook_url, json=payload, timeout=5)
                    if r.ok:
                        status = 'success'
                    message = f"HTTP {r.status_code}: {r.text[:200]}"
                except Exception as ex:
                    status = 'failed'
                    message = f"Error: {str(ex)[:200]}"
                    
        with get_db_connection() as conn:
            with conn:
                update_query = """
                    UPDATE integration_settings 
                    SET last_test_status = %s, last_test_message = %s, last_tested_at = NOW() 
                    WHERE integration_key = %s;
                """
                execute_write(
                    conn,
                    action="integration_test",
                    target_type="integration",
                    target_id=key,
                    details={"integration_key": key, "status": status, "message": message},
                    write_query=update_query,
                    write_params=(status, message, key),
                    actor=user["username"],
                    target=f"integration:{key}",
                    detail={"integration_key": key, "status": status, "message": message}
                )
                
        from _lib.integrations import invalidate_cache
        invalidate_cache(key)
        
        return {"status": status, "message": message}
    except Exception as e:
        logger.error(f"Error testing integration {key}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/admin/integrations/{key}")
def clear_integration_settings(key: str, user: dict = Depends(require_role("admin"))):
    if key not in ("cavelo", "autotask", "slack"):
        raise HTTPException(status_code=404, detail="Integration not found")
    try:
        from _lib.integrations import invalidate_cache
        with get_db_connection() as conn:
            with conn:
                update_query = """
                    UPDATE integration_settings 
                    SET secrets_encrypted = NULL, enabled = false, 
                        updated_at = NOW(), updated_by = %s 
                    WHERE integration_key = %s;
                """
                execute_write(
                    conn,
                    action="integration_cleared",
                    target_type="integration",
                    target_id=key,
                    details={"integration_key": key},
                    write_query=update_query,
                    write_params=(user["id"], key),
                    actor=user["username"],
                    target=f"integration:{key}",
                    detail={"integration_key": key}
                )
        invalidate_cache(key)
        return {"status": "success", "message": f"Integration {key} cleared successfully"}
    except Exception as e:
        logger.error(f"Error clearing integration {key}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/settings.html", response_class=HTMLResponse)
def get_settings_html(user: dict = Depends(require_role("manager"))):
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Integrations Settings</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Outfit:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --border-color: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent-green: #10b981;
            --accent-red: #ef4444;
            --accent-warning: #f59e0b;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --accent-purple: #c084fc;
        }
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            padding: 2.5rem;
            display: flex;
            flex-direction: column;
            min-height: 100vh;
        }
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 1.5rem;
        }
        h1 {
            font-family: 'Outfit', sans-serif;
            font-size: 2rem;
            font-weight: 700;
            background: linear-gradient(135deg, #06b6d4 0%, #3b82f6 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .subtitle {
            font-size: 0.95rem;
            color: var(--text-secondary);
            margin-top: 0.25rem;
        }
        header a:hover {
            color: var(--accent-cyan) !important;
        }
        .container {
            max-width: 900px;
            margin: 0 auto;
            width: 100%;
            display: flex;
            flex-direction: column;
            gap: 2rem;
        }
        .card {
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 2rem;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3);
        }
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 1rem;
            margin-bottom: 1.5rem;
        }
        .card-title {
            font-family: 'Outfit', sans-serif;
            font-size: 1.4rem;
            font-weight: 700;
            color: var(--text-primary);
        }
        .badges-row {
            display: flex;
            gap: 0.5rem;
            align-items: center;
        }
        .badge {
            padding: 0.3rem 0.75rem;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .badge.enabled {
            background-color: rgba(16, 185, 129, 0.15);
            color: var(--accent-green);
            border: 1px solid var(--accent-green);
        }
        .badge.disabled {
            background-color: rgba(148, 163, 184, 0.1);
            color: var(--text-secondary);
            border: 1px solid var(--border-color);
        }
        .badge.success {
            background-color: rgba(59, 130, 246, 0.15);
            color: var(--accent-blue);
            border: 1px solid var(--accent-blue);
        }
        .badge.failed {
            background-color: rgba(239, 68, 68, 0.15);
            color: var(--accent-red);
            border: 1px solid var(--accent-red);
        }
        .form-group {
            margin-bottom: 1.25rem;
        }
        .form-group-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-bottom: 1.25rem;
        }
        label {
            display: block;
            font-size: 0.75rem;
            text-transform: uppercase;
            font-weight: 700;
            color: var(--text-secondary);
            margin-bottom: 0.5rem;
            letter-spacing: 0.05em;
        }
        .input-control {
            width: 100%;
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 0.75rem 1rem;
            border-radius: 6px;
            font-size: 0.9rem;
            outline: none;
            transition: border-color 0.2s;
        }
        .input-control:focus {
            border-color: var(--accent-cyan);
        }
        .checkbox-container {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            margin-top: 1.5rem;
            margin-bottom: 1.5rem;
            cursor: pointer;
            user-select: none;
        }
        .checkbox-container input {
            width: 18px;
            height: 18px;
            accent-color: var(--accent-cyan);
            cursor: pointer;
        }
        .checkbox-text {
            font-size: 0.9rem;
            font-weight: 600;
            color: var(--text-primary);
        }
        .buttons-row {
            display: flex;
            gap: 1rem;
            justify-content: flex-start;
            margin-top: 1.5rem;
        }
        .btn {
            padding: 0.75rem 1.5rem;
            font-family: 'Outfit', sans-serif;
            font-weight: 600;
            font-size: 0.9rem;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.2s;
            border: none;
        }
        .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        .btn-save {
            background: linear-gradient(135deg, #06b6d4 0%, #3b82f6 100%);
            color: white;
        }
        .btn-save:hover:not(:disabled) {
            opacity: 0.9;
            transform: translateY(-1px);
        }
        .btn-test {
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
        }
        .btn-test:hover:not(:disabled) {
            border-color: var(--accent-cyan);
            color: var(--accent-cyan);
        }
        .btn-clear {
            background-color: transparent;
            border: 1px solid var(--accent-red);
            color: var(--accent-red);
            margin-left: auto;
        }
        .btn-clear:hover:not(:disabled) {
            background-color: rgba(239, 68, 68, 0.1);
        }
        .btn-secondary {
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
        }
        .btn-secondary:hover:not(:disabled) {
            border-color: var(--text-primary);
            color: var(--text-primary);
        }
        .test-result-alert {
            margin-top: 1rem;
            padding: 1rem;
            border-radius: 6px;
            font-size: 0.85rem;
            background-color: rgba(15, 23, 42, 0.6);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
        }
        .toast-container {
            position: fixed;
            bottom: 2rem;
            right: 2rem;
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
            z-index: 9999;
        }
        .toast {
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-left: 4px solid var(--accent-green);
            color: var(--text-primary);
            padding: 1rem 1.5rem;
            border-radius: 6px;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.5);
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-family: 'Outfit', sans-serif;
            font-size: 0.9rem;
            min-width: 320px;
            animation: toastIn 0.3s cubic-bezier(0.16, 1, 0.3, 1);
            transition: opacity 0.3s, transform 0.3s;
        }
        .toast.warning {
            border-left-color: var(--accent-warning);
        }
        .toast.error {
            border-left-color: var(--accent-red);
        }
        @keyframes toastIn {
            from { opacity: 0; transform: translateX(50px); }
            to { opacity: 1; transform: translateX(0); }
        }
        .toast-icon {
            font-size: 1.25rem;
        }
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <header>
        <div>
            <h1>Integrations Configurations</h1>
            <div class="subtitle">Securely store API Credentials inside the database under master encryption key</div>
        </div>
        <div style="display: flex; align-items: center; gap: 1rem; flex-wrap: wrap;">
            <nav style="display: flex; align-items: center; gap: 0.75rem;">
                <a href="/brief.html" id="navFindings" style="color: var(--text-primary); text-decoration: none; font-weight: 600; font-size: 0.9rem; transition: color 0.2s;">Findings</a>
                <span style="color: var(--border-color); font-size: 0.9rem;">|</span>
                <a href="/assets.html" id="navAssets" style="color: var(--text-primary); text-decoration: none; font-weight: 600; font-size: 0.9rem; transition: color 0.2s;">Assets</a>
                <span id="navDividerAssets" style="color: var(--border-color); font-size: 0.9rem;">|</span>
                <span id="navDividerUsers" style="color: var(--border-color); font-size: 0.9rem; display: none;">|</span>
                <a href="/users.html" id="navUsers" style="color: var(--text-primary); text-decoration: none; font-weight: 600; font-size: 0.9rem; display: none; transition: color 0.2s;">Users</a>
                <span id="navDividerAudit" style="color: var(--border-color); font-size: 0.9rem; display: none;">|</span>
                <a href="/audit.html" id="navAudit" style="color: var(--text-primary); text-decoration: none; font-weight: 600; font-size: 0.9rem; display: none; transition: color 0.2s;">Audit</a>
                <span id="navDividerSettings" style="color: var(--border-color); font-size: 0.9rem; display: none;">|</span>
                <a href="/settings.html" id="navSettings" style="color: var(--text-primary); text-decoration: none; font-weight: 600; font-size: 0.9rem; display: none; transition: color 0.2s;">Settings</a>
            </nav>
            <span style="color: var(--border-color); font-size: 0.9rem;">|</span>
            <div style="display: flex; align-items: center; gap: 0.75rem;">
                <span id="headerUserInfo" style="font-weight: 500; color: var(--text-primary); font-size: 0.9rem;"></span>
                <span style="color: var(--text-secondary); font-size: 0.9rem;">|</span>
                <a href="/change-password.html" style="color: var(--accent-cyan); text-decoration: none; font-weight: 500; font-size: 0.9rem;">Change password</a>
                <span style="color: var(--text-secondary); font-size: 0.9rem;">|</span>
                <a href="#" onclick="handleLogout(event)" style="color: var(--accent-red); text-decoration: none; font-weight: 500; font-size: 0.9rem;">Logout</a>
            </div>
        </div>
    </header>

    <div class="container">
        <!-- Cavelo Card -->
        <div class="card" id="card_cavelo">
            <div class="card-header" style="flex-direction: column; align-items: flex-start; gap: 0.5rem;">
                <div style="display: flex; justify-content: space-between; align-items: center; width: 100%;">
                    <span class="card-title">Cavelo Endpoint Integration</span>
                    <div class="badges-row">
                        <span class="badge" id="cavelo_status_badge">Disabled</span>
                        <span class="badge" id="cavelo_test_badge">Not Tested</span>
                    </div>
                </div>
                <div id="cavelo_meta" style="font-size: 0.8rem; color: var(--text-secondary);"></div>
            </div>
            <div class="form-group">
                <label for="cavelo_api_url">API Base URL</label>
                <input type="text" id="cavelo_api_url" class="input-control" placeholder="https://api.cavelo.com">
            </div>
            <div class="form-group">
                <label for="cavelo_api_token">API Token (Secret)</label>
                <input type="password" id="cavelo_api_token" class="input-control">
            </div>
            <label class="checkbox-container">
                <input type="checkbox" id="cavelo_enabled">
                <span class="checkbox-text">Enable Cavelo API fetcher</span>
            </label>
            <div class="test-result-alert" id="cavelo_test_result" style="display:none;"></div>
            <div class="buttons-row">
                <button class="btn btn-save" id="cavelo_btn_save" onclick="saveIntegration('cavelo')">Save Config</button>
                <button class="btn btn-test" id="cavelo_btn_test" onclick="testIntegration('cavelo')">Test Connection</button>
                <button class="btn btn-clear" id="cavelo_btn_clear" onclick="clearIntegration('cavelo')">Clear Credentials</button>
            </div>
        </div>

        <!-- Autotask Card -->
        <div class="card" id="card_autotask">
            <div class="card-header" style="flex-direction: column; align-items: flex-start; gap: 0.5rem;">
                <div style="display: flex; justify-content: space-between; align-items: center; width: 100%;">
                    <span class="card-title">Datto Autotask ticketing Integration</span>
                    <div class="badges-row">
                        <span class="badge" id="autotask_status_badge">Disabled</span>
                        <span class="badge" id="autotask_test_badge">Not Tested</span>
                    </div>
                </div>
                <div id="autotask_meta" style="font-size: 0.8rem; color: var(--text-secondary);"></div>
            </div>
            <div class="form-group">
                <label for="autotask_api_url">REST API Base URL</label>
                <input type="text" id="autotask_api_url" class="input-control" placeholder="https://webservices.autotask.net/atservicesrest/v1.0">
            </div>
            <div class="form-group-row">
                <div class="form-group">
                    <label for="autotask_queue_id">Queue ID</label>
                    <input type="text" id="autotask_queue_id" class="input-control">
                </div>
                <div class="form-group">
                    <label for="autotask_account_id">Company / Account ID</label>
                    <input type="text" id="autotask_account_id" class="input-control">
                </div>
                <div class="form-group">
                    <label for="autotask_default_assignee_resource_id">Default Assignee Resource ID</label>
                    <input type="text" id="autotask_default_assignee_resource_id" class="input-control">
                </div>
            </div>
            <div class="form-group-row">
                <div class="form-group">
                    <label for="autotask_api_integration_code">API Integration Code (Secret)</label>
                    <input type="password" id="autotask_api_integration_code" class="input-control">
                </div>
                <div class="form-group">
                    <label for="autotask_username">Username (Secret)</label>
                    <input type="password" id="autotask_username" class="input-control">
                </div>
                <div class="form-group">
                    <label for="autotask_secret">Secret Key (Secret)</label>
                    <input type="password" id="autotask_secret" class="input-control">
                </div>
            </div>
            <label class="checkbox-container">
                <input type="checkbox" id="autotask_enabled">
                <span class="checkbox-text">Enable Autotask ticketing service</span>
            </label>
            <div class="test-result-alert" id="autotask_test_result" style="display:none;"></div>
            <div class="buttons-row">
                <button class="btn btn-save" id="autotask_btn_save" onclick="saveIntegration('autotask')">Save Config</button>
                <button class="btn btn-test" id="autotask_btn_test" onclick="testIntegration('autotask')">Test Connection</button>
                <button class="btn btn-clear" id="autotask_btn_clear" onclick="clearIntegration('autotask')">Clear Credentials</button>
            </div>
        </div>

        <!-- Slack Card -->
        <div class="card" id="card_slack">
            <div class="card-header" style="flex-direction: column; align-items: flex-start; gap: 0.5rem;">
                <div style="display: flex; justify-content: space-between; align-items: center; width: 100%;">
                    <span class="card-title">Slack Notifications Integration</span>
                    <div class="badges-row">
                        <span class="badge" id="slack_status_badge">Disabled</span>
                        <span class="badge" id="slack_test_badge">Not Tested</span>
                    </div>
                </div>
                <div id="slack_meta" style="font-size: 0.8rem; color: var(--text-secondary);"></div>
            </div>
            <div class="form-group">
                <label for="slack_channel">Channel</label>
                <input type="text" id="slack_channel" class="input-control" placeholder="#triage">
            </div>
            <div class="form-group">
                <label for="slack_webhook_url">Incoming Webhook URL (Secret)</label>
                <input type="password" id="slack_webhook_url" class="input-control">
            </div>
            <label class="checkbox-container">
                <input type="checkbox" id="slack_enabled">
                <span class="checkbox-text">Enable Slack daily brief alerts</span>
            </label>
            <div class="test-result-alert" id="slack_test_result" style="display:none;"></div>
            <div class="buttons-row">
                <button class="btn btn-save" id="slack_btn_save" onclick="saveIntegration('slack')">Save Config</button>
                <button class="btn btn-test" id="slack_btn_test" onclick="testIntegration('slack')">Test Connection</button>
                <button class="btn btn-clear" id="slack_btn_clear" onclick="clearIntegration('slack')">Clear Credentials</button>
            </div>
        </div>

        <!-- Danger Zone Card -->
        <div id="dangerZone" class="card" style="border: 1px solid var(--accent-red); display: none;">
            <div class="card-header" style="border-bottom: 1px solid var(--accent-red); margin-bottom: 1.5rem;">
                <div class="card-title" style="color: var(--accent-red);">Danger Zone</div>
            </div>
            <p style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 1.5rem;">
                Wipe all vulnerability and asset data. Users are preserved.
            </p>
            <div class="buttons-row">
                <button class="btn" style="background-color: var(--accent-red); border: none; color: white; width: auto;" onclick="openResetModal()">Reset System</button>
            </div>
        </div>
    </div>

    <div class="toast-container" id="toastContainer"></div>

    <!-- Reset Modal -->
    <div id="resetModal" style="position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(8px); display: none; align-items: center; justify-content: center; z-index: 2000;">
        <div class="card" style="width: 100%; max-width: 480px; margin-bottom: 0; border: 1px solid var(--accent-red);">
            <h2 style="font-family: 'Outfit', sans-serif; font-size: 1.5rem; margin-bottom: 1rem; color: var(--accent-red);">Reset System Confirmation</h2>
            <p style="font-size: 0.9rem; color: var(--text-primary); margin-bottom: 1.5rem; line-height: 1.5;">
                This action is irreversible. You are about to permanently wipe all findings, triage status, tickets, enrichment data, and asset lists.
            </p>
            <p style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 1rem;">
                Please type <strong style="color: var(--text-primary);">RESET</strong> in uppercase to confirm:
            </p>
            <input type="text" id="resetConfirmInput" class="input-control" style="width: 100%; margin-bottom: 1.5rem; background-color: var(--bg-primary); border: 1px solid var(--border-color); color: var(--text-primary); padding: 0.75rem 1rem; border-radius: 6px;" placeholder="RESET" oninput="handleResetInput(event)">
            <div style="display: flex; justify-content: flex-end; gap: 1rem;">
                <button class="btn btn-secondary" onclick="closeResetModal()">Cancel</button>
                <button id="btnConfirmReset" class="btn" style="background-color: var(--accent-red); color: white;" disabled onclick="submitResetSystem()">Confirm Reset</button>
            </div>
        </div>
    </div>

    <script>
        const state = {
            currentUser: null,
            integrations: {}
        };

        window.addEventListener('DOMContentLoaded', () => {
            checkAuthAndInit();
        });

        async function checkAuthAndInit() {
            try {
                const response = await window.apiFetch('/api/me');
                if (!response.ok) {
                    window.location.href = '/login.html';
                    return;
                }
                const user = await response.json();
                state.currentUser = user;
                document.getElementById('headerUserInfo').innerText = `${user.username} (${user.role})`;
                
                if (user.role === 'admin' || user.role === 'manager') {
                    if (user.role === 'admin') {
                        const navUsers = document.getElementById('navUsers');
                        if (navUsers) navUsers.style.display = 'inline';
                        const navDividerUsers = document.getElementById('navDividerUsers');
                        if (navDividerUsers) navDividerUsers.style.display = 'inline';
                        const navAudit = document.getElementById('navAudit');
                        if (navAudit) navAudit.style.display = 'inline';
                        const navDividerAudit = document.getElementById('navDividerAudit');
                        if (navDividerAudit) navDividerAudit.style.display = 'inline';
                        const navSettings = document.getElementById('navSettings');
                        if (navSettings) navSettings.style.display = 'inline';
                        const navDividerSettings = document.getElementById('navDividerSettings');
                        if (navDividerSettings) navDividerSettings.style.display = 'inline';
                    }
                } else {
                    window.location.href = '/brief.html';
                    return;
                }
                
                applyRoleUI(user.role);
                fetchIntegrations();
            } catch (err) {
                window.location.href = '/login.html';
            }
        }

        async function handleLogout(event) {
            event.preventDefault();
            try {
                await window.apiFetch('/api/logout', { method: 'POST' });
            } catch (err) {}
            window.location.href = '/login.html';
        }

        async function fetchIntegrations() {
            try {
                const r = await window.apiFetch('/api/admin/integrations');
                if (r.ok) {
                    const list = await r.json();
                    list.forEach(item => {
                        state.integrations[item.integration_key] = item;
                        renderIntegration(item);
                    });
                }
            } catch (e) {
                // apiFetch handles toasts
            }
        }

        function getRelativeTime(isoStr) {
            if (!isoStr) return '';
            const date = new Date(isoStr);
            const now = new Date();
            const diffMs = now - date;
            const diffSecs = Math.floor(diffMs / 1000);
            const diffMins = Math.floor(diffSecs / 60);
            const diffHours = Math.floor(diffMins / 60);
            const diffDays = Math.floor(diffHours / 24);

            if (diffSecs < 60) {
                return 'just now';
            } else if (diffMins < 60) {
                return `${diffMins} minute${diffMins > 1 ? 's' : ''} ago`;
            } else if (diffHours < 24) {
                return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
            } else {
                return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
            }
        }

        function renderIntegration(item) {
            const key = item.integration_key;
            
            const statusBadge = document.getElementById(`${key}_status_badge`);
            if (item.enabled) {
                statusBadge.innerText = 'Enabled';
                statusBadge.className = 'badge enabled';
            } else {
                statusBadge.innerText = 'Disabled';
                statusBadge.className = 'badge disabled';
            }
            
            const testBadge = document.getElementById(`${key}_test_badge`);
            if (item.last_test_status === 'success') {
                testBadge.innerText = 'Last Test: Success';
                testBadge.className = 'badge success';
            } else if (item.last_test_status === 'failed') {
                testBadge.innerText = 'Last Test: Failed';
                testBadge.className = 'badge failed';
            } else {
                testBadge.innerText = 'Not Tested';
                testBadge.className = 'badge disabled';
            }
            
            const metaContainer = document.getElementById(`${key}_meta`);
            if (metaContainer) {
                if (item.updated_at && item.updated_by_username) {
                    const relativeTime = getRelativeTime(item.updated_at);
                    metaContainer.innerHTML = `Updated by <strong>${item.updated_by_username}</strong> ${relativeTime}`;
                } else {
                    metaContainer.innerHTML = 'Never updated';
                }
            }

            if (key === 'cavelo') {
                document.getElementById('cavelo_api_url').value = item.config.api_url || '';
                const apiTokenInput = document.getElementById('cavelo_api_token');
                apiTokenInput.value = '';
                if (item.secret_keys_set.includes('api_token')) {
                    apiTokenInput.placeholder = 'Leave blank to keep current secret';
                } else {
                    apiTokenInput.placeholder = 'api_token';
                }
                document.getElementById('cavelo_enabled').checked = item.enabled;
            } else if (key === 'autotask') {
                document.getElementById('autotask_api_url').value = item.config.api_url || '';
                document.getElementById('autotask_queue_id').value = item.config.queue_id || '';
                document.getElementById('autotask_account_id').value = item.config.account_id || '';
                document.getElementById('autotask_default_assignee_resource_id').value = item.config.default_assignee_resource_id || '';
                
                const codeInput = document.getElementById('autotask_api_integration_code');
                codeInput.value = '';
                codeInput.placeholder = item.secret_keys_set.includes('api_integration_code') ? 'Leave blank to keep current secret' : 'api_integration_code';
                
                const userInput = document.getElementById('autotask_username');
                userInput.value = '';
                userInput.placeholder = item.secret_keys_set.includes('username') ? 'Leave blank to keep current secret' : 'username';
                
                const secretInput = document.getElementById('autotask_secret');
                secretInput.value = '';
                secretInput.placeholder = item.secret_keys_set.includes('secret') ? 'Leave blank to keep current secret' : 'secret';
                
                document.getElementById('autotask_enabled').checked = item.enabled;
            } else if (key === 'slack') {
                document.getElementById('slack_channel').value = item.config.channel || '';
                const webhookInput = document.getElementById('slack_webhook_url');
                webhookInput.value = '';
                webhookInput.placeholder = item.secret_keys_set.includes('webhook_url') ? 'Leave blank to keep current secret' : 'webhook_url';
                
                document.getElementById('slack_enabled').checked = item.enabled;
            }
            
            const testResultContainer = document.getElementById(`${key}_test_result`);
            if (item.last_test_status && item.last_test_status !== 'never') {
                const dateStr = item.last_tested_at ? new Date(item.last_tested_at).toLocaleString() : 'N/A';
                testResultContainer.innerHTML = `
                    <div style="font-weight: 600; margin-bottom: 0.25rem;">
                        Test Status: <span style="color: ${item.last_test_status === 'success' ? 'var(--accent-green)' : 'var(--accent-red)'}">${item.last_test_status.toUpperCase()}</span>
                    </div>
                    <div style="font-size: 0.8rem; color: var(--text-secondary); margin-bottom: 0.5rem;">Tested at: ${dateStr}</div>
                    <div style="padding: 0.5rem; background-color: var(--bg-primary); border-radius: 4px; font-size: 0.8rem; font-family: monospace;">${item.last_test_message || '(No message)'}</div>
                `;
                testResultContainer.style.display = 'block';
            } else {
                testResultContainer.style.display = 'none';
            }
        }

        async function saveIntegration(key) {
            const payload = {
                config: {},
                secrets: {},
                enabled: document.getElementById(`${key}_enabled`).checked
            };
            
            if (key === 'cavelo') {
                payload.config.api_url = document.getElementById('cavelo_api_url').value;
                payload.secrets.api_token = document.getElementById('cavelo_api_token').value;
            } else if (key === 'autotask') {
                payload.config.api_url = document.getElementById('autotask_api_url').value;
                payload.config.queue_id = document.getElementById('autotask_queue_id').value;
                payload.config.account_id = document.getElementById('autotask_account_id').value;
                payload.config.default_assignee_resource_id = document.getElementById('autotask_default_assignee_resource_id').value;
                
                payload.secrets.api_integration_code = document.getElementById('autotask_api_integration_code').value;
                payload.secrets.username = document.getElementById('autotask_username').value;
                payload.secrets.secret = document.getElementById('autotask_secret').value;
            } else if (key === 'slack') {
                payload.config.channel = document.getElementById('slack_channel').value;
                payload.secrets.webhook_url = document.getElementById('slack_webhook_url').value;
            }

            const saveBtn = document.getElementById(`${key}_btn_save`);
            const origText = saveBtn.innerText;
            saveBtn.disabled = true;
            saveBtn.innerHTML = '<span class="spinner" style="display: inline-block; width: 0.8rem; height: 0.8rem; border: 2px solid #fff; border-top-color: transparent; border-radius: 50%; animation: spin 0.8s linear infinite; margin-right: 0.5rem; vertical-align: middle;"></span>Saving...';
            
            try {
                const response = await window.apiFetch(`/api/admin/integrations/${key}`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                
                if (response.ok) {
                    window.toast(`${key} configuration saved successfully.`, 'success');
                    fetchIntegrations();
                }
            } catch (e) {
                // apiFetch handles toasts
            } finally {
                saveBtn.disabled = false;
                saveBtn.innerText = origText;
            }
        }

        async function testIntegration(key) {
            const btn = document.getElementById(`${key}_btn_test`);
            const origText = btn.innerText;
            btn.innerHTML = '<span class="spinner" style="display: inline-block; width: 0.8rem; height: 0.8rem; border: 2px solid var(--accent-cyan); border-top-color: transparent; border-radius: 50%; animation: spin 0.8s linear infinite; margin-right: 0.5rem; vertical-align: middle;"></span>Testing...';
            btn.disabled = true;
            
            try {
                const response = await window.apiFetch(`/api/admin/integrations/${key}/test`, { method: 'POST' });
                
                if (response.ok) {
                    const result = await response.json();
                    if (result.status === 'success') {
                        window.toast(`${key} connection test succeeded!`, 'success');
                    } else {
                        window.toast(`${key} connection test failed! Check details below.`, 'warning');
                    }
                    fetchIntegrations();
                }
            } catch (e) {
                // apiFetch handles toasts
            } finally {
                btn.innerText = origText;
                btn.disabled = false;
            }
        }

        async function clearIntegration(key) {
            const confirmed = await window.confirmDialog({
                title: 'Clear Credentials',
                message: `Are you sure you want to delete database secrets and disable the ${key} integration?`,
                confirmText: 'Clear',
                confirmStyle: 'danger'
            });
            if (!confirmed) return;

            const clearBtn = document.getElementById(`${key}_btn_clear`);
            const origText = clearBtn.innerText;
            clearBtn.disabled = true;
            clearBtn.innerHTML = '<span class="spinner" style="display: inline-block; width: 0.8rem; height: 0.8rem; border: 2px solid var(--accent-red); border-top-color: transparent; border-radius: 50%; animation: spin 0.8s linear infinite; margin-right: 0.5rem; vertical-align: middle;"></span>Clearing...';

            try {
                const response = await window.apiFetch(`/api/admin/integrations/${key}`, { method: 'DELETE' });
                if (response.ok) {
                    window.toast(`${key} credentials cleared and integration disabled.`, 'success');
                    fetchIntegrations();
                }
            } catch (e) {
                // apiFetch handles toasts
            } finally {
                clearBtn.disabled = false;
                clearBtn.innerText = origText;
            }
        }

        function applyRoleUI(role) {
            if (role === 'admin') {
                const dangerZone = document.getElementById('dangerZone');
                if (dangerZone) dangerZone.style.display = 'block';
            } else {
                // Disable all inputs and hide buttons for non-admin roles
                document.querySelectorAll('.card input, .card checkbox').forEach(el => el.disabled = true);
                document.querySelectorAll('.buttons-row').forEach(el => {
                    if (!el.closest('#dangerZone')) {
                        el.style.display = 'none';
                    }
                });
            }
        }

        function openResetModal() {
            document.getElementById('resetModal').style.display = 'flex';
            document.getElementById('resetConfirmInput').value = '';
            document.getElementById('btnConfirmReset').disabled = true;
            document.getElementById('resetConfirmInput').focus();
        }

        function closeResetModal() {
            document.getElementById('resetModal').style.display = 'none';
        }

        // Reset modal Esc and Backdrop dismissal
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                closeResetModal();
            }
        });
        
        window.addEventListener('click', function(e) {
            const modal = document.getElementById('resetModal');
            if (e.target === modal) {
                closeResetModal();
            }
        });

        function handleResetInput(event) {
            const val = event.target.value;
            document.getElementById('btnConfirmReset').disabled = (val !== 'RESET');
        }

        async function submitResetSystem() {
            const btn = document.getElementById('btnConfirmReset');
            btn.disabled = true;
            btn.innerText = 'Resetting...';
            try {
                const response = await window.apiFetch('/api/admin/reset', {
                    method: 'POST'
                });
                if (response.ok) {
                    const res = await response.json();
                    const totalWiped = Object.values(res.wiped || {}).reduce((a, b) => a + b, 0);
                    window.toast(`✓ System successfully reset! Wiped ${totalWiped} rows`, 'success');
                    closeResetModal();
                    setTimeout(() => {
                        window.location.reload();
                    }, 1500);
                } else {
                    const err = await response.json();
                    window.toast(`Reset failed: ${err.detail || 'Forbidden'}`, 'warning');
                    btn.disabled = false;
                    btn.innerText = 'Confirm Reset';
                }
            } catch (e) {
                window.toast(`Network error: ${e.message}`, 'warning');
                btn.disabled = false;
                btn.innerText = 'Confirm Reset';
            }
        }
    </script>
</body>
</html>"""
    return render_html(html_content)

if __name__ == "__main__":
    import uvicorn
    import argparse
    
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true", help="Send a dry-run daily brief to log and exit.")
    args = parser.parse_args()
    
    if args.once:
        logger.info("Executing dry-run Slack brief.")
        send_slack_brief(dry_run=True)
        sys.exit(0)
        
    port = int(os.getenv("COORDINATOR_PORT", "8080"))
    logger.info(f"Starting Coordinator on port {port}")
    uvicorn.run(app, host="0.0.0.0", port=port)
