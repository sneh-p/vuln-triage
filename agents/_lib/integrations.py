# agents/_lib/integrations.py
import os
import json
import time
import logging
from cryptography.fernet import Fernet
from _lib.db import get_db_connection

logger = logging.getLogger("integrations_lib")

# Cache to store integration settings: key -> (timestamp, result_dict)
_cache = {}
CACHE_TTL = 60  # 60 seconds

def get_integration_secret_key():
    """Retrieves the master key from environment or parses the mounted .env file."""
    key = os.getenv("INTEGRATION_SECRET_KEY")
    if key:
        return key.strip()
        
    env_path = "/root/vuln-triage/secrets/.env"
    if os.path.exists(env_path):
        try:
            with open(env_path, "r") as f:
                for line in f:
                    if line.strip().startswith("INTEGRATION_SECRET_KEY="):
                        return line.split("=", 1)[1].strip()
        except Exception as e:
            logger.error(f"Error reading INTEGRATION_SECRET_KEY from .env file: {e}")
    return None

def get_fernet():
    """Lazily initializes and returns Fernet cipher instance using the master key."""
    key = get_integration_secret_key()
    if not key:
        raise ValueError("INTEGRATION_SECRET_KEY is not configured or generated yet.")
    return Fernet(key.encode())

def encrypt_secrets(plain_dict):
    """Encrypts a dictionary of secrets to bytes using Fernet."""
    if not plain_dict:
        return None
    data = json.dumps(plain_dict).encode("utf-8")
    return get_fernet().encrypt(data)

def decrypt_secrets(enc_bytes):
    """Decrypts Fernet-encrypted bytes back to a dictionary."""
    if not enc_bytes:
        return {}
    if isinstance(enc_bytes, memoryview):
        enc_bytes = bytes(enc_bytes)
    try:
        decrypted = get_fernet().decrypt(enc_bytes)
        return json.loads(decrypted.decode("utf-8"))
    except Exception as e:
        logger.error(f"Failed to decrypt secrets: {e}")
        return {}

def get_env_secrets_fallback(key):
    """Fallback values for secrets from environment variables."""
    if key == "cavelo":
        return {"api_token": os.getenv("CAVELO_API_TOKEN", "")}
    elif key == "autotask":
        return {
            "api_integration_code": os.getenv("AUTOTASK_API_INTEGRATION_CODE", ""),
            "username": os.getenv("AUTOTASK_USERNAME", ""),
            "secret": os.getenv("AUTOTASK_SECRET", "")
        }
    elif key == "slack":
        return {"webhook_url": os.getenv("SLACK_WEBHOOK_URL", "")}
    return {}

def get_env_config_fallback(key, current_config):
    """Fallback values for config from environment variables."""
    cfg = dict(current_config or {})
    if key == "cavelo":
        if "api_url" not in cfg or not cfg["api_url"]:
            cfg["api_url"] = os.getenv("CAVELO_API_URL", "https://api.cavelo.com")
    elif key == "autotask":
        if "api_url" not in cfg or not cfg["api_url"]:
            cfg["api_url"] = os.getenv("AUTOTASK_API_URL", "https://webservices.autotask.net/atservicesrest/v1.0")
        if "queue_id" not in cfg or not cfg["queue_id"]:
            cfg["queue_id"] = os.getenv("AUTOTASK_QUEUE_ID", "")
        if "account_id" not in cfg or not cfg["account_id"]:
            cfg["account_id"] = os.getenv("AUTOTASK_ACCOUNT_ID", "")
        if "default_assignee_resource_id" not in cfg or not cfg["default_assignee_resource_id"]:
            cfg["default_assignee_resource_id"] = os.getenv("AUTOTASK_DEFAULT_ASSIGNEE_RESOURCE_ID", "")
    elif key == "slack":
        if "channel" not in cfg or not cfg["channel"]:
            cfg["channel"] = os.getenv("SLACK_CHANNEL", "#triage")
    return cfg

def get_env_enabled_fallback(key, current_enabled):
    """Determines enabled status based on DB value or presence of env variables."""
    if current_enabled:
        return True
        
    # Check if DB row has secrets configured (meaning it was explicitly disabled)
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT secrets_encrypted FROM integration_settings WHERE integration_key = %s;", (key,))
                res = cur.fetchone()
                if res and res[0] is not None:
                    return False
    except Exception:
        pass
        
    # Fallback to check if env config is present
    if key == "cavelo":
        return bool(os.getenv("CAVELO_API_TOKEN"))
    elif key == "autotask":
        return bool(os.getenv("AUTOTASK_SECRET") and os.getenv("AUTOTASK_USERNAME"))
    elif key == "slack":
        return bool(os.getenv("SLACK_WEBHOOK_URL"))
    return False

def get_integration(key):
    """Retrieves config, secrets, and enabled flag for an integration with caching."""
    now = time.time()
    if key in _cache:
        cached_time, cached_val = _cache[key]
        if now - cached_time < CACHE_TTL:
            return cached_val

    row = None
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT config, secrets_encrypted, enabled FROM integration_settings WHERE integration_key = %s;", (key,))
                row = cur.fetchone()
    except Exception as e:
        # Table might not exist yet during startup migration
        pass

    if row:
        config = row[0]
        secrets_encrypted = row[1]
        enabled = row[2]
        
        if isinstance(config, str):
            try:
                config = json.loads(config)
            except Exception:
                config = {}
                
        if secrets_encrypted is not None:
            secrets = decrypt_secrets(secrets_encrypted)
        else:
            secrets = get_env_secrets_fallback(key)
            config = get_env_config_fallback(key, config)
            enabled = get_env_enabled_fallback(key, enabled)
    else:
        # DB row not found, fall back entirely to environment
        config = get_env_config_fallback(key, {})
        secrets = get_env_secrets_fallback(key)
        enabled = get_env_enabled_fallback(key, False)

    result = {
        "config": config,
        "secrets": secrets,
        "enabled": enabled
    }
    
    # Store in cache
    _cache[key] = (now, result)
    return result

def invalidate_cache(key):
    """Invalidates the settings cache for a given integration key."""
    if key in _cache:
        del _cache[key]
