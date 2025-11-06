#!/usr/bin/env python3
"""
paymentdetect.py

Robust account loading and startup for deployment (Railway / any PaaS).
- Prefer environment variables IMAP_USER / IMAP_PASS (also accepts EMAIL_USER / EMAIL_PASS).
- Optionally load ACCOUNTS_PATH from env or default to accounts.json.
- Emits clear diagnostic logs showing which env vars are visible (masks secrets).
- Exits with a clear message if no account configuration found.
- Keeps same shape expected by the rest of your app: returns a list of account dicts.
"""

import os
import json
import logging
from pathlib import Path
from typing import List, Dict, Any

# --- Logging setup
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("email_checker")

# --- Constants and paths
BASE_DIR = Path(os.getenv("BASE_DIR", "."))  # override if Railway uses different CWD
ACCOUNTS_ENV_KEYS = [
    ("IMAP_USER", "IMAP_PASS"),
    ("EMAIL_USER", "EMAIL_PASS"),
]
DEFAULT_ACCOUNTS_PATH = Path(os.getenv("ACCOUNTS_PATH", str(BASE_DIR / "accounts.json")))
LAST_UIDS_PATH = Path(os.getenv("LAST_UIDS_PATH", str(BASE_DIR / "seen_uids.json")))

# --- Utilities
def mask(v: str) -> str:
    if not v:
        return "<missing>"
    if len(v) <= 6:
        return "<set>"
    return f"{v[:3]}...{v[-3:]}"

def detect_env_presence() -> None:
    keys = ["IMAP_USER", "IMAP_PASS", "EMAIL_USER", "EMAIL_PASS", "ACCOUNTS_PATH", "LAST_UIDS_PATH"]
    for k in keys:
        v = os.environ.get(k)
        logger.debug("ENV %s=%s", k, "<set>" if v else "<missing>")
    logger.info("CWD: %s", Path.cwd())
    logger.info("ACCOUNTS_PATH resolved to: %s (exists=%s)", DEFAULT_ACCOUNTS_PATH, DEFAULT_ACCOUNTS_PATH.exists())

# --- Account loader
def ensure_accounts() -> List[Dict[str, Any]]:
    """
    Return a list of account dicts. Priority:
    1) Env vars (IMAP_USER + IMAP_PASS) or alternative names (EMAIL_USER + EMAIL_PASS)
    2) accounts.json file at ACCOUNTS_PATH
    If none found, log details and exit.
    """
    # 1) Try environment-based short config
    env_user = os.getenv("IMAP_USER") or os.getenv("EMAIL_USER")
    env_pass = os.getenv("IMAP_PASS") or os.getenv("EMAIL_PASS")

    if env_user and env_pass:
        logger.info("Using IMAP credentials from environment (env_user=%s)", mask(env_user))
        account = {
            "name": os.getenv("IMAP_NAME", env_user),
            "host": os.getenv("IMAP_HOST", "imap.gmail.com"),
            "port": int(os.getenv("IMAP_PORT", "993")),
            "user": env_user,
            "password": env_pass,
            "folder": os.getenv("IMAP_FOLDER", "INBOX"),
            "use_gmail_xgmraw": os.getenv("USE_GMAIL_XGMRAW", "true").lower() in ("1", "true", "yes"),
            "search_mode": os.getenv("SEARCH_MODE", "UNSEEN"),
            "since_days": int(os.getenv("SINCE_DAYS", "1")),
            "max_fetch": int(os.getenv("MAX_FETCH", "25")),
        }
        return [account]

    # 2) Try accounts.json file
    try:
        if DEFAULT_ACCOUNTS_PATH.exists():
            with open(DEFAULT_ACCOUNTS_PATH, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            # Expect either a dict with "accounts" or a list of accounts
            if isinstance(data, dict) and "accounts" in data and isinstance(data["accounts"], list):
                logger.info("Loaded %d accounts from %s", len(data["accounts"]), DEFAULT_ACCOUNTS_PATH)
                return data["accounts"]
            if isinstance(data, list):
                logger.info("Loaded %d accounts from %s", len(data), DEFAULT_ACCOUNTS_PATH)
                return data
            logger.warning("accounts.json content not a list or dict['accounts']; ignoring file")
    except Exception as exc:
        logger.exception("Error reading accounts file %s: %s", DEFAULT_ACCOUNTS_PATH, exc)

    # 3) Nothing found — log detailed guidance and exit
    missing = []
    if not env_user:
        missing.append("IMAP_USER / EMAIL_USER")
    if not env_pass:
        missing.append("IMAP_PASS / EMAIL_PASS")
    logger.critical(
        "No accounts configured. Missing: %s. Create accounts.json at %s or set env vars.",
        ", ".join(missing),
        DEFAULT_ACCOUNTS_PATH,
    )
    detect_env_presence()
    raise SystemExit(1)

# --- Example entrypoint for the rest of your app
def main():
    # Optional debug: show env presence at startup (masks values)
    if os.getenv("DEBUG_ENV", "false").lower() in ("1", "true", "yes"):
        # Print a masked summary to INFO so it's visible in Railway logs without exposing secrets
        u = os.getenv("IMAP_USER") or os.getenv("EMAIL_USER")
        p = os.getenv("IMAP_PASS") or os.getenv("EMAIL_PASS")
        logger.info("Startup env summary: IMAP_USER=%s IMAP_PASS=%s ACCOUNTS_PATH=%s",
                    mask(u), "<set>" if p else "<missing>", DEFAULT_ACCOUNTS_PATH)

    accounts = ensure_accounts()
    # The rest of your application uses `accounts`. Example placeholder:
    logger.info("Starting email checker for %d account(s)", len(accounts))
    for acct in accounts:
        logger.info("Account: name=%s host=%s user=%s folder=%s",
                    acct.get("name"), acct.get("host"), mask(acct.get("user", "")), acct.get("folder"))

    # Placeholder: insert your existing IMAP loop / detection logic here.
    # For example:
    # checker = EmailChecker(accounts, last_uids_path=LAST_UIDS_PATH)
    # checker.run_forever()

if __name__ == "__main__":
    main()