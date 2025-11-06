#!/usr/bin/env python3
"""
email_checker.py
- Periodically checks configured IMAP accounts for messages within the last 2 hours.
- Uses UID-based state tracking persisted to last_uids.json to avoid duplicate alerts.
- Poll interval: 30 seconds (POLL_SECONDS). Adjust as needed.
- Place accounts in accounts.json (example below) or set single-account env vars.
"""

import os
import json
import re
import ssl
import imaplib
import email
import email.utils
import logging
import asyncio
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# -----------------------
# Configuration
# -----------------------
POLL_SECONDS = int(os.getenv("POLL_SECONDS", "30"))  # 30s default
HOURS_WINDOW = int(os.getenv("HOURS_WINDOW", "2"))  # 2-hour window
LAST_UIDS_PATH = Path(os.getenv("LAST_UIDS_PATH", "last_uids.json"))
ACCOUNTS_PATH = Path(os.getenv("ACCOUNTS_PATH", "accounts.json"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# Example accounts.json format:
# [
#   {
#     "name": "personal",
#     "host": "imap.gmail.com",
#     "port": 993,
#     "user": "you@example.com",
#     "password": "app-or-account-password",
#     "folder": "INBOX",
#     "use_gmail_xgmraw": true,
#     "search_mode": "UNSEEN",  # UNSEEN | ALL | SINCE
#     "since_days": 1,
#     "max_fetch": 10
#   }
# ]

# -----------------------
# Logging
# -----------------------
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("email_checker")

# -----------------------
# State persistence
# -----------------------
def load_last_uids() -> Dict[str, int]:
    if LAST_UIDS_PATH.exists():
        try:
            with LAST_UIDS_PATH.open("r", encoding="utf-8") as f:
                data = json.load(f)
                return {k: int(v) for k, v in data.items()}
        except Exception:
            logger.exception("Failed to load LAST_UIDS; starting fresh")
    return {}

def save_last_uids(state: Dict[str, int]):
    try:
        with LAST_UIDS_PATH.open("w", encoding="utf-8") as f:
            json.dump(state, f)
    except Exception:
        logger.exception("Failed to save LAST_UIDS")

LAST_UID: Dict[str, int] = load_last_uids()

# -----------------------
# Utility helpers
# -----------------------
def _safe_decode(b: bytes) -> str:
    try:
        return b.decode("utf-8", errors="ignore")
    except Exception:
        return str(b)

def ensure_accounts() -> List[Dict[str, Any]]:
    if ACCOUNTS_PATH.exists():
        try:
            with ACCOUNTS_PATH.open("r", encoding="utf-8") as f:
                accounts = json.load(f)
                if isinstance(accounts, list):
                    return accounts
        except Exception:
            logger.exception("Failed to read accounts.json")
    # Fallback single-account from env
    env_user = os.getenv("IMAP_USER")
    env_pass = os.getenv("IMAP_PASS")
    if env_user and env_pass:
        logger.info("Using single account from environment variables")
        return [{
            "name": os.getenv("IMAP_NAME", env_user),
            "host": os.getenv("IMAP_HOST", "imap.gmail.com"),
            "port": int(os.getenv("IMAP_PORT", "993")),
            "user": env_user,
            "password": env_pass,
            "folder": os.getenv("IMAP_FOLDER", "INBOX"),
            "use_gmail_xgmraw": os.getenv("USE_GMAIL_XGMRAW", "true").lower() == "true",
            "search_mode": os.getenv("SEARCH_MODE", "UNSEEN"),
            "since_days": int(os.getenv("SINCE_DAYS", "1")),
            "max_fetch": int(os.getenv("MAX_FETCH", "10"))
        }]
    logger.critical("No accounts configured. Create accounts.json or set IMAP_USER and IMAP_PASS env vars.")
    raise SystemExit(1)

# -----------------------
# IMAP operations (blocking) - run in thread via asyncio.to_thread
# -----------------------
def connect_imap(host: str, port: int, user: str, password: str, timeout: int = 30) -> imaplib.IMAP4_SSL:
    ctx = ssl.create_default_context()
    im = imaplib.IMAP4_SSL(host, port, ssl_context=ctx)
    im.sock.settimeout(timeout)
    typ, data = im.login(user, password)
    logger.debug("Login response for %s: %s %s", user, typ, data)
    return im

def list_mailboxes(im_conn: imaplib.IMAP4_SSL):
    try:
        typ, data = im_conn.list()
        logger.debug("LIST -> %s", typ)
        if data:
            for b in data:
                logger.debug("Mailbox entry: %s", _safe_decode(b))
    except Exception:
        logger.exception("LIST failed")

def select_folder(im_conn: imaplib.IMAP4_SSL, folder: str) -> bool:
    try:
        typ, data = im_conn.select(folder, readonly=True)
        logger.debug("SELECT %s -> %s %s", folder, typ, data)
        return typ == "OK"
    except Exception:
        logger.exception("SELECT failed for %s", folder)
        return False

def search_unseen(im_conn: imaplib.IMAP4_SSL) -> List[int]:
    try:
        typ, data = im_conn.search(None, "UNSEEN")
        logger.debug("SEARCH UNSEEN -> %s", typ)
        if typ != "OK" or not data or not data[0]:
            return []
        ids = data[0].split()
        return [int(x) for x in ids]
    except Exception:
        logger.exception("SEARCH UNSEEN failed")
        return []

def search_all(im_conn: imaplib.IMAP4_SSL) -> List[int]:
    try:
        typ, data = im_conn.search(None, "ALL")
        logger.debug("SEARCH ALL -> %s", typ)
        if typ != "OK" or not data or not data[0]:
            return []
        return [int(x) for x in data[0].split()]
    except Exception:
        logger.exception("SEARCH ALL failed")
        return []

def search_since(im_conn: imaplib.IMAP4_SSL, since_days: int) -> List[int]:
    try:
        since_date = (datetime.now(timezone.utc) - timedelta(days=since_days)).strftime("%d-%b-%Y")
        typ, data = im_conn.search(None, "SINCE", since_date)
        logger.debug("SEARCH SINCE %s -> %s", since_date, typ)
        if typ != "OK" or not data or not data[0]:
            return []
        return [int(x) for x in data[0].split()]
    except Exception:
        logger.exception("SEARCH SINCE failed")
        return []

def search_gmail_xgmraw(im_conn: imaplib.IMAP4_SSL, query: str) -> List[int]:
    try:
        # Use IMAP UID SEARCH X-GM-RAW via simple commands
        typ, data = im_conn._simple_command('UID', 'SEARCH', 'X-GM-RAW', f'"{query}"')
        resp = im_conn._untagged_response(typ, data, 'SEARCH')
        logger.debug("X-GM-RAW -> %s %s", typ, resp)
        if not resp or not resp[0]:
            return []
        return [int(x) for x in resp[0].split()]
    except Exception:
        logger.exception("X-GM-RAW search failed")
        return []

def fetch_internaldates_by_uid(im_conn: imaplib.IMAP4_SSL, uids: List[int]) -> Dict[int, datetime]:
    if not uids:
        return {}
    uid_str = ",".join(str(u) for u in uids)
    try:
        typ, data = im_conn.uid('FETCH', uid_str, '(INTERNALDATE)')
        logger.debug("UID FETCH INTERNALDATE -> %s (items=%d)", typ, len(data) if data else 0)
        uid_dates: Dict[int, datetime] = {}
        if not data:
            return uid_dates
        # Parse response parts for UID and INTERNALDATE
        for part in data:
            if not part:
                continue
            if isinstance(part, tuple) and part[0]:
                header = _safe_decode(part[0])
                m_uid = re.search(r'UID\s+(\d+)', header)
                m_date = re.search(r'INTERNALDATE\s+"([^"]+)"', header)
                if m_uid and m_date:
                    uid = int(m_uid.group(1))
                    date_str = m_date.group(1)
                    try:
                        parsed = email.utils.parsedate_to_datetime(date_str)
                        if parsed.tzinfo is None:
                            parsed = parsed.replace(tzinfo=timezone.utc)
                        uid_dates[uid] = parsed
                    except Exception:
                        logger.exception("Failed to parse INTERNALDATE '%s' for uid %s", date_str, uid)
        return uid_dates
    except Exception:
        logger.exception("UID FETCH INTERNALDATE failed")
        return {}

def fetch_headers_by_uid(im_conn: imaplib.IMAP4_SSL, uids: List[int]) -> List[Dict[str, Any]]:
    out = []
    if not uids:
        return out
    uid_str = ",".join(str(u) for u in uids)
    try:
        typ, msgs = im_conn.uid('FETCH', uid_str, '(RFC822.HEADER)')
        logger.debug("UID FETCH RFC822.HEADER -> %s (items=%d)", typ, len(msgs) if msgs else 0)
        # msgs is list of alternating tuples and separators; parse carefully
        for item in msgs:
            if not item or not isinstance(item, tuple):
                continue
            raw = item[1]
            if not raw:
                continue
            try:
                h = email.message_from_bytes(raw)
                subj = h.get("Subject", "(no subject)")
                frm = h.get("From", "(no from)")
                date_hdr = h.get("Date")
                parsed_date = None
                try:
                    if date_hdr:
                        parsed_date = email.utils.parsedate_to_datetime(date_hdr)
                        if parsed_date and parsed_date.tzinfo is None:
                            parsed_date = parsed_date.replace(tzinfo=timezone.utc)
                except Exception:
                    parsed_date = None
                # try to extract UID from the response header
                m_uid = re.search(r'UID\s+(\d+)', _safe_decode(item[0]))
                uid_val = int(m_uid.group(1)) if m_uid else None
                out.append({"uid": uid_val, "subject": subj, "from": frm, "date": parsed_date})
            except Exception:
                logger.exception("Failed parsing header block for one item")
        return out
    except Exception:
        logger.exception("UID FETCH RFC822.HEADER failed")
        return out

# -----------------------
# Core check logic (async wrapper around blocking IMAP functions)
# -----------------------
async def check_account(account: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Returns list of new message dicts: {"uid": , "subject": , "from": , "date": datetime}
    Only messages with INTERNALDATE within last HOURS_WINDOW are returned.
    """
    user = account.get("user")
    host = account.get("host", "imap.gmail.com")
    port = int(account.get("port", 993))
    password = account.get("password")
    folder = account.get("folder", "INBOX")
    use_xgm = bool(account.get("use_gmail_xgmraw", False))
    search_mode = account.get("search_mode", "UNSEEN")
    since_days = int(account.get("since_days", 1))
    max_fetch = int(account.get("max_fetch", 10))

    logger.info("Checking account %s", user)

    def _work():
        im = None
        try:
            im = connect_imap(host, port, user, password)
            list_mailboxes(im)
            # select folder (try fallback options)
            if not select_folder(im, folder):
                for alt in ["INBOX", "[Gmail]/All Mail", "All Mail"]:
                    if select_folder(im, alt):
                        logger.debug("Using alternate folder %s for %s", alt, user)
                        break
            # search
            uids: List[int] = []
            if search_mode == "UNSEEN":
                uids = search_unseen(im)
                if not uids and use_xgm:
                    logger.debug("UNSEEN empty; trying X-GM-RAW is:unread")
                    uids = search_gmail_xgmraw(im, "is:unread")
            elif search_mode == "ALL":
                uids = search_all(im)
            elif search_mode == "SINCE":
                uids = search_since(im, since_days)
            else:
                uids = search_unseen(im)

            logger.debug("Search returned %d uids for %s", len(uids), user)
            if not uids:
                return []

            uids_sorted = sorted(uids)
            last = LAST_UID.get(user, 0)
            if last == 0:
                # Cold start baseline: set to latest observed UID and skip alerting
                LAST_UID[user] = uids_sorted[-1]
                logger.info("Cold start: set LAST_UID[%s] = %s", user, LAST_UID[user])
                save_last_uids(LAST_UID)
                return []

            # Candidates newer than last seen
            candidate_uids = [u for u in uids_sorted if u > last]
            if not candidate_uids:
                logger.debug("No uids newer than last (%s) for %s", last, user)
                # update LAST_UID to current max to avoid reprocessing very old messages forever
                LAST_UID[user] = max(uids_sorted)
                save_last_uids(LAST_UID)
                return []

            logger.debug("Candidate UIDs for %s: %s", user, candidate_uids)
            # Fetch INTERNALDATE for candidates
            uid_dates = fetch_internaldates_by_uid(im, candidate_uids)
            cutoff = datetime.now(timezone.utc) - timedelta(hours=HOURS_WINDOW)
            uids_within_window = [uid for uid, d in uid_dates.items() if d and d >= cutoff]

            logger.debug("UIDs within %d-hour window for %s: %s", HOURS_WINDOW, user, uids_within_window)
            if not uids_within_window:
                LAST_UID[user] = max(uids_sorted)
                save_last_uids(LAST_UID)
                logger.info("No recent messages within window; updated LAST_UID[%s] = %s", user, LAST_UID[user])
                return []

            # Limit how many to fetch headers for
            to_fetch = sorted(uids_within_window)[-max_fetch:]
            headers = fetch_headers_by_uid(im, to_fetch)

            # Update LAST_UID to highest observed UID so we don't reprocess older msgs next cycle
            LAST_UID[user] = max(uids_sorted)
            save_last_uids(LAST_UID)

            return headers
        finally:
            try:
                if im:
                    im.logout()
            except Exception:
                pass

    # run blocking IMAP work in thread to avoid blocking the event loop
    try:
        results = await asyncio.to_thread(_work)
        return results
    except Exception:
        logger.exception("Async check_account wrapper failed for %s", user)
        return []

async def check_all_accounts(accounts: List[Dict[str, Any]]):
    results = {}
    for acct in accounts:
        user = acct.get("user")
        try:
            new_msgs = await check_account(acct)
            results[user] = new_msgs
            logger.info("Account %s -> %d new message(s)", user, len(new_msgs))
            for m in new_msgs:
                logger.info("New: %s | %s | %s", user, m.get("uid"), m.get("subject"))
        except Exception:
            logger.exception("Failed to check %s", user)
            results[user] = []
    return results

# -----------------------
# Main loop
# -----------------------
async def main_loop():
    accounts = ensure_accounts()
    logger.info("Loaded %d account(s). Poll every %d seconds. Window: %d hours", len(accounts), POLL_SECONDS, HOURS_WINDOW)
    # initial immediate run then sleep
    while True:
        try:
            await check_all_accounts(accounts)
        except Exception:
            logger.exception("Error in main check loop")
        await asyncio.sleep(POLL_SECONDS)

if __name__ == "__main__":
    try:
        asyncio.run(main_loop())
    except KeyboardInterrupt:
        logger.info("Shutting down by user request")
    except Exception:
        logger.exception("Unhandled exception in main")