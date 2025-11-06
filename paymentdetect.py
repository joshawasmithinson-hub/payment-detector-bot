#!/usr/bin/env python3
"""
paymentdetect.py
Detect payments (Zelle, PayPal, Chime, Cash App, Venmo) and post to Discord.

Behavior:
- By default searches UNSEEN messages and posts only new UIDs (SHOW_ONLY_NEW=true).
- USE_READ_2H=true enforces a strict "received in last 2 hours" filter using the IMAP INTERNALDATE (server timestamp).
- USE_HOUR_WINDOW=true will use UNSEEN SINCE 1 hour as an alternate server-side narrowing (less precise).
- Uses BODY.PEEK[] to avoid marking messages read.
- Persists seen UIDs per account in seen_uids.json.
- Dumps non-matching parsed emails to debug_email_dump.txt.
- Optional verbose debug via VERBOSE_DEBUG env var.
Environment: info.env loaded by python-dotenv with DISCORD_TOKEN and EMAIL_1_ADDRESS/_PASSWORD/_IMAP/_CHANNEL, etc.
"""
import os
import re
import imaplib
import email
import asyncio
import discord
import threading
import time
import json
import atexit
from email.header import decode_header
from email.utils import parsedate_to_datetime
from datetime import datetime, timedelta, timezone
from discord.ext import commands
from dotenv import load_dotenv
from bs4 import BeautifulSoup

print("[BOOT] paymentdetect.py is running")

# Load env
load_dotenv("info.env")
VERBOSE = os.getenv("VERBOSE_DEBUG", "false").lower() in ("1", "true", "yes")
USE_HOUR_WINDOW = os.getenv("USE_HOUR_WINDOW", "false").lower() in ("1", "true", "yes")
USE_READ_2H = os.getenv("USE_READ_2H", "true").lower() in ("1", "true", "yes")
SHOW_ONLY_NEW = os.getenv("SHOW_ONLY_NEW", "true").lower() in ("1", "true", "yes")

TOKEN = os.getenv("DISCORD_TOKEN")
if not TOKEN:
    print("[ERROR] DISCORD_TOKEN not found in environment")

# Load email account configs EMAIL_1_..., EMAIL_2_...
email_configs = []
i = 1
while True:
    addr = os.getenv(f"EMAIL_{i}_ADDRESS")
    if not addr:
        break
    email_configs.append({
        "address": addr,
        "password": os.getenv(f"EMAIL_{i}_PASSWORD"),
        "imap": os.getenv(f"EMAIL_{i}_IMAP", "imap.gmail.com"),
        "channel_id": int(os.getenv(f"EMAIL_{i}_CHANNEL")) if os.getenv(f"EMAIL_{i}_CHANNEL") else None,
    })
    i += 1

print(f"[DEBUG] Loaded {len(email_configs)} email config(s)")
if not email_configs:
    raise SystemExit("No email configs found in info.env")

# Discord setup
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)

SEEN_FILE = "seen_uids.json"

def load_seen_uids():
    if os.path.exists(SEEN_FILE):
        try:
            with open(SEEN_FILE, "r", encoding="utf-8") as f:
                raw = json.load(f)
                return {k: set(v) for k, v in raw.items()}
        except Exception as e:
            print(f"[WARN] Failed to load seen_uids.json: {e}")
    return {cfg["address"]: set() for cfg in email_configs}

def save_seen_uids():
    try:
        with open(SEEN_FILE, "w", encoding="utf-8") as f:
            json.dump({k: list(v) for k, v in seen_uids.items()}, f)
    except Exception as e:
        print(f"[ERROR] Failed to save seen_uids.json: {e}")

seen_uids = load_seen_uids()

def get_search_query():
    """
    Return an IMAP search query string.
    Note: SINCE may be day-granular on some IMAP servers; USE_READ_2H enforces exact 2-hour filtering locally via INTERNALDATE.
    """
    if USE_READ_2H:
        since_date = (datetime.now() - timedelta(hours=2)).strftime("%d-%b-%Y")
        return f'(SEEN SINCE "{since_date}")'
    if USE_HOUR_WINDOW:
        since_date = (datetime.now() - timedelta(hours=1)).strftime("%d-%b-%Y")
        return f'(UNSEEN SINCE "{since_date}")'
    return "UNSEEN"

def email_check_loop():
    while True:
        try:
            if VERBOSE:
                print(f"[CYCLE] Checking {len(email_configs)} accounts at {datetime.now().isoformat()}")
            for cfg in email_configs:
                check_single_email_blocking(cfg)
        except Exception as e:
            print(f"[ERROR] email_check_loop: {e}")
        time.sleep(30)

def check_single_email_blocking(cfg):
    addr = cfg["address"]
    try:
        if VERBOSE:
            print(f"[IMAP] Connecting to {cfg['imap']} for {addr}")
        mail = imaplib.IMAP4_SSL(cfg["imap"], timeout=30)
        mail.login(addr, cfg["password"])
        mail.select("inbox")
    except Exception as e:
        print(f"[ERROR] IMAP login/select for {addr}: {e}")
        return

    try:
        query = get_search_query()
        if VERBOSE:
            print(f"[IMAP] Searching with query: {query}")
        status, data = mail.search(None, query)
        if status != "OK":
            print(f"[DEBUG] Search failed for {addr} with status {status}")
            mail.close()
            mail.logout()
            return

        uids = data[0].split()
        if not uids or uids == [b""]:
            if VERBOSE:
                print(f"[DEBUG] No matching emails for {addr}")
            mail.close()
            mail.logout()
            return

        if VERBOSE:
            print(f"[IMAP] Found {len(uids)} message(s) for {addr}")

        channel = None
        if cfg.get("channel_id"):
            channel = bot.get_channel(cfg["channel_id"])
            if channel is None and VERBOSE:
                print(f"[WARN] Discord channel {cfg['channel_id']} not available to bot")

        for uid_b in uids:
            uid = uid_b.decode()
            seen_set = seen_uids.setdefault(addr, set())

            # Skip already-seen if configured
            if SHOW_ONLY_NEW and uid in seen_set:
                if VERBOSE:
                    print(f"[DEBUG] Skipping already-seen UID {uid} for {addr}")
                continue

            # Fetch BODY.PEEK[] and INTERNALDATE for reliable server timestamp
            if VERBOSE:
                print(f"[IMAP] Fetching UID {uid} (BODY.PEEK[] INTERNALDATE)")
            try:
                status, msg_data = mail.fetch(uid_b, '(BODY.PEEK[] INTERNALDATE)')
            except Exception as e:
                print(f"[ERROR] fetch failed for {addr} uid {uid}: {e}")
                continue

            if status != "OK" or not msg_data:
                if VERBOSE:
                    print(f"[DEBUG] Empty fetch for uid {uid} ({status})")
                continue

            # Extract raw email bytes and INTERNALDATE token
            raw_email = None
            internaldate_raw = None
            # msg_data commonly contains tuples and other items; inspect all
            for part in msg_data:
                if isinstance(part, tuple) and part[1]:
                    # part[1] is the raw bytes of the message when present
                    # prefer the largest bytes blob if multiple are present
                    if raw_email is None or (isinstance(part[1], (bytes, bytearray)) and len(part[1]) > len(raw_email)):
                        raw_email = part[1]
                # other parts may be bytes containing the metadata line with INTERNALDATE
                if isinstance(part, bytes):
                    m = re.search(rb'INTERNALDATE\s+"([^"]+)"', part)
                    if m:
                        internaldate_raw = m.group(1).decode(errors='ignore')

            # fallback: attempt to extract INTERNALDATE from first element header bytes if present
            if internaldate_raw is None and isinstance(msg_data[0], tuple) and isinstance(msg_data[0][0], bytes):
                m = re.search(rb'INTERNALDATE\s+"([^"]+)"', msg_data[0][0])
                if m:
                    internaldate_raw = m.group(1).decode(errors='ignore')

            if raw_email is None:
                if VERBOSE:
                    print(f"[DEBUG] No raw email bytes found for uid {uid}")
                continue

            # If USE_READ_2H enforce 2-hour cutoff using INTERNALDATE (server timestamp)
            if USE_READ_2H:
                if not internaldate_raw:
                    if VERBOSE:
                        print(f"[WARN] No INTERNALDATE for uid {uid}; skipping in 2-hour mode")
                    seen_set.add(uid); save_seen_uids()
                    continue
                try:
                    dt = parsedate_to_datetime(internaldate_raw)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    age = datetime.now(timezone.utc) - dt.astimezone(timezone.utc)
                    if age > timedelta(hours=2):
                        if VERBOSE:
                            print(f"[DEBUG] UID {uid} INTERNALDATE {dt.isoformat()} older than 2 hours; skipping")
                        seen_set.add(uid); save_seen_uids()
                        continue
                except Exception as e:
                    if VERBOSE:
                        print(f"[WARN] Failed to parse INTERNALDATE for uid {uid}: {e}")
                    seen_set.add(uid); save_seen_uids()
                    continue

            # Parse the email object
            try:
                msg = email.message_from_bytes(raw_email)
            except Exception as e:
                print(f"[ERROR] parsing email bytes uid {uid}: {e}")
                seen_set.add(uid); save_seen_uids()
                continue

            # Parse and detect payment
            result, full_text = parse_email(msg, return_full_text=True)

            if result:
                # final guard: post only if SHOW_ONLY_NEW logic allows it
                if SHOW_ONLY_NEW and uid in seen_set:
                    if VERBOSE:
                        print(f"[DEBUG] UID {uid} added during processing; skipping post")
                else:
                    print(f"[SUCCESS] ${result['amount']} from {result['sender']} via {result['service']}")
                    if channel:
                        embed = discord.Embed(
                            title=f"New {result['service']} Payment!",
                            description=f"**Account:** `{addr}`",
                            color=0x00FF00
                        )
                        embed.add_field(name="Amount", value=f"${result['amount']:,.2f}", inline=True)
                        embed.add_field(name="From", value=result['sender'], inline=True)
                        embed.set_footer(text=f"Subject: {result['subject'][:100]}")
                        try:
                            asyncio.run_coroutine_threadsafe(channel.send(embed=embed), bot.loop)
                        except Exception as e:
                            print(f"[ERROR] sending to discord channel {cfg.get('channel_id')}: {e}")
            else:
                # dump non-matching full_text for inspection
                try:
                    with open("debug_email_dump.txt", "a", encoding="utf-8") as df:
                        dump = {"uid": uid, "from": msg.get("From"), "full_text": full_text}
                        df.write(json.dumps(dump) + "\n\n")
                    if VERBOSE:
                        print(f"[DEBUG] Dumped non-matching email uid {uid}")
                except Exception as e:
                    print(f"[ERROR] writing debug dump for uid {uid}: {e}")

            # persist UID so we don't re-post later
            seen_set.add(uid)
            save_seen_uids()

    finally:
        try:
            mail.close()
            mail.logout()
        except Exception:
            pass

def parse_email(msg, return_full_text=False):
    # decode subject header safely
    subject_header = msg.get("Subject", "") or ""
    decoded = decode_header(subject_header)[0][0]
    subject = decoded.decode(errors="ignore") if isinstance(decoded, bytes) else (decoded or "")

    # extract text body: prefer text/plain, else join html parts and convert
    body = ""
    html_parts = []
    try:
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                disp = str(part.get("Content-Disposition") or "")
                if "attachment" in disp:
                    continue
                payload = part.get_payload(decode=True)
                if not payload:
                    continue
                if ctype == "text/plain":
                    body = payload.decode(errors="ignore")
                    break
                elif ctype == "text/html":
                    try:
                        html_parts.append(payload.decode(errors="ignore"))
                    except Exception:
                        html_parts.append(payload.decode("utf-8", errors="ignore"))
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                try:
                    body = payload.decode(errors="ignore")
                except Exception:
                    body = payload.decode("utf-8", errors="ignore")
    except Exception as e:
        if VERBOSE:
            print(f"[WARN] error extracting parts: {e}")

    if not body and html_parts:
        html = "\n".join(html_parts)
        body = BeautifulSoup(html, "html.parser").get_text("\n")

    full_text = f"{subject}\n{body}"
    from_addr = (email.utils.parseaddr(msg.get("From", ""))[1] or "").lower()
    from_name = (email.utils.parseaddr(msg.get("From", ""))[0] or "").strip()

    # service detection
    service = None
    ft_lower = full_text.lower()
    if "zelle" in from_addr or "zelle" in ft_lower:
        service = "Zelle"
    elif "chime" in from_addr or "chime" in ft_lower:
        service = "Chime"
    elif "paypal" in from_addr or "paypal" in ft_lower or "sent you" in ft_lower or "transaction id" in ft_lower:
        service = "PayPal"
    elif "cashapp" in from_addr or "cash app" in ft_lower or "cashapp" in ft_lower:
        service = "Cash App"
    elif "venmo" in from_addr or "venmo.com" in from_addr or "venmo" in ft_lower:
        service = "Venmo"
    else:
        # Zelle heuristics for bank notifications
        if re.search(r"good news[:\s].*zelle", full_text, re.IGNORECASE) or \
           re.search(r"has just sent you money.*zelle", full_text, re.IGNORECASE) or \
           re.search(r"\bSENT YOU MONEY\b", full_text, re.IGNORECASE) or \
           (from_name and from_name.isupper() and "zelle" in ft_lower):
            service = "Zelle"

    if not service:
        return (None, full_text) if return_full_text else None

    amount, sender = extract_amount_and_sender(full_text, service)
    if amount is None:
        return (None, full_text) if return_full_text else None

    result = {
        "service": service,
        "amount": amount,
        "sender": sender,
        "subject": subject or ""
    }
    return (result, full_text) if return_full_text else result

def extract_amount_and_sender(text, service):
    patterns = {
        "Zelle": [
            r'([A-Z][A-Z\-\s]{1,120}?)\s+has\s+just\s+sent\s+you\s+money(?:\s+via\s+Zelle)?[^\$]*\$?([\d,]+(?:\.\d{1,2})?)',
            r'has\s+just\s+sent\s+you[^\$]*\$?([\d,]+(?:\.\d{1,2})?)',
            r'good\s+news[:\s].*?sent\s+you\s+money[^\$]*\$?([\d,]+(?:\.\d{1,2})?)',
            r'Amount[:\s]+\$?([\d,]+(?:\.\d{1,2})?)',
            r'Zelle[^\$]{0,60}\$?([\d,]+(?:\.\d{1,2})?)',
        ],
        "PayPal": [
            r'([A-Za-z][A-Za-z\'\-\.\s]{1,120}?)\s+sent\s+you\s+\$?([\d,]+(?:\.\d{1,2})?)\s*USD',
            r'Amount[:\s]+\$?([\d,]+(?:\.\d{1,2})?)',
            r'You received a payment of \$?([\d,]+(?:\.\d{1,2})?)',
            r'You received \$?([\d,]+(?:\.\d{1,2})?)',
            r'Payment received[:\s]+\$?([\d,]+(?:\.\d{1,2})?)'
        ],
        "Chime": [
            r'You just got paid \$?([\d,]+(?:\.\d{1,2})?)'
        ],
        "Cash App": [
            r'Cash App.+?\$?([\d,]+(?:\.\d{1,2})?)'
        ],
        "Venmo": [
            r'paid you \$?([\d,]+(?:\.\d{1,2})?)'
        ]
    }

    for pattern in patterns.get(service, []):
        match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
        if not match:
            continue

        # If two groups captured (name + amount)
        if service in ("Zelle", "PayPal") and len(match.groups()) >= 2:
            sender_candidate = match.group(1).strip()
            amount_candidate = match.group(2)
        else:
            amount_candidate = match.group(1)
            sender_candidate = extract_sender_info(text)

        if not amount_candidate:
            continue

        amount_str = re.sub(r"[^\d.]", "", amount_candidate)
        try:
            amount = float(amount_str)
            if amount <= 0:
                continue
            sender = (sender_candidate.title() if sender_candidate and sender_candidate.isupper() else (sender_candidate or extract_sender_info(text)))
            return amount, sender
        except (ValueError, TypeError):
            continue

    return None, None

def extract_sender_info(text):
    name_match = re.search(r'From[:\s]+([A-Za-z][A-Za-z\'\-\.\s]{1,120}?)', text, re.IGNORECASE)
    name = name_match.group(1).strip() if name_match else None

    uppercase_match = re.search(r'\n([A-Z][A-Z\-\s]{1,120}?)\s+has\s+just\s+sent\s+you', text)
    uppercase_name = uppercase_match.group(1).strip() if uppercase_match else None

    sent_name_match = re.search(r'([A-Za-z][A-Za-z\'\-\.\s]{1,120}?)\s+sent\s+you', text, re.IGNORECASE)
    sent_name = sent_name_match.group(1).strip() if sent_name_match else None

    phone_match = re.search(r'(\+?\d{1,3}[-.\s]?\(?\d{2,4}\)?[-.\s]?\d{2,4}[-.\s]?\d{2,4})', text)
    phone = re.sub(r'[^\d+]', '', phone_match.group(1)) if phone_match else None
    if phone:
        phone = phone[-10:]
        phone = ('+1' + phone) if not phone.startswith('+') else phone

    email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', text)
    sender_email = email_match.group(0).lower() if email_match else None

    return name or uppercase_name or sent_name or phone or sender_email or "Unknown Sender"

@bot.event
async def on_ready():
    print(f"[DEBUG] Logged in as: {bot.user}")
    print("[DEBUG] Starting email polling thread...")
    thread = threading.Thread(target=email_check_loop, daemon=True)
    thread.start()

# Ensure seen UID save on exit
atexit.register(save_seen_uids)

if __name__ == "__main__":
    try:
        print("[DEBUG] Calling bot.run()")
        bot.run(TOKEN)
    except discord.LoginFailure:
        print("[ERROR] Invalid Discord token")
    except Exception as e:
        print(f"[ERROR] Unexpected runtime error: {e}")