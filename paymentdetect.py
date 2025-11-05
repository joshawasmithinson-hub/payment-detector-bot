print("[BOOT] paymentdetect.py is running")

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
from datetime import datetime, timedelta
from discord.ext import commands
from dotenv import load_dotenv
from bs4 import BeautifulSoup

# Load environment variables
print("[DEBUG] Loading .env file")
load_dotenv("info.env")

print("[DEBUG] Getting DISCORD_TOKEN")
TOKEN = os.getenv('DISCORD_TOKEN')
if not TOKEN:
    print("[ERROR] DISCORD_TOKEN not found in .env")

# Load email configs
email_configs = []
i = 1
while True:
    addr = os.getenv(f'EMAIL_{i}_ADDRESS')
    if not addr:
        break
    try:
        channel_id = int(os.getenv(f'EMAIL_{i}_CHANNEL'))
    except (TypeError, ValueError):
        channel_id = None
    email_configs.append({
        'address': addr,
        'password': os.getenv(f'EMAIL_{i}_PASSWORD'),
        'imap': os.getenv(f'EMAIL_{i}_IMAP', 'imap.gmail.com'),
        'channel_id': channel_id,
    })
    i += 1

print(f"[DEBUG] Loaded {len(email_configs)} email config(s)")
if not email_configs:
    raise ValueError("No email accounts configured in info.env")

# Setup Discord bot
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

SEEN_FILE = "seen_uids.json"

def load_seen_uids():
    if os.path.exists(SEEN_FILE):
        with open(SEEN_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return {k: set(v) for k, v in data.items()}
    return {cfg['address']: set() for cfg in email_configs}

def save_seen_uids():
    with open(SEEN_FILE, 'w', encoding='utf-8') as f:
        json.dump({k: list(v) for k, v in seen_uids.items()}, f)

seen_uids = load_seen_uids()

def email_check_loop():
    while True:
        print(f"\n[CYCLE] Checking {len(email_configs)} accounts...")
        for cfg in email_configs:
            check_single_email_blocking(cfg)
        time.sleep(30)

def check_single_email_blocking(cfg):
    try:
        print(f"[DEBUG] Logging into {cfg['address']}...")
        mail = imaplib.IMAP4_SSL(cfg['imap'])
        mail.login(cfg['address'], cfg['password'])
        mail.select('inbox')

        # Use UNSEEN + SINCE 1 hour to target unread messages within last hour
        since_date = (datetime.now() - timedelta(hours=1)).strftime('%d-%b-%Y')
        # combine UNSEEN and SINCE to reduce thread/stack issues while keeping 1-hour window
        status, data = mail.search(None, f'(UNSEEN SINCE "{since_date}")')
        if status != 'OK':
            print(f"[DEBUG] Search failed for {cfg['address']}")
            mail.close()
            mail.logout()
            return

        uids = data[0].split()
        if not uids or uids == [b'']:
            print(f"[DEBUG] No new emails for {cfg['address']}")
            mail.close()
            mail.logout()
            return

        print(f"[DEBUG] Found {len(uids)} email(s) for {cfg['address']}")
        channel = bot.get_channel(cfg['channel_id']) if cfg['channel_id'] else None
        if not channel:
            print(f"[ERROR] Channel not found or not configured for account {cfg['address']} (id={cfg['channel_id']})")
            # Continue parsing but skip sending if channel missing

        for uid_b in uids:
            uid = uid_b.decode()
            if uid in seen_uids.get(cfg['address'], set()):
                continue

            # Use BODY.PEEK[] to avoid marking as read by fetch
            status, msg_data = mail.fetch(uid_b, '(BODY.PEEK[])')
            if status != 'OK' or not msg_data or not msg_data[0]:
                continue

            raw_email = msg_data[0][1]
            msg = email.message_from_bytes(raw_email)

            result, full_text = parse_email(msg, return_full_text=True)

            if result:
                print(f"[SUCCESS] ${result['amount']} from {result['sender']} via {result['service']}")
                if channel:
                    embed = discord.Embed(
                        title=f"New {result['service']} Payment!",
                        description=f"**Account:** `{cfg['address']}`",
                        color=0x00ff00
                    )
                    embed.add_field(name="Amount", value=f"${result['amount']:,.2f}", inline=True)
                    embed.add_field(name="From", value=result['sender'], inline=True)
                    embed.set_footer(text=f"Subject: {result['subject'][:100]}")
                    asyncio.run_coroutine_threadsafe(channel.send(embed=embed), bot.loop)
            else:
                # Debug dump for non-matching emails
                try:
                    with open("debug_email_dump.txt", "a", encoding="utf-8") as df:
                        dump = {"uid": uid, "from": msg.get("From"), "full_text": full_text}
                        df.write(json.dumps(dump) + "\n\n")
                    print(f"[DEBUG] Dumped email uid {uid} to debug_email_dump.txt")
                except Exception as de:
                    print(f"[DEBUG] Dump failed: {de}")

            seen_uids.setdefault(cfg['address'], set()).add(uid)
            save_seen_uids()

        mail.close()
        mail.logout()

    except Exception as e:
        print(f"[ERROR] {cfg['address']}: {e}")

def parse_email(msg, return_full_text=False):
    # decode subject
    subject_header = msg.get("Subject", "")
    decoded = decode_header(subject_header)[0][0]
    subject = decoded.decode(errors='ignore') if isinstance(decoded, bytes) else (decoded or "")

    # robust text extraction preferring plain text
    body = ""
    html_parts = []
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
                body = payload.decode(errors='ignore')
                break
            elif ctype == "text/html":
                html_parts.append(payload.decode(errors='ignore'))
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body = payload.decode(errors='ignore')

    if not body and html_parts:
        html = "\n".join(html_parts)
        body = BeautifulSoup(html, "html.parser").get_text("\n")

    full_text = f"{subject}\n{body}"
    from_hdr = (email.utils.parseaddr(msg.get("From", ""))[1] or "").lower()
    # also capture display name to help detect uppercase names from banks
    from_name = (email.utils.parseaddr(msg.get("From", ""))[0] or "").strip()

    # Broadened service detection with enhanced Zelle rules
    service = None
    if 'zelle' in from_hdr or 'zelle' in full_text.lower():
        service = 'Zelle'
    elif 'chime' in from_hdr or 'chime' in full_text.lower():
        service = 'Chime'
    elif 'paypal' in from_hdr or 'paypal' in full_text.lower() or 'sent you' in full_text.lower() or 'transaction id' in full_text.lower():
        service = 'PayPal'
    elif 'cash' in from_hdr or 'cashapp' in from_hdr:
        service = 'Cash App'
    elif 'venmo' in from_hdr or 'venmo.com' in from_hdr:
        service = 'Venmo'
    else:
        # additional Zelle heuristics: capitalized headline patterns from banks
        # e.g., "Good news: Someone sent you money with Zelle"
        if re.search(r'good news[:\s].*zelle', full_text, re.IGNORECASE) or \
           re.search(r'has just sent you money.*zelle', full_text, re.IGNORECASE) or \
           re.search(r'\bSENT YOU MONEY\b', full_text, re.IGNORECASE) or \
           (from_name and from_name.isupper() and 'zelle' in full_text.lower()):
            service = 'Zelle'

    if not service:
        return (None, full_text) if return_full_text else None

    amount, sender = extract_amount_and_sender(full_text, service)
    if amount is None:
        return (None, full_text) if return_full_text else None

    return ({
        'service': service,
        'amount': amount,
        'sender': sender,
        'subject': subject or ""
    }, full_text) if return_full_text else {
        'service': service,
        'amount': amount,
        'sender': sender,
        'subject': subject or ""
    }

def extract_amount_and_sender(text, service):
    # Patterns tuned for Zelle (bank notifications), PayPal, Chime, Cash App, Venmo
    patterns = {
        'Zelle': [
            # Capital One / bank style: "JILL BAILEY has just sent you money via Zelle® in the amount of $12.80."
            r'([A-Z][A-Z\-\s]{1,120}?)\s+has\s+just\s+sent\s+you\s+money(?:\s+via\s+Zelle)?[^\$]*\$?([\d,]+(?:\.\d{1,2})?)',
            # "has just sent you $12.80"
            r'has\s+just\s+sent\s+you[^\$]*\$?([\d,]+(?:\.\d{1,2})?)',
            # "Good news: Someone sent you money with Zelle"
            r'good\s+news[:\s].*?sent\s+you\s+money[^\$]*\$?([\d,]+(?:\.\d{1,2})?)',
            # fallback: "Amount: $12.80"
            r'Amount[:\s]+\$?([\d,]+(?:\.\d{1,2})?)',
            # any dollar amount labeled near "Zelle"
            r'Zelle[^\$]{0,60}\$?([\d,]+(?:\.\d{1,2})?)',
        ],
        'PayPal': [
            r'([A-Za-z][A-Za-z\'\-\.\s]{1,120}?)\s+sent\s+you\s+\$?([\d,]+(?:\.\d{1,2})?)\s*USD',
            r'Amount[:\s]+\$?([\d,]+(?:\.\d{1,2})?)',
            r'You received a payment of \$?([\d,]+(?:\.\d{1,2})?)',
            r'You received \$?([\d,]+(?:\.\d{1,2})?)',
            r'Payment received[:\s]+\$?([\d,]+(?:\.\d{1,2})?)'
        ],
        'Chime': [
            r'You just got paid \$?([\d,]+(?:\.\d{1,2})?)'
        ],
        'Cash App': [
            r'Cash App.+?\$?([\d,]+(?:\.\d{1,2})?)'
        ],
        'Venmo': [
            r'paid you \$?([\d,]+(?:\.\d{1,2})?)'
        ]
    }

    for pattern in patterns.get(service, []):
        match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
        if not match:
            continue

        # If Zelle pattern captured name + amount
        if service == 'Zelle' and len(match.groups()) >= 2:
            sender_candidate = match.group(1).strip()
            amount_candidate = match.group(2)
        elif service == 'PayPal' and len(match.groups()) >= 2:
            sender_candidate = match.group(1).strip()
            amount_candidate = match.group(2)
        else:
            # single-group matches: amount only
            amount_candidate = match.group(1)
            sender_candidate = extract_sender_info(text)

        if not amount_candidate:
            continue

        amount_str = re.sub(r'[^\d.]', '', amount_candidate)
        try:
            amount = float(amount_str)
            if amount <= 0:
                continue
            # clean sender: uppercase bank notifications often use all caps
            sender = sender_candidate.title() if sender_candidate and sender_candidate.isupper() else (sender_candidate or extract_sender_info(text))
            return amount, sender
        except (ValueError, TypeError):
            continue

    return None, None

def extract_sender_info(text):
    # Try multiple heuristics: "From: Name", "From: NAME" (banks often uppercase), email addresses, or "sent you" patterns
    name_match = re.search(r'From[:\s]+([A-Za-z][A-Za-z\'\-\.\s]{1,120}?)', text, re.IGNORECASE)
    name = name_match.group(1).strip() if name_match else None

    # bank style uppercase name
    uppercase_match = re.search(r'\n([A-Z][A-Z\-\s]{1,120}?)\s+has\s+just\s+sent\s+you', text)
    uppercase_name = uppercase_match.group(1).strip() if uppercase_match else None

    sent_name_match = re.search(r'([A-Za-z][A-Za-z\'\-\.\s]{1,120}?)\s+sent\s+you', text, re.IGNORECASE)
    sent_name = sent_name_match.group(1).strip() if sent_name_match else None

    phone_match = re.search(r'(\+?\d{1,3}[-.\s]?\(?\d{2,4}\)?[-.\s]?\d{2,4}[-.\s]?\d{2,4})', text)
    phone = re.sub(r'[^\d+]', '', phone_match.group(1)) if phone_match else None
    if phone:
        phone = phone[-10:]
        phone = '+1' + phone if not phone.startswith('+') else phone

    email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', text)
    sender_email = email_match.group(0).lower() if email_match else None

    return name or uppercase_name or sent_name or phone or sender_email or "Unknown Sender"

@bot.event
async def on_ready():
    print(f"[DEBUG] Logged in as: {bot.user}")
    print("[DEBUG] Starting email polling thread...")
    thread = threading.Thread(target=email_check_loop, daemon=True)
    thread.start()

# ensure seen file is saved on exit
atexit.register(save_seen_uids)

# Run bot
print("[DEBUG] Calling bot.run()")
try:
    bot.run(TOKEN)
except discord.LoginFailure:
    print("[ERROR] Invalid Discord token")
except Exception as e:
    print(f"[ERROR] Unexpected: {e}")