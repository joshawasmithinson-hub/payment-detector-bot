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
    email_configs.append({
        'address': addr,
        'password': os.getenv(f'EMAIL_{i}_PASSWORD'),
        'imap': os.getenv(f'EMAIL_{i}_IMAP', 'imap.gmail.com'),
        'channel_id': int(os.getenv(f'EMAIL_{i}_CHANNEL')),
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
        with open(SEEN_FILE, 'r') as f:
            data = json.load(f)
            return {k: set(v) for k, v in data.items()}
    # initialize per configured address
    return {cfg['address']: set() for cfg in email_configs}

def save_seen_uids():
    with open(SEEN_FILE, 'w') as f:
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

        since_date = (datetime.now() - timedelta(hours=1)).strftime('%d-%b-%Y')
        status, data = mail.search(None, f'(SINCE "{since_date}")')
        if status != 'OK':
            print(f"[DEBUG] Search failed")
            mail.close()
            mail.logout()
            return

        uids = data[0].split()
        if not uids or uids == [b'']:
            print(f"[DEBUG] No new emails")
            mail.close()
            mail.logout()
            return

        print(f"[DEBUG] Found {len(uids)} email(s)")
        channel = bot.get_channel(cfg['channel_id'])
        if not channel:
            print(f"[ERROR] Channel not found for id {cfg['channel_id']}!")
            mail.close()
            mail.logout()
            return

        for uid in uids:
            uid = uid.decode()
            if uid in seen_uids.get(cfg['address'], set()):
                continue

            status, msg_data = mail.fetch(uid, '(RFC822)')
            if status != 'OK' or not msg_data or not msg_data[0]:
                continue

            raw_email = msg_data[0][1]
            msg = email.message_from_bytes(raw_email)
            result = parse_email(msg)

            if result:
                print(f"[SUCCESS] ${result['amount']} from {result['sender']}")
                embed = discord.Embed(
                    title=f"New {result['service']} Payment!",
                    description=f"**Account:** `{cfg['address']}`",
                    color=0x00ff00
                )
                embed.add_field(name="Amount", value=f"${result['amount']:,.2f}", inline=True)
                embed.add_field(name="From", value=result['sender'], inline=True)
                embed.set_footer(text=f"Subject: {result['subject'][:100]}")

                asyncio.run_coroutine_threadsafe(channel.send(embed=embed), bot.loop)

            # mark seen and persist
            seen_uids.setdefault(cfg['address'], set()).add(uid)
            save_seen_uids()

        mail.close()
        mail.logout()

    except Exception as e:
        print(f"[ERROR] {cfg['address']}: {e}")

def parse_email(msg):
    subject_header = msg.get("Subject", "")
    decoded = decode_header(subject_header)[0][0]
    subject = decoded.decode() if isinstance(decoded, bytes) else decoded

    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition"))
            if ctype == "text/plain" and "attachment" not in disp:
                payload = part.get_payload(decode=True)
                if payload:
                    body = payload.decode(errors='ignore')
                    break
            elif ctype == "text/html" and not body:
                payload = part.get_payload(decode=True)
                if payload:
                    html = payload.decode(errors='ignore')
                    soup = BeautifulSoup(html, "html.parser")
                    body = soup.get_text(separator='\n')
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body = payload.decode(errors='ignore')

    full_text = f"{subject}\n{body}"
    from_hdr = email.utils.parseaddr(msg.get("From", ""))[1].lower()

    service = None
    if 'zelle' in from_hdr or 'zelle' in full_text.lower():
        service = 'Zelle'
    elif 'chime' in from_hdr or 'chime' in full_text.lower():
        service = 'Chime'
    elif 'paypal' in from_hdr or 'paypal' in full_text.lower():
        service = 'PayPal'
    elif 'cash' in from_hdr or 'cashapp' in from_hdr:
        service = 'Cash App'
    elif 'venmo' in from_hdr or 'venmo.com' in from_hdr:
        service = 'Venmo'

    if not service:
        return None

    amount, sender = extract_amount_and_sender(full_text, service)
    if amount is None:
        return None

    return {
        'service': service,
        'amount': amount,
        'sender': sender,
        'subject': subject or ""
    }

def extract_amount_and_sender(text, service):
    patterns = {
        'Zelle': [r'You received \$?([\d,]+\.?\d*) from'],
        'Chime': [r'You just got paid \$?([\d,]+\.?\d*)'],
        'PayPal': [
            r'You received a payment of \$?([\d,]+\.?\d*)',
            r'You received \$?([\d,]+\.?\d*)',
            r'Payment received[:\s]+\$?([\d,]+\.?\d*)',
            r"You've got money.+?\$?([\d,]+\.?\d*)",
            r"([A-Z][a-z]+(?:\s[A-Z][a-z]+)?) sent you \$?([\d,]+\.?\d*) USD"
        ],
        'Cash App': [r'Cash App.+?\$?([\d,]+\.?\d*)'],
        'Venmo': [r'paid you \$?([\d,]+\.?\d*)'],
    }

    for pattern in patterns.get(service, []):
        match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
        if not match:
            continue

        # PayPal pattern that captures sender and amount
        if service == 'PayPal' and len(match.groups()) == 2:
            sender = match.group(1).strip()
            amount_str = re.sub(r'[^\d.]', '', match.group(2).strip())
        else:
            amount_str = re.sub(r'[^\d.]', '', match.group(1).strip())
            sender = extract_sender_info(text)

        try:
            amount = float(amount_str)
            if amount <= 0:
                continue
            return amount, sender
        except (ValueError, TypeError):
            continue
    return None, None

def extract_sender_info(text):
    name_match = re.search(r'(?:from|sent by|paid by)\s+([A-Z][a-z]+(?:\s[A-Z][a-z]+)?)', text, re.IGNORECASE)
    name = name_match.group(1).strip() if name_match else None

    phone_match = re.search(r'(\+?\d{1,3}[-.\s]?\(?\d{2,4}\)?[-.\s]?\d{2,4}[-.\s]?\d{2,4})', text)
    phone = re.sub(r'[^\d+]', '', phone_match.group(1)) if phone_match else None
    if phone:
        phone = phone[-10:]
        phone = '+1' + phone if not phone.startswith('+') else phone

    email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', text)
    sender_email = email_match.group(0).lower() if email_match else None

    return name or phone or sender_email or "Unknown Sender"

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