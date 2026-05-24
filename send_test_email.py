#!/usr/bin/env python3
import smtplib
from email import message_from_file
import sys
import io

# Citeste EML-ul cu UTF-8
with open('samples/mai_joke.eml', 'r', encoding='utf-8') as f:
    msg = message_from_file(f)

# Conectare Postfix pe localhost:25
try:
    server = smtplib.SMTP('localhost', 25)

    # Trimite email
    from_addr = msg['From'].split('<')[-1].rstrip('>')
    to_addr = msg['To'].split('<')[-1].rstrip('>')

    server.sendmail(from_addr, to_addr, msg.as_string())
    server.quit()

    print("[OK] Email trimis cu succes la razvan.dobreanu@igsu.local")
    print(f"  From: {msg['From']}")
    print(f"  To: {msg['To']}")
    print(f"  Subject: {msg['Subject']}")

except Exception as e:
    print(f"[ERROR] Eroare la trimitere: {e}")
    sys.exit(1)
