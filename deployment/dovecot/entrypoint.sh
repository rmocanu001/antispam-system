#!/bin/bash
set -e

# Create vmail user/group for mail storage
groupadd -g 5000 vmail 2>/dev/null || true
useradd -u 5000 -g vmail -d /var/mail -s /usr/sbin/nologin vmail 2>/dev/null || true

mkdir -p /var/mail
chown -R vmail:vmail /var/mail

# Fix config permissions (SQL config contains credentials)
chmod 640 /etc/dovecot/dovecot-sql.conf.ext
chown root:dovecot /etc/dovecot/dovecot-sql.conf.ext

echo "Starting Dovecot..."
exec dovecot -F
