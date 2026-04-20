#!/bin/bash
set -e

DOMAIN="igsu.local"
SELECTOR="mail"

# Generate DKIM keys if they don't exist
if [ ! -f /etc/opendkim/keys/$DOMAIN/$SELECTOR.private ]; then
    echo "Generating DKIM keys for $DOMAIN..."
    opendkim-genkey -b 2048 -d $DOMAIN \
        -D /etc/opendkim/keys/$DOMAIN -s $SELECTOR -v
    chown -R opendkim:opendkim /etc/opendkim/keys
    echo "DKIM TXT record:"
    cat /etc/opendkim/keys/$DOMAIN/$SELECTOR.txt
fi

# OpenDKIM signing/key tables (igsu.local only)
echo "*@$DOMAIN $SELECTOR._domainkey.$DOMAIN" \
    > /etc/opendkim/signing.table
echo "$SELECTOR._domainkey.$DOMAIN $DOMAIN:$SELECTOR:/etc/opendkim/keys/$DOMAIN/$SELECTOR.private" \
    > /etc/opendkim/key.table
printf "127.0.0.1\n::1\nlocalhost\n*.$DOMAIN\n" \
    > /etc/opendkim/trusted.hosts

chown -R opendkim:opendkim /etc/opendkim

# Build virtual mailbox map (catch-all for igsu.local)
echo "@$DOMAIN OK" > /etc/postfix/relay_recipients
postmap /etc/postfix/relay_recipients

# Transport map — deliver igsu.local via LMTP to Dovecot
echo "$DOMAIN lmtp:inet:dovecot:24" > /etc/postfix/transport
postmap /etc/postfix/transport

# Copy DNS config into Postfix chroot so smtpd can resolve hostnames
mkdir -p /var/spool/postfix/etc
cp /etc/resolv.conf /var/spool/postfix/etc/resolv.conf
cp /etc/hosts       /var/spool/postfix/etc/hosts
cp /etc/nsswitch.conf /var/spool/postfix/etc/nsswitch.conf 2>/dev/null || true
cp /etc/services    /var/spool/postfix/etc/services

# Fix permissions
chown -R postfix:postfix /var/spool/postfix || true
chown -R root:root /var/spool/postfix/etc
postfix set-permissions || true

# Wait for cert volume to be populated
for i in $(seq 1 30); do
    [ -f /certs/server.crt ] && break
    echo "Waiting for TLS certificates... ($i/30)"
    sleep 2
done
[ -f /certs/server.crt ] || { echo "ERROR: TLS certificates not found."; exit 1; }

# Start rsyslog
rsyslogd

# Start OpenDKIM
opendkim -x /etc/opendkim.conf

# Start Postfix in foreground
postfix start-fg
