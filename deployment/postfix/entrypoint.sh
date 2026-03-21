#!/bin/bash
set -e

DOMAIN="igsu.local"
SELECTOR="mail"

# Generate DKIM keys if they don't exist
if [ ! -f /etc/opendkim/keys/$DOMAIN/$SELECTOR.private ]; then
    echo "Generating DKIM keys for $DOMAIN..."
    opendkim-genkey -b 2048 -d $DOMAIN -D /etc/opendkim/keys/$DOMAIN -s $SELECTOR -v
    chown -R opendkim:opendkim /etc/opendkim/keys
    echo "DKIM TXT record to add to DNS:"
    cat /etc/opendkim/keys/$DOMAIN/$SELECTOR.txt
fi

# Create OpenDKIM tables
echo "*@$DOMAIN $SELECTOR._domainkey.$DOMAIN" > /etc/opendkim/signing.table
echo "$SELECTOR._domainkey.$DOMAIN $DOMAIN:$SELECTOR:/etc/opendkim/keys/$DOMAIN/$SELECTOR.private" > /etc/opendkim/key.table
echo "127.0.0.1" > /etc/opendkim/trusted.hosts
echo "::1" >> /etc/opendkim/trusted.hosts
echo "localhost" >> /etc/opendkim/trusted.hosts
echo "*.$DOMAIN" >> /etc/opendkim/trusted.hosts

chown -R opendkim:opendkim /etc/opendkim

# Create relay_recipients if it doesn't exist
if [ ! -f /etc/postfix/relay_recipients ]; then
    echo "@$DOMAIN OK" > /etc/postfix/relay_recipients
    echo "@igsu.ro OK" >> /etc/postfix/relay_recipients
    postmap /etc/postfix/relay_recipients
fi

# Create transport map
if [ ! -f /etc/postfix/transport ]; then
    echo "$DOMAIN lmtp:inet:dovecot:24" > /etc/postfix/transport
    echo "igsu.ro lmtp:inet:dovecot:24" >> /etc/postfix/transport
    postmap /etc/postfix/transport
fi

# Fix permissions
chown -R postfix:postfix /var/spool/postfix || true
postfix set-permissions || true

# Start rsyslog for logging
rsyslogd

# Start OpenDKIM
opendkim -x /etc/opendkim.conf

# Start Postfix in foreground
postfix start-fg
