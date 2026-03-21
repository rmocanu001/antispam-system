#!/bin/bash
set -e

# Create vmail user and group
groupadd -g 5000 vmail 2>/dev/null || true
useradd -u 5000 -g vmail -d /var/mail -s /usr/sbin/nologin vmail 2>/dev/null || true

# Create mail directories for each user
for user in user1 admin test; do
    mkdir -p /var/mail/${user}@igsu.local/Maildir/{cur,new,tmp}
    chown -R vmail:vmail /var/mail/${user}@igsu.local
done

# Fix permissions
chown -R vmail:vmail /var/mail

# Generate proper passwords (test123 for all users)
if command -v doveadm &>/dev/null; then
    HASH=$(doveadm pw -s SHA512-CRYPT -p test123)
    cat > /etc/dovecot/users <<EOF
user1@igsu.local:${HASH}::::::
admin@igsu.local:${HASH}::::::
test@igsu.local:${HASH}::::::
EOF
fi

echo "Starting Dovecot..."
exec dovecot -F
