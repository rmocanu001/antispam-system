#!/bin/bash

# Setup Script for IGSU Antispam Relay (Dual NIC)
# Interfaces:
# - eth0 (WAN): External facing, receives mail (MX)
# - eth1 (LAN): Internal facing, relay to internal server

# Configuration
WAN_IF="eth0"
LAN_IF="eth1"
INTERNAL_MAIL_SERVER="192.168.1.10" # Example internal Exchange/Zimbra
HOSTNAME="antispam.igsu.local"

echo "Configuring Hostname..."
hostnamectl set-hostname $HOSTNAME

echo "Installing Dependencies..."
apt-get update
apt-get install -y postfix spamassassin spamc

echo "Configuring Network (Forwarding)..."
# Enable IP Forwarding if needed for transparent proxy, but for SMTP relay typical setup is enough.
sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

echo "Configuring Postfix..."
# Backup existing config
cp /etc/postfix/main.cf /etc/postfix/main.cf.bak
cp /etc/postfix/master.cf /etc/postfix/master.cf.bak

# Deploy Configs (Assumes files are present in ./deployment/postfix)
cp ./deployment/postfix/main.cf /etc/postfix/main.cf
cp ./deployment/postfix/master.cf /etc/postfix/master.cf

# Update internal relay host
postconf -e "relayhost = [$INTERNAL_MAIL_SERVER]"

echo "Configuring SpamAssassin..."
cp ./deployment/spamassassin/local.cf /etc/spamassassin/local.cf

echo "Enabling Services..."
systemctl enable spamassassin
systemctl start spamassassin
systemctl enable postfix
systemctl restart postfix

echo "Setup Complete. Verify logs at /var/log/mail.log"
