FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    postfix \
    opendkim \
    opendkim-tools \
    postfix-policyd-spf-python \
    spamc \
    rsyslog \
    && rm -rf /var/lib/apt/lists/*

# Create directories
RUN mkdir -p /etc/opendkim/keys/igsu.local \
    && mkdir -p /var/spool/postfix/opendkim \
    && chown opendkim:opendkim /var/spool/postfix/opendkim

# Copy configuration files
COPY main.cf /etc/postfix/main.cf
COPY master.cf /etc/postfix/master.cf
COPY opendkim.conf /etc/opendkim.conf

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 25 587

ENTRYPOINT ["/entrypoint.sh"]
