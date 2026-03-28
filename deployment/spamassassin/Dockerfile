FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    spamassassin \
    spamc \
    && rm -rf /var/lib/apt/lists/*

# Create spamd user
RUN groupadd -r spamd && useradd -r -g spamd -d /var/lib/spamassassin -s /usr/sbin/nologin spamd

COPY local.cf /etc/spamassassin/local.cf

# Initialize SpamAssassin rules
RUN sa-update || true

EXPOSE 783

CMD ["spamd", "--listen=0.0.0.0", "--allow-tell", "--nouser-config", "--max-children=5", "-s", "stderr"]
