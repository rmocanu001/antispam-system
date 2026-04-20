FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    dovecot-imapd \
    dovecot-lmtpd \
    dovecot-mysql \
    && rm -rf /var/lib/apt/lists/*

COPY dovecot.conf          /etc/dovecot/dovecot.conf
COPY dovecot-sql.conf.ext  /etc/dovecot/dovecot-sql.conf.ext
COPY entrypoint.sh         /entrypoint.sh
RUN sed -i 's/\r//' /entrypoint.sh && chmod +x /entrypoint.sh

EXPOSE 143 993 24 12345

ENTRYPOINT ["/entrypoint.sh"]
