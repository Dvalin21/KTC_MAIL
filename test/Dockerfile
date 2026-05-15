# KTC Mail — config validation container
#
# Build:   docker build -t ktc-mail-test -f test/Dockerfile .
# Run:     docker run --rm ktc-mail-test
#
# This installs the full mail stack and validates every config file
# with the actual tools (postfix check, dovecot -n, nginx -t, etc).
# No ports exposed — this is a syntax/startup test, not a live server.

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV KTC_MAIL_CONFIG_DIR=/etc/ktc-mail
ENV KTC_MAIL_STATE_DIR=/var/lib/ktc-mail

# Install mail stack + Python
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    postfix postfix-pcre \
    dovecot-core dovecot-imapd dovecot-lmtpd dovecot-sieve dovecot-managesieved \
    rspamd redis-server \
    nginx openssl ca-certificates netcat-openbsd nftables \
    python3 python3-pip python3-setuptools \
    systemd systemd-sysv \
    && rm -rf /var/lib/apt/lists/*

# Create vmail user
RUN groupadd -g 5000 vmail \
    && useradd -u 5000 -g vmail -d /var/mail -s /usr/sbin/nologin vmail \
    && install -d -m 0750 -o vmail -g vmail /var/mail

WORKDIR /opt/ktc-mail

# Copy everything
COPY src/ src/
COPY scripts/ scripts/
COPY test/ test/
COPY setup.py .

# Install ktc-mail Python package
# --break-system-packages for Debian bookworm (PEP 668); fallback for older distros.
# DO NOT suppress errors — a failed install must fail the build.
RUN pip install --no-cache-dir -e . --break-system-packages 2>/dev/null || \
    pip install --no-cache-dir -e . 2>/dev/null || \
    (echo "FATAL: pip install failed" >&2 && exit 1)

# Create test setup profile
RUN mkdir -p /etc/ktc-mail && python3 /opt/ktc-mail/test/create_profile.py

# Create config directories and deploy configs
RUN mkdir -p /etc/postfix /etc/dovecot /etc/rspamd/local.d /etc/nginx/sites-enabled \
    /etc/autoconfig \
    && python3 /opt/ktc-mail/test/deploy_configs.py

# Generate self-signed TLS cert for nginx validation
RUN mkdir -p /etc/letsencrypt/live/ktc-mail \
    && openssl req -x509 -nodes -days 90 -newkey rsa:2048 \
        -keyout /etc/letsencrypt/live/ktc-mail/privkey.pem \
        -out /etc/letsencrypt/live/ktc-mail/fullchain.pem \
        -subj "/CN=test.example.com/O=KTC Mail Dev" \
        -addext "subjectAltName=DNS:test.example.com,DNS:autoconfig.test.example.com,DNS:webmail.test.example.com" \
    && cp /etc/letsencrypt/live/ktc-mail/fullchain.pem /etc/letsencrypt/live/ktc-mail/chain.pem

# Create Postfix lookup tables
RUN touch /etc/postfix/virtual_alias /etc/postfix/virtual_mbx \
    && postmap /etc/postfix/virtual_alias 2>/dev/null || true \
    && postmap /etc/postfix/virtual_mbx 2>/dev/null || true

# Link nginx config (remove default site first)
RUN rm -f /etc/nginx/sites-enabled/default && \
    if [ -f /etc/nginx/webmail.conf ]; then \
        ln -sf /etc/nginx/webmail.conf /etc/nginx/sites-enabled/ktc-mail.conf; \
    fi

# Validation entrypoint
COPY test/validate.sh /validate.sh
COPY test/smoke-test.sh /smoke-test.sh
RUN chmod +x /validate.sh /smoke-test.sh

CMD ["/validate.sh"]
