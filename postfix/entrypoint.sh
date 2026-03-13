#!/bin/sh
set -e

echo "Waiting for Dovecot LMTP on dovecot:24..."
until nc -z dovecot 24; do
  sleep 1
done
echo "Dovecot LMTP is up."

# Enable submission (port 587) with SASL auth
postconf -M "submission/inet=submission inet n - y - - smtpd"
postconf -P "submission/inet/smtpd_sasl_auth_enable=yes"
postconf -P "submission/inet/smtpd_recipient_restrictions=permit_sasl_authenticated,reject"

# Copy DNS config into the chroot so smtpd can resolve hostnames
cp /etc/resolv.conf /var/spool/postfix/etc/resolv.conf
cp /etc/hosts /var/spool/postfix/etc/hosts
cp /etc/nsswitch.conf /var/spool/postfix/etc/nsswitch.conf
cp /etc/services /var/spool/postfix/etc/services

exec postfix start-fg
