#!/bin/sh
set -e

echo "Waiting for Dovecot LMTP on dovecot:24..."
until nc -z dovecot 24; do
  sleep 1
done
echo "Dovecot LMTP is up."

# Copy DNS config into the chroot so smtpd can resolve hostnames
cp /etc/resolv.conf /var/spool/postfix/etc/resolv.conf
cp /etc/hosts /var/spool/postfix/etc/hosts
cp /etc/nsswitch.conf /var/spool/postfix/etc/nsswitch.conf
cp /etc/services /var/spool/postfix/etc/services

exec postfix start-fg
