#!/bin/sh
set -e

echo "Waiting for Dovecot LMTP on dovecot:24..."
until nc -z dovecot 24; do
  sleep 1
done
echo "Dovecot LMTP is up."

# Enable submission (port 587) with SASL auth.
#
# Keep off-domain relay protected while still allowing delivery to
# local.test recipients for local client testing.
postconf -M "submission/inet=submission inet n - n - - smtpd"
postconf -P "submission/inet/smtpd_sasl_auth_enable=yes"
postconf -P "submission/inet/smtpd_relay_restrictions=reject_unauth_destination"

# Enable implicit TLS SMTP (port 465) for clients that select SSL/TLS.
postconf -M "smtps/inet=smtps inet n - n - - smtpd"
postconf -P "smtps/inet/smtpd_tls_wrappermode=yes"
postconf -P "smtps/inet/smtpd_sasl_auth_enable=yes"
postconf -P "smtps/inet/smtpd_relay_restrictions=reject_unauth_destination"

# Copy DNS config into the chroot so smtpd can resolve hostnames
cp /etc/resolv.conf /var/spool/postfix/etc/resolv.conf
cp /etc/hosts /var/spool/postfix/etc/hosts
cp /etc/nsswitch.conf /var/spool/postfix/etc/nsswitch.conf
cp /etc/services /var/spool/postfix/etc/services

exec postfix start-fg
