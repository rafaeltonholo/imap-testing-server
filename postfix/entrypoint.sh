#!/bin/sh
set -eu

MAX_WAIT_ATTEMPTS=60

wait_for_service() {
  host=$1
  port=$2
  label=$3
  attempt=1

  echo "Waiting for $label on $host:$port..."
  while [ "$attempt" -le "$MAX_WAIT_ATTEMPTS" ]; do
    if nc -z -w 1 "$host" "$port"; then
      echo "$label is up."
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 1
  done

  echo "$label did not become ready after $MAX_WAIT_ATTEMPTS attempts." >&2
  return 1
}

wait_for_service oauth2-mock 10001 "OAuth socketmap"
wait_for_service dovecot 24 "Dovecot LMTP"

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

# Debian 13's Postfix package does not create the chroot etc directory.
mkdir -p /var/spool/postfix/etc

# Copy DNS config into the chroot so smtpd can resolve hostnames
cp /etc/resolv.conf /var/spool/postfix/etc/resolv.conf
cp /etc/hosts /var/spool/postfix/etc/hosts
cp /etc/nsswitch.conf /var/spool/postfix/etc/nsswitch.conf
cp /etc/services /var/spool/postfix/etc/services

exec postfix start-fg
