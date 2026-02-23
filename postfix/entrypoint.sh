#!/bin/sh
set -e

echo "Waiting for Dovecot LMTP on dovecot:24..."
until nc -z dovecot 24; do
  sleep 1
done
echo "Dovecot LMTP is up."

exec postfix start-fg
