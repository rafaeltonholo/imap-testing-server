#!/usr/bin/env bash

for f in mails/*.eml; do
  docker cp "$f" dovecot-dev:/tmp/
  base=$(basename "$f")
  docker exec dovecot-dev doveadm save -u dev@local.test -m INBOX "/tmp/$base"
done
