#!/usr/bin/env bash

FOLDER=$1

if [ -z "$FOLDER" ]; then
    echo "Missing folder argument"
    exit 100
fi

docker exec -it dovecot-dev doveadm mailbox create -u dev@local.test "$FOLDER"
