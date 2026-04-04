#!/bin/sh
set -e

CONNECT="${CONNECT_ADDR:?CONNECT_ADDR is required}"

TCP_FLAG=""
if [ "${TCP_MODE}" = "true" ]; then
    TCP_FLAG="-tcp"
fi

exec ./vk-turn-proxy -listen 0.0.0.0:56000 -connect "$CONNECT" $TCP_FLAG
