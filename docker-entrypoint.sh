#!/bin/sh
set -e

CONNECT="${CONNECT_ADDR:?CONNECT_ADDR is required}"

VLESS_FLAG=""
if [ "${VLESS_MODE}" = "true" ]; then
    VLESS_FLAG="-vless"
fi

BOND_FLAG=""
if [ "${VLESS_BOND}" = "true" ]; then
    BOND_FLAG="-vless-bond"
fi

exec ./vk-turn-proxy -listen 0.0.0.0:56000 -connect "$CONNECT" $VLESS_FLAG $BOND_FLAG
