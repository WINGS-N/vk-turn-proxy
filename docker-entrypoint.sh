#!/bin/sh
set -e

CONNECT="${CONNECT_ADDR:-}"
UDP_CONNECT="${UDP_CONNECT_ADDR:-}"
TCP_CONNECT="${TCP_CONNECT_ADDR:-}"

TRANSPORT_FLAGS=""
if [ "${VLESS_MODE}" = "true" ]; then
    TRANSPORT_FLAGS="$TRANSPORT_FLAGS -vless"
fi
if [ "${TCP_MODE}" = "true" ]; then
    TRANSPORT_FLAGS="$TRANSPORT_FLAGS -vless"
fi

if [ -n "$UDP_CONNECT" ] || [ -n "$TCP_CONNECT" ]; then
    [ -n "$UDP_CONNECT" ] && TRANSPORT_FLAGS="$TRANSPORT_FLAGS -udp-connect $UDP_CONNECT"
    [ -n "$TCP_CONNECT" ] && TRANSPORT_FLAGS="$TRANSPORT_FLAGS -tcp-connect $TCP_CONNECT"
else
    [ -n "$CONNECT" ] || {
        echo "CONNECT_ADDR is required when UDP_CONNECT_ADDR/TCP_CONNECT_ADDR are not set" >&2
        exit 1
    }
    TRANSPORT_FLAGS="$TRANSPORT_FLAGS -connect $CONNECT"
fi

exec ./vk-turn-proxy -listen 0.0.0.0:56000 $TRANSPORT_FLAGS
