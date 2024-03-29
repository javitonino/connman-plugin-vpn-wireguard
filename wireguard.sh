#!/bin/sh
set -eu

if [ -z $WG_PEER_PERSISTENT_KEEPALIVE ]
then
    WG_PEER_PERSISTENT_KEEPALIVE=0
fi

wireguard $WG_TUN
trap "rm -f /var/run/wireguard/$WG_TUN.sock; sleep 0.5; exit" SIGTERM SIGINT

PATH=/usr/sbin:/sbin:$PATH ip addr add $WG_INTERFACE_ADDRESS dev $WG_TUN
KEYFILE=$(mktemp)
echo $WG_INTERFACE_PRIVATE_KEY > $KEYFILE
wg set $WG_TUN private-key $KEYFILE peer $WG_PEER_PUBLIC_KEY endpoint $WG_PEER_ENDPOINT allowed-ips "$WG_PEER_ALLOWED_IPS" persistent-keepalive $WG_PEER_PERSISTENT_KEEPALIVE
rm $KEYFILE

if [ "${WG_PEER_PRESHARED_KEY:-}" ]
then
    PSKFILE=$(mktemp)
    echo $WG_PEER_PRESHARED_KEY > $PSKFILE
    wg set $WG_TUN peer $WG_PEER_PUBLIC_KEY preshared-key $PSKFILE
    rm $PSKFILE
fi

dbus-send --system --dest=$CONNMAN_BUSNAME --type=method_call $CONNMAN_PATH $CONNMAN_INTERFACE.notify string:up

sleep infinity &
wait $!
