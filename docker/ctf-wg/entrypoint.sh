#!/bin/sh
set -eu

CONF="/run/wg/wg0.conf"
DNS_FILE="/run/wg/dns"
READY_FILE="/run/wg/ready"
ORIG_RESOLV="/run/wg/resolv.orig"

if [ ! -f "$CONF" ]; then
  echo "missing $CONF" >&2
  exit 1
fi

rm -f "$READY_FILE"
chmod 600 "$CONF"

if [ -f /etc/resolv.conf ] && [ ! -f "$ORIG_RESOLV" ]; then
  cp /etc/resolv.conf "$ORIG_RESOLV"
fi

# Start WireGuard first so Endpoint hostnames resolve via the container's initial DNS.
wg-quick up "$CONF"

# Rewrite Docker's bind-mounted /etc/resolv.conf in-place (atomic truncate, never mv).
if [ -s "$DNS_FILE" ]; then
  dns_count=$(grep -cE '[^[:space:]]' "$DNS_FILE" || true)
  {
    while IFS= read -r ns; do
      [ -n "$ns" ] && printf 'nameserver %s\n' "$ns"
    done < "$DNS_FILE"
    if [ "$dns_count" -lt 2 ] && [ -f "$ORIG_RESOLV" ]; then
      grep -E '^(nameserver|search|options) ' "$ORIG_RESOLV" || true
    fi
  } > /etc/resolv.conf
fi

touch "$READY_FILE"

cleanup() {
  rm -f "$READY_FILE"
  if [ -f "$ORIG_RESOLV" ]; then
    cat "$ORIG_RESOLV" > /etc/resolv.conf 2>/dev/null || true
  fi
  wg-quick down "$CONF" 2>/dev/null || true
  exit 0
}

trap cleanup TERM INT

while true; do
  sleep 60 &
  wait $! || true
done
