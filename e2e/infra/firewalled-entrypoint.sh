#!/bin/sh
# "Firewall host": HTTP on 8080; SYNs to 80 get TCP RST (nmap: 80 filtered, 8080 open)
set -e
apk add --no-cache iptables >/dev/null 2>&1 || true
python3 -m http.server 8080 &
if iptables -A INPUT -p tcp --dport 80 -j REJECT --reject-with tcp-reset 2>/dev/null; then
  :
else
  echo "firewalled-host: iptables rule skipped (kernel/cap); only :8080 is meaningful" >&2
fi
wait
