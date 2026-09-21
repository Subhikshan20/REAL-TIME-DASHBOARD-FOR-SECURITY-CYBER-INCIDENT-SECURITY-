#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Ubuntu victim VM (192.168.56.20) — install + configure Suricata IDS.
# Usage:  sudo bash lab/install_suricata_sensor.sh <HOME_NET_CIDR> <IFACE>
#   e.g.  sudo bash lab/install_suricata_sensor.sh 192.168.56.0/24 enp0s8
# Find your host-only interface with:  ip -4 -o addr show
# ---------------------------------------------------------------------------
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo."; exit 1; }

SUBNET="${1:-192.168.56.0/24}"
IFACE="${2:-enp0s8}"

echo "[*] Installing Suricata… (HOME_NET=${SUBNET}, interface=${IFACE})"
apt-get update -y
apt-get install -y suricata jq

echo "[*] Fetching the Emerging Threats OPEN ruleset (so the 4 attacks fire signatures)…"
suricata-update enable-source et/open || true
suricata-update || true

echo "[*] Setting HOME_NET and capture interface…"
# HOME_NET in the main config:
sed -i "s|^\(\s*HOME_NET:\).*|\1 \"[${SUBNET}]\"|" /etc/suricata/suricata.yaml || true
# Debian/Ubuntu service reads the interface from /etc/default/suricata:
if grep -q "^IFACE=" /etc/default/suricata 2>/dev/null; then
  sed -i "s/^IFACE=.*/IFACE=${IFACE}/" /etc/default/suricata
else
  echo "IFACE=${IFACE}" >> /etc/default/suricata
fi
# Also pin the af-packet interface in suricata.yaml (first occurrence):
sed -i "0,/^\(\s*-\s*interface:\).*/s//\1 ${IFACE}/" /etc/suricata/suricata.yaml || true

echo "[*] Restarting Suricata…"
systemctl enable suricata
systemctl restart suricata
sleep 4

echo "[*] Validating config…"
suricata -T -c /etc/suricata/suricata.yaml -v || echo "  (review the config test output above)"
echo
echo "[✓] Suricata up. eve.json tail:"
tail -n 2 /var/log/suricata/eve.json 2>/dev/null || echo "  (no events yet — generate traffic from Kali)"
echo
echo "Next: sudo bash lab/install_wazuh_agent.sh 192.168.56.10"
