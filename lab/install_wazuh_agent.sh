#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Ubuntu victim VM (192.168.56.20) — install the Wazuh agent and forward BOTH
# the Suricata eve.json AND host logs (auth / FIM / commands) to the Manager,
# so network signatures arrive correlated with host telemetry.
# Usage:  sudo bash lab/install_wazuh_agent.sh <MANAGER_IP>
# ---------------------------------------------------------------------------
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo."; exit 1; }
MGR="${1:?usage: install_wazuh_agent.sh <manager-ip>}"
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "[*] Adding the Wazuh apt repository…"
apt-get install -y curl gnupg apt-transport-https
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
  gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  > /etc/apt/sources.list.d/wazuh.list
apt-get update -y

echo "[*] Installing the agent (registering to manager ${MGR})…"
WAZUH_MANAGER="$MGR" apt-get install -y wazuh-agent

echo "[*] Enabling host-side signals needed for correlation (sshd / auditd)…"
apt-get install -y openssh-server auditd
systemctl enable --now ssh auditd

echo "[*] Forwarding the Suricata eve.json to Wazuh…"
OSSEC="/var/ossec/etc/ossec.conf"
if ! grep -q "/var/log/suricata/eve.json" "$OSSEC"; then
  # insert our localfile block just before the closing </ossec_config>
  python3 - "$OSSEC" "$HERE/wazuh_agent_suricata_localfile.xml" <<'PY'
import sys
conf, snippet = sys.argv[1], sys.argv[2]
block = open(snippet).read().strip() + "\n"
text = open(conf).read()
text = text.replace("</ossec_config>", block + "</ossec_config>", 1)
open(conf, "w").write(text)
print("  added Suricata localfile block")
PY
else
  echo "  (already present)"
fi

echo "[*] Starting the agent…"
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl restart wazuh-agent
sleep 3
echo "[✓] Agent status:"; systemctl is-active wazuh-agent || true
echo "Confirm the agent shows 'Active' in the Wazuh dashboard (Agents)."
