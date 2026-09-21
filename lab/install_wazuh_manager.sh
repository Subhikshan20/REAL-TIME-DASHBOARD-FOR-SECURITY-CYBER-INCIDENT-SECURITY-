#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Wazuh Manager VM (Ubuntu Server 22.04, 192.168.56.10)
# Installs the all-in-one Wazuh stack: Manager + Indexer + Dashboard.
# Run as root:  sudo bash lab/install_wazuh_manager.sh
# ---------------------------------------------------------------------------
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo."; exit 1; }

WAZUH_VERSION="${WAZUH_VERSION:-4.9}"   # check packages.wazuh.com for the latest stable

cd /root
echo "[*] Downloading the Wazuh installation assistant (v${WAZUH_VERSION})…"
curl -sO "https://packages.wazuh.com/${WAZUH_VERSION}/wazuh-install.sh"

echo "[*] Installing all-in-one (Manager + Indexer + Dashboard)…"
bash ./wazuh-install.sh -a -i

echo
echo "[✓] Wazuh installed. Credentials (SAVE THESE):"
tar -O -xf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt 2>/dev/null \
  | grep -E "username|password" || \
  echo "    (extract later: sudo tar -O -xf /root/wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt)"
echo
echo "Dashboard:  https://192.168.56.10   (user: admin)"
echo "API  :55000   Indexer :9200"
