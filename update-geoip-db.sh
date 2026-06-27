#!/bin/bash
# update-geoip-db.sh - Download the latest geoip-cn.db (China IP ranges)
# for overseas-dns-geoip-check. Runs monthly via systemd timer.
set -euo pipefail

GEOIP_DB="/etc/dnsdist/geoip-cn.db"
GEOIP_URL="https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip-cn.db"
GEOIP_TMP="${GEOIP_DB}.tmp.$$"

# Download
if ! wget -qO "${GEOIP_TMP}" "${GEOIP_URL}" 2>/dev/null; then
    echo "[!] Failed to download geoip-cn.db"
    rm -f "${GEOIP_TMP}"
    exit 1
fi

# Validate: check it's a non-empty file with at least some MMDB-like structure
size=$(stat -c%s "${GEOIP_TMP}" 2>/dev/null || stat -f%z "${GEOIP_TMP}" 2>/dev/null || echo 0)
if [[ "${size}" -lt 1000 ]]; then
    echo "[!] Downloaded geoip-cn.db is suspiciously small (${size} bytes), keeping existing"
    rm -f "${GEOIP_TMP}"
    exit 1
fi

OLD_SIZE=0
[[ -f "${GEOIP_DB}" ]] && OLD_SIZE=$(stat -c%s "${GEOIP_DB}" 2>/dev/null || echo 0)

mv "${GEOIP_TMP}" "${GEOIP_DB}"
echo "[+] geoip-cn.db updated ($(numfmt --to=iec ${OLD_SIZE}) → $(numfmt --to=iec ${size}))"

# Restart the proxy to reload the DB
if systemctl is-active --quiet overseas-dns-geoip-check 2>/dev/null; then
    systemctl restart overseas-dns-geoip-check 2>/dev/null || true
    echo "[+] overseas-dns-geoip-check restarted"
fi
