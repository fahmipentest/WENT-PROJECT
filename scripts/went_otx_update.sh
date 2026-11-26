#!/bin/bash
OTX_KEY="<OTX_API_KEY>"
OUT=/var/ossec/etc/lists/went-malicious-ip
TMP=$(mktemp)

curl -s -H "X-OTX-API-KEY: $OTX_KEY" \
  "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50" \
  -o /tmp/otx_pulses.json

jq -r '.results[].indicators[] | select(.type=="IPv4") | .indicator' /tmp/otx_pulses.json \
  | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' \
  | sed 's/$/:/' > "$TMP"

echo "10.10.10.30:" >> "$TMP"

sort -u "$TMP" > "$OUT"
chown wazuh:wazuh "$OUT"
rm -f "$TMP" /tmp/otx_pulses.json

echo "[$(date)] Update selesai. Total IP: $(wc -l < $OUT)"
