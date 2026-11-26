#!/var/ossec/framework/python/bin/python3
import sys
import json
import requests

alert_file_path = sys.argv[1]

hook_url = None
for arg in sys.argv[1:]:
    if arg.startswith("http"):
        hook_url = arg
        break

if hook_url is None:
    sys.exit(1)

CHAT_ID = "<CHAT_ID>"

try:
    with open(alert_file_path) as f:
        alert = json.load(f)
except Exception:
    sys.exit(0)

rule = alert.get("rule", {})
agent = alert.get("agent", {})
data = alert.get("data", {})

level = rule.get("level", 0)
description = rule.get("description", "N/A")
rule_id = rule.get("id", "N/A")
agent_name = agent.get("name", "N/A")
src_ip = data.get("src_ip", data.get("srcip", "N/A"))
dest_ip = data.get("dest_ip", data.get("dstip", "N/A"))
timestamp = alert.get("timestamp", "N/A")

message = (
    f"🚨 *WENT SOC Alert*\n\n"
    f"*Level:* {level}\n"
    f"*Rule:* {rule_id} - {description}\n"
    f"*Agent:* {agent_name}\n"
    f"*Source IP:* {src_ip} → {dest_ip}\n"
    f"*Time:* {timestamp}"
)

payload = {
    "chat_id": CHAT_ID,
    "text": message,
    "parse_mode": "Markdown"
}

try:
    requests.post(hook_url, data=payload, timeout=10)
except Exception:
    pass

sys.exit(0)
