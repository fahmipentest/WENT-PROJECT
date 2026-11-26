# Arsitektur WENT-Enterprise

## Topologi

```
Laptop Windows (host, 10.10.56.1)
   │ Host-only 10.10.56.0/24
   ├── WENT-SIEM-01   10.10.10.10 / 10.10.56.10   Wazuh + Suricata
   ├── WENT-WEB-01    10.10.10.40 / 10.10.56.40   WAF (ModSecurity) + Juice Shop
   │
   │ Internal Network "went-internal-01" 10.10.10.0/24
   ├── WENT-ENDPOINT-01  10.10.10.20   Windows 11, Sysmon, Wazuh Agent
   └── WENT-ATTACKER-01  10.10.10.30   Kali Linux (tanpa host-only)
```

## Alokasi

| Host | Hostname | IP Internal | IP Host-only |
|---|---|---|---|
| SIEM | wazuhenterprise / WENT-SIEM-01 | 10.10.10.10 | 10.10.56.10 |
| Endpoint | DESKTOP-LABUSER / WENT-ENDPOINT-01 | 10.10.10.20 | 10.10.56.20 |
| Attacker | went-attacker-01 | 10.10.10.30 | - |
| Web | went-web-01 / WENT-WEB-01 | 10.10.10.40 | 10.10.56.40 |
| Laptop | - | - | 10.10.56.1 |

## Alur data (terbukti)

```
Kali nmap → Suricata (enp0s8, promiscuous) → eve.json
          → Wazuh localfile → rule 86601 → rule 110100 (CDB list OTX)
          → integrator → custom-telegram.py → Telegram
```

## Alur data web (rencana)

```
Client → WAF ModSecurity (10.10.10.40:80) → Juice Shop (port 3000, jaringan Docker internal)
```
