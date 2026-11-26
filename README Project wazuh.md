# WENT-Enterprise: Home Lab SOC dengan Wazuh

> Home lab SOC berbasis VirtualBox yang membangun alur kerja SOC secara bertahap:
> **deteksi jaringan (Suricata) → SIEM (Wazuh) → threat intelligence (AlienVault OTX) → notifikasi (Telegram) → simulasi serangan web (Juice Shop + ModSecurity WAF)**.

Dokumen ini adalah **writeup lengkap**: konsep, arsitektur, langkah instalasi, integrasi, troubleshooting nyata yang dialami, dan cara membaca log. Tujuannya agar bisa diulang dari nol, dan dipakai sebagai bahan portofolio SOC Analyst L1.

> **Catatan keamanan:** semua token, API key, password, dan chat ID dalam dokumen ini sudah diganti placeholder. Jangan pernah commit nilai asli ke GitHub. Lihat bagian [Keamanan](#11-keamanan-dan-kebersihan-kredensial).

---

## Daftar Isi

1. [Tujuan Project](#1-tujuan-project)
2. [Konsep Dasar SOC](#2-konsep-dasar-soc)
3. [Arsitektur dan Alur Data](#3-arsitektur-dan-alur-data)
4. [Alokasi Jaringan, Host, dan VM](#4-alokasi-jaringan-host-dan-vm)
5. [Keputusan Desain](#5-keputusan-desain)
6. [Tahap 0: Persiapan VirtualBox](#6-tahap-0-persiapan-virtualbox)
7. [Tahap 1: WENT-SIEM-01 (Wazuh + Suricata)](#7-tahap-1-went-siem-01-wazuh--suricata)
8. [Tahap 2: WENT-ENDPOINT-01 (Windows 11 + Sysmon + Wazuh Agent)](#8-tahap-2-went-endpoint-01-windows-11--sysmon--wazuh-agent)
9. [Tahap 3: WENT-ATTACKER-01 (Kali Linux)](#9-tahap-3-went-attacker-01-kali-linux)
10. [Tahap 4: Integrasi](#10-tahap-4-integrasi)
11. [Keamanan dan Kebersihan Kredensial](#11-keamanan-dan-kebersihan-kredensial)
12. [Tahap 5: WENT-WEB-01 (Juice Shop + ModSecurity WAF)](#12-tahap-5-went-web-01-juice-shop--modsecurity-waf)
13. [Cara Membaca Log (Konseptual)](#13-cara-membaca-log-konseptual)
14. [Log Troubleshooting: Masalah Nyata dan Solusinya](#14-log-troubleshooting-masalah-nyata-dan-solusinya)
15. [Status Saat Ini dan Roadmap](#15-status-saat-ini-dan-roadmap)
16. [Lampiran: Konfigurasi Lengkap](#16-lampiran-konfigurasi-lengkap)

---

## 1. Tujuan Project

Tujuan project ini bukan sekadar memasang tool, melainkan **memahami bagaimana SOC bekerja dari balik layar**:

- Mengetahui infrastruktur yang dibutuhkan SOC (SIEM, IDS, endpoint, threat intel, notifikasi, otomasi).
- Membaca **log mentah** dari firewall/IDS, WAF, web server, dan endpoint Windows.
- Mengenali pola serangan (port scan, brute force, web attack) dari log.
- Melakukan **triase**: membedakan alert benar (true positive) dan false positive.
- Menjelaskan alur investigasi dan respons ketika insiden terjadi.

Semua pengujian dilakukan di **lingkungan lab terisolasi milik sendiri**, dengan VM yang dibuat sendiri.

---

## 2. Konsep Dasar SOC

### 2.1 Apa itu SOC?

**Security Operations Center (SOC)** adalah tim dan infrastruktur yang memantau, mendeteksi, menginvestigasi, dan merespons ancaman keamanan secara berkelanjutan.

### 2.2 Siklus kerja SOC

| Tahap | Pertanyaan utama | Contoh di lab ini |
|---|---|---|
| **Prevention** | Bagaimana mencegah serangan masuk? | Firewall OS (UFW), hardening Windows, WAF |
| **Detection** | Apakah ada aktivitas mencurigakan? | Suricata mendeteksi port scan |
| **Monitoring** | Bagaimana melihat aktivitas secara terus-menerus? | Wazuh Manager, Dashboard custom |
| **Investigation** | Apa yang sebenarnya terjadi? | Membaca `eve.json`, `alerts.json`, event Windows |
| **Response** | Apa tindakan yang diambil? | Notifikasi Telegram, rencana blokir IP |
| **Automation** | Bagaimana mempercepat respons? | Script integrasi Wazuh → AI → Telegram |
| **Threat Intelligence** | Apakah IP/domain ini sudah diketahui berbahaya? | CDB list dari AlienVault OTX |

### 2.3 Istilah penting

| Istilah | Arti singkat |
|---|---|
| **SIEM** | Mengumpulkan dan menganalisis log dari banyak sumber (Wazuh) |
| **IDS** | Mendeteksi trafik jaringan mencurigakan, mode pasif (Suricata) |
| **IPS** | Seperti IDS tapi bisa memblokir trafik (tidak dipakai di lab ini) |
| **WAF** | Firewall aplikasi web yang memfilter HTTP (ModSecurity) |
| **EDR / Endpoint security** | Proteksi dan monitoring di perangkat akhir (Defender, Sysmon) |
| **IOC** | *Indicator of Compromise*: IP, domain, hash yang terkait serangan |
| **CDB list** | Daftar lookup di Wazuh untuk mencocokkan IOC |
| **Rule** | Aturan Wazuh/Suricata yang memicu alert jika pola cocok |
| **Alert level** | Tingkat keparahan alert di Wazuh (0-15) |
| **False positive** | Alert yang terpicu tapi aktivitasnya sebenarnya normal |
| **True positive** | Alert yang terpicu dan aktivitasnya memang berbahaya |
| **SOAR** | Security Orchestration, Automation, and Response |

### 2.4 Mengapa membaca log itu penting

Dashboard hanya menampilkan **hasil yang sudah diproses**. Analis SOC harus bisa kembali ke **log mentah** untuk:
- memverifikasi apakah alert benar,
- menemukan detail yang tidak tampil di dashboard,
- menjelaskan kejadian kepada orang lain secara akurat.

---

## 3. Arsitektur dan Alur Data

### 3.1 Diagram topologi

```
                    Laptop Windows (host)
                    ├── VirtualBox
                    ├── Browser (akses dashboard & Juice Shop)
                    └── Host-only 10.10.56.1
                             │
          ┌──────────────────┼────────────────────────┐
          │ Host-only 10.10.56.0/24                   │
          │                                           │
   WENT-SIEM-01        WENT-WEB-01            (tidak terhubung
   Ubuntu 24.04        Ubuntu 24.04            ke host-only)
   10.10.56.10         10.10.56.40             WENT-ATTACKER-01
          │                  │                 Kali Linux
          └──────────────────┼─────────────────────┘
                             │
        Internal Network "went-internal-01" 10.10.10.0/24
   ┌───────────┬─────────────┬──────────────┬─────────────────┐
   │ SIEM      │ ENDPOINT    │ WEB          │ ATTACKER        │
   │ .10       │ .20         │ .40          │ .30             │
   │ Wazuh     │ Windows 11  │ WAF+Juice    │ Kali            │
   │ Suricata  │ Sysmon      │ Shop         │ nmap, hydra     │
   └───────────┴─────────────┴──────────────┴─────────────────┘
```

### 3.2 Mengapa Kali ditaruh di jaringan yang sama dengan target?

Suricata hanya bisa melihat trafik yang **melewati interface yang di-sniff**. Dengan menaruh Kali, Windows, dan SIEM di satu Internal Network dan mengaktifkan **Promiscuous Mode: Allow All** pada adapter SIEM, Suricata bisa melihat trafik antar-VM. Ini sudah **terbukti** saat scan Nmap dari Kali terdeteksi di `fast.log`.

### 3.3 Alur data (end-to-end yang sudah terbukti)

```
Kali (nmap scan)
   │  paket SYN ke 10.10.10.20
   ▼
Suricata di WENT-SIEM-01 (interface enp0s8, promiscuous)
   │  alert "WENT SCAN Possible TCP SYN Port Scan" (sid 9000001)
   ▼  /var/log/suricata/eve.json
Wazuh Manager (localfile json)
   │  rule 86601 (alert Suricata bawaan, level 3)
   │  rule 110100 (TI match via CDB list, level 10)  ← naik karena IP ada di daftar OTX
   ▼  /var/ossec/logs/alerts/alerts.json
Integrator Wazuh → custom-telegram.py
   ▼
Telegram Bot → notifikasi ke ponsel
```

### 3.4 Alur data untuk web attack (akan dibangun)

```
Browser/Kali → WAF (ModSecurity, WENT-WEB-01 :80)
                  │  audit log: payload dan rule yang cocok
                  ▼
              Juice Shop (container, port 3000, internal)
                  │  access log / respons
                  ▼
   (rencana) log dibaca Wazuh agent → SIEM → dashboard & Telegram
```

---

## 4. Alokasi Jaringan, Host, dan VM

### 4.1 Network di VirtualBox

| Nama / Tipe | Subnet | Fungsi |
|---|---|---|
| `went-internal-01` (Internal Network) | `10.10.10.0/24` | Jalur serangan dan telemetri antar-VM. Suricata sniffing di sini |
| Host-only Adapter (`VirtualBox Host-Only Ethernet Adapter #N`) | `10.10.56.0/24` | Jalur admin dari laptop ke VM (SSH, dashboard, Juice Shop) |
| NAT | `10.0.2.0/24` | Akses internet untuk instalasi paket |

> Catatan: nama adapter host-only di Windows tidak bisa diubah dari Network Manager VirtualBox. Itu normal, yang penting IP-nya `10.10.56.1`.

### 4.2 Alokasi IP

| Host | Hostname | IP Internal (`10.10.10.x`) | IP Host-only (`10.10.56.x`) |
|---|---|---|---|
| Wazuh + Suricata | `wazuhenterprise` / WENT-SIEM-01 | `10.10.10.10` | `10.10.56.10` |
| Windows 11 endpoint | `DESKTOP-LABUSER` / WENT-ENDPOINT-01 | `10.10.10.20` | `10.10.56.20` |
| Kali attacker | `went-attacker-01` | `10.10.10.30` | (tidak ada, sengaja) |
| Web target (WAF + Juice Shop) | `went-web-01` / WENT-WEB-01 | `10.10.10.40` | `10.10.56.40` |
| Laptop host | — | — | `10.10.56.1` |

**Kenapa Kali tidak punya host-only?** Supaya "penyerang" simulasi tidak bisa menjangkau laptop, sehingga batas lab dan komputer asli tetap jelas.

### 4.3 VM dan resource

| VM | OS | CPU | RAM | Disk | Adapter |
|---|---|---|---|---|---|
| WENT-SIEM-01 | Ubuntu Server 24.04 | 4 | 8 GB | 80 GB | NAT, Internal (promiscuous), Host-only |
| WENT-ENDPOINT-01 | Windows 11 | 2 | 4 GB | 60 GB | NAT, Internal, Host-only |
| WENT-ATTACKER-01 | Kali Linux | 2 | 2 GB | 40 GB | NAT, Internal |
| WENT-WEB-01 | Ubuntu Server 24.04 | 2 | 2 GB | 20 GB | NAT, Internal, Host-only |

Total RAM VM sekitar 16 GB. Laptop 24 GB, jadi host tetap perlu menyisakan ruang untuk Windows dan VirtualBox.

---

## 5. Keputusan Desain

Dokumen awal menyebut banyak komponen. Berikut keputusan yang diambil untuk menyesuaikan dengan laptop (24 GB RAM) dan tujuan belajar:

| Rencana awal | Keputusan | Alasan |
|---|---|---|
| OPNsense (firewall VM) | Diganti **UFW** di Ubuntu dan **Windows Defender Firewall** | Hemat satu VM; fokus ke deteksi, bukan arsitektur firewall |
| Suricata IPS | Mode **IDS** (pasif) | Mode IPS (netmap) sering bermasalah di VirtualBox dan butuh posisi inline |
| MISP | Diganti **AlienVault OTX** (feed gratis) | MISP terlalu berat untuk lab |
| TheHive + Cortex | Ditunda, opsional | Sekarang butuh lisensi StrangeBee untuk versi 5 |
| Shuffle (SOAR visual) | **Dibatalkan** | Terlalu berat (4+ container, ~4 GB RAM) |
| n8n (SOAR visual ringan) | **Dibatalkan** | Diputuskan tidak dipakai setelah evaluasi resource |
| Ollama (AI lokal) | **Dibatalkan** | Berjalan CPU-only (GPU RTX 4060 tidak terpakai, lihat troubleshooting), lambat, dan tambah kompleksitas |
| SOAR | **Script Python sederhana** (`custom-telegram.py`) | Cukup untuk membuktikan konsep orkestrasi Wazuh → Telegram |
| Dashboard Wazuh | Explore → Dashboards (6 visualisasi) | Sudah memadai |

---

## 6. Tahap 0: Persiapan VirtualBox

**Dijalankan di:** VirtualBox Manager (laptop Windows).

1. **Buat Host-only Network:**
   - `File → Tools → Network Manager → Host-only Networks → Create`
   - Set IPv4 `10.10.56.1`, mask `255.255.255.0`, **DHCP dimatikan**.
2. **Internal Network `went-internal-01`** terbentuk otomatis saat VM pertama dipasangi nama tersebut di adapter.
3. **Snapshot** setelah setiap tahap selesai, supaya bisa kembali ke titik aman.
4. **Promiscuous Mode** pada adapter Internal VM1 (WENT-SIEM-01): `Settings → Network → Adapter 2 → Advanced → Promiscuous Mode: Allow All`. VM harus dalam keadaan mati saat mengubahnya.

---

## 7. Tahap 1: WENT-SIEM-01 (Wazuh + Suricata)

### 7.1 Buat VM

- Ubuntu Server 24.04, hostname `went-siem-01` (tampil sebagai `wazuhenterprise` di prompt).
- Install OpenSSH server saat instalasi.
- Adapter: NAT, Internal `went-internal-01` (Promiscuous Allow All), Host-only.

### 7.2 Konfigurasi dasar

**Dijalankan di:** SSH ke WENT-SIEM-01

```bash
sudo apt update && sudo apt upgrade -y
sudo timedatectl set-timezone Asia/Jakarta
ip -br addr
```

Set IP statis lewat netplan (`/etc/netplan/50-cloud-init.yaml`):

```yaml
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: true
    enp0s8:
      addresses: [10.10.10.10/24]
    enp0s9:
      addresses: [10.10.56.10/24]
```

```bash
sudo netplan apply
ip -br addr
```

> **Penting:** nama interface (`enp0s3`, `enp0s8`, `enp0s9`) bisa berbeda. Selalu cek dengan `ip -br addr` sebelum menulis netplan.

**SSH dari laptop** (PowerShell laptop):

```powershell
ssh soc-admin@10.10.56.10
```

Jika gagal, periksa: UFW (`sudo ufw allow from 10.10.56.0/24 to any port 22 proto tcp`), service SSH (`sudo systemctl status ssh`), dan adapter host-only di VM.

### 7.3 Install Wazuh (all-in-one)

**Dijalankan di:** SSH WENT-SIEM-01

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash wazuh-install.sh -a
```

- Versi `4.14` dipilih setelah dicek ke dokumentasi; `4.9` yang disebut awalnya sudah usang.
- Simpan **password admin** yang ditampilkan di akhir instalasi. Password tidak ditampilkan lagi.

Verifikasi:

```bash
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard
```

Akses dashboard dari browser laptop: `https://10.10.56.10` (login `admin`).

Firewall OS:

```bash
sudo ufw allow from 10.10.10.0/24 to any port 1514,1515,55000 proto tcp
sudo ufw allow from 10.10.56.0/24 to any port 443 proto tcp
sudo ufw reload
```

### 7.4 Install Suricata

**Dijalankan di:** SSH WENT-SIEM-01

```bash
sudo apt install -y suricata jq
suricata --build-info | grep -i af-packet     # harus ada: AF_PACKET support: yes
```

Edit `/etc/suricata/suricata.yaml`:

```yaml
HOME_NET: "[10.10.10.0/24]"

af-packet:
  - interface: enp0s8
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
```

Update ruleset dan validasi:

```bash
sudo apt install -y suricata-update
sudo suricata-update
sudo suricata -T -c /etc/suricata/suricata.yaml -v
sudo systemctl enable --now suricata
sudo systemctl status suricata
```

Verifikasi bahwa engine benar-benar jalan:

```bash
sudo grep -E "rule files processed|Engine started" /var/log/suricata/suricata.log | tail -n 4
```

Hasil yang diharapkan: `53432 rules` (atau lebih) dan `Engine started`.

### 7.5 Verifikasi Suricata menangkap trafik

Tes ini harus dilakukan dari jaringan internal, **bukan** dari internet (karena `enp0s8` tidak punya rute ke internet):

```bash
ping -c 5 10.10.10.99                     # IP kosong, paket ARP tetap keluar
sudo tcpdump -i enp0s8 -c 10              # harus menangkap ARP request
```

> **Pelajaran:** `curl testmyids.com` dari VM1 tidak memicu alert, karena trafiknya keluar lewat NAT (`enp0s3`), bukan lewat `enp0s8`. Ini konsekuensi desain, bukan bug.

Verifikasi `decoder.pkts` naik di stats Suricata:

```bash
sudo tail -n 3 /var/log/suricata/eve.json | jq 'select(.event_type=="stats") | .stats.decoder.pkts'
```

### 7.6 Hubungkan Suricata ke Wazuh

**Dijalankan di:** SSH WENT-SIEM-01, file `/var/ossec/etc/ossec.conf`, di dalam `<ossec_config>`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```

```bash
sudo systemctl restart wazuh-manager
sudo grep -i "eve.json" /var/ossec/logs/ossec.log | tail -n 3
```

Hasil yang diharapkan: baris `Analyzing file: '/var/log/suricata/eve.json'`.

---

## 8. Tahap 2: WENT-ENDPOINT-01 (Windows 11 + Sysmon + Wazuh Agent)

### 8.1 Buat VM dan atur IP

- Windows 11, hostname `WENT-ENDPOINT-01` (akhirnya tampil sebagai `DESKTOP-LABUSER`, tidak masalah; nama agent tetap `WENT-ENDPOINT-01`).
- User lokal `labuser` (hindari akun Microsoft untuk lab).
- Adapter: NAT, Internal `went-internal-01`, Host-only.

Cek nama adapter:

```powershell
Get-NetAdapter
```

Pada lab ini, adapter diatur lewat `ncpa.cpl → Properties → IPv4`:

| Adapter Windows | IP | Jaringan |
|---|---|---|
| Ethernet | `10.0.2.15` (DHCP) | NAT |
| Ethernet 2 | `10.10.10.20` | Internal |
| Ethernet 3 | `10.10.56.20` | Host-only |

Verifikasi konektivitas:

```powershell
ping 10.10.10.10
ping 10.10.56.10
```

Kedua ping harus berbalas. Default Gateway hanya boleh di adapter NAT.

### 8.2 Audit dan logging

**Dijalankan di:** PowerShell **Administrator** di Windows

```powershell
# Audit logon supaya event 4625 (login gagal) tercatat
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

# PowerShell Script Block Logging
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1
```

### 8.3 Sysmon

**Dijalankan di:** PowerShell Administrator, Windows

```powershell
New-Item -ItemType Directory -Path C:\Tools -Force
cd C:\Tools
Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile Sysmon.zip
Expand-Archive Sysmon.zip -DestinationPath . -Force
Invoke-WebRequest -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile sysmonconfig-export.xml
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
Get-Service Sysmon64
```

Status harus `Running`.

### 8.4 Wazuh Agent

**Cara yang aman:** ambil perintah instalasi langsung dari dashboard Wazuh, supaya versinya cocok dengan manager.

1. Dashboard → **Agents → Deploy new agent**.
2. Package: Windows (MSI). **Server address: `10.10.10.10`** (alamat manager, bukan IP Windows).
3. Agent name: `WENT-ENDPOINT-01`.
4. Jalankan perintah yang ditampilkan di PowerShell Administrator, lalu:

```powershell
NET START WazuhSvc
```

Tambahkan pembacaan channel log di `C:\Program Files (x86)\ossec-agent\ossec.conf`, sebelum `</ossec_config>`:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
<localfile>
  <location>Microsoft-Windows-Windows Defender/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

```powershell
Restart-Service WazuhSvc
```

Verifikasi dari SIEM:

```bash
sudo /var/ossec/bin/agent_control -l     # status harus Active
```

> Di dashboard, status agent bisa tertahan `Pending` beberapa saat. Itu soal sinkronisasi tampilan. Patokannya adalah `agent_control -l`.

### 8.5 Firewall Windows untuk ICMP lab

Windows memblokir ping masuk secara default. Untuk lab, izinkan ICMP dari subnet internal:

```powershell
New-NetFirewallRule -DisplayName "WENT Lab ICMP" -Protocol ICMPv4 -IcmpType 8 -RemoteAddress 10.10.10.0/24 -Action Allow
```

---

## 9. Tahap 3: WENT-ATTACKER-01 (Kali Linux)

### 9.1 Buat VM

- Adapter 1: NAT. Adapter 2: Internal `went-internal-01`. **Tanpa Adapter 3.**

### 9.2 Atur IP statis

**Dijalankan di:** terminal Kali

```bash
sudo hostnamectl set-hostname went-attacker-01
ip -br addr
nmcli con show
```

> Pada project ini terjadi kesalahan: profil NetworkManager lama (`soc-attack`) masih aktif di `eth0` dengan IP `10.10.10.10`, sehingga bentrok dengan SIEM. Solusinya: hapus profil lama dan pastikan hanya `eth1` yang punya `10.10.10.30/24`.

```bash
# Hapus profil lama yang bentrok (sesuaikan UUID dari `nmcli con show`)
sudo nmcli con delete <UUID_PROFIL_LAMA>

# Profil Internal (eth1)
sudo nmcli con add type ethernet ifname eth1 con-name went-internal ipv4.method manual ipv4.addresses 10.10.10.30/24
sudo nmcli con up went-internal

# Profil NAT (eth0) kembali ke DHCP
sudo nmcli con add type ethernet ifname eth0 con-name went-nat ipv4.method auto
sudo nmcli con up went-nat

ip -br addr
```

Tes konektivitas:

```bash
ping -c 3 10.10.10.10
ping -c 3 10.10.10.20
```

Nilai ping normal ke VM lain sekitar 0,2 sampai 1 ms. Nilai 0,03 ms berarti IP bentrok dengan mesin sendiri.

### 9.3 Tool

```bash
nmap --version
hydra -h | head -n 2
```

Biasanya sudah tersedia di Kali.

---

## 10. Tahap 4: Integrasi

### 10.1 Rule custom Suricata (deteksi port scan)

**Dijalankan di:** SSH WENT-SIEM-01

```bash
sudo nano /var/lib/suricata/rules/local.rules
```

Isi:

```
alert tcp any any -> $HOME_NET any (msg:"WENT SCAN Possible TCP SYN Port Scan"; flags:S; threshold: type both, track by_src, count 15, seconds 10; classtype:attempted-recon; sid:9000001; rev:1;)
```

Daftarkan di `/etc/suricata/suricata.yaml` pada bagian `rule-files:`:

```yaml
rule-files:
  - suricata.rules
  - local.rules
```

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
sudo systemctl restart suricata
```

**Tunggu sampai `Engine started` muncul** (sekitar 2 menit) sebelum melakukan scan. Scan yang dijalankan saat engine belum siap tidak akan terdeteksi.

Uji dari Kali:

```bash
nmap -sS -T4 -p 1-200 10.10.10.20
```

Di SIEM:

```bash
sudo tail -n 10 /var/log/suricata/fast.log
```

Output yang diharapkan:

```
11/18/2026-01:33:18 [**] [1:9000001:1] WENT SCAN Possible TCP SYN Port Scan [**] ... {TCP} 10.10.10.30:36084 -> 10.10.10.20:199
```

### 10.2 Alert Suricata masuk ke Wazuh

Di dashboard: **Explore → Discover**, index `wazuh-alerts-*`, query:

```
rule.groups: suricata
```

Alert bawaan Wazuh untuk Suricata memakai **rule ID 86601** dengan **level 3**. Field IP sumber yang benar adalah **`data.src_ip`** (dilihat di dashboard), sedangkan di dalam rule XML dan `wazuh-logtest` nama fieldnya **`src_ip`** (tanpa `data.`). Perbedaan ini penting, lihat bagian troubleshooting.

### 10.3 Threat intelligence: CDB list + rule

**Langkah A. Buat daftar IP** (`/var/ossec/etc/lists/went-malicious-ip`):

```bash
echo "10.10.10.30:" | sudo tee /var/ossec/etc/lists/went-malicious-ip
sudo chown wazuh:wazuh /var/ossec/etc/lists/went-malicious-ip
sudo chmod 660 /var/ossec/etc/lists/went-malicious-ip
```

Format CDB list Wazuh: setiap baris `indikator:` (dengan titik dua di akhir).

**Langkah B. Daftarkan list di `ossec.conf`**, di dalam blok `<ruleset>`:

```xml
<list>etc/lists/went-malicious-ip</list>
```

**Langkah C. Tambahkan rule** di `/var/ossec/etc/rules/local_rules.xml` (tambahkan di bagian bawah, jangan menimpa rule contoh):

```xml
<group name="local,went,threat_intel,">
  <rule id="110100" level="10">
    <if_sid>86601</if_sid>
    <list field="src_ip" lookup="address_match_key">etc/lists/went-malicious-ip</list>
    <description>WENT TI: Suricata alert dari IP malicious ($(src_ip))</description>
    <mitre>
      <id>T1595</id>
    </mitre>
  </rule>
</group>
```

**Langkah D. Validasi dan restart:**

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
ls -l /var/ossec/etc/lists/ | grep went     # harus ada went-malicious-ip.cdb
```

**Langkah E. Uji dengan `wazuh-logtest`** (tanpa perlu scan ulang):

```bash
sudo grep -a '"signature_id":9000001' /var/log/suricata/eve.json | tail -n 1
sudo /var/ossec/bin/wazuh-logtest
```

Tempel satu baris JSON tersebut. Di **Phase 3** harus muncul `id: '110100'`, `level: '10'`.

Hasil terbukti: alert naik dari level 3 (rule 86601) menjadi level 10 (rule 110100) dengan mapping MITRE T1595.

**Langkah F. Ganti daftar manual dengan feed OTX otomatis.**

Ada catatan penting: endpoint `/api/v1/indicators/export` yang sempat disarankan **tidak terverifikasi** di dokumentasi OTX. Pendekatan yang terbukti: **subscribe ke pulses**, lalu tarik IPv4 dari indikator pulse tersebut.

1. Login ke `otx.alienvault.com`, cari pulse (misal: phishing, malware, RAT), klik **Subscribe** (3-5 pulse).
2. Tes API:

```bash
curl -s -H "X-OTX-API-KEY: <OTX_API_KEY>" \
  "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=5" | jq '.results[].name'
```

3. Script `/usr/local/bin/went_otx_update.sh` (lihat [Lampiran A](#a-went_otx_updatesh)).

Hasil uji: 50 pulse, 44 indikator IPv4, 42 IP unik setelah deduplikasi.

4. Jadwalkan cron:

```bash
sudo crontab -e
```

```
0 */6 * * * /usr/local/bin/went_otx_update.sh >> /var/log/went_otx_update.log 2>&1
```

> **Catatan:** pulse seputar phishing/malware umumnya lebih banyak berisi domain dan file hash daripada IP. Jika ingin IP lebih banyak, subscribe pulse yang bertema "scanner", "botnet", atau "C2".

### 10.4 Dashboard custom

**Dijalankan di:** browser → `https://10.10.56.10` → **Explore → Dashboards**

**Bersihkan sample data dulu** (Dev Tools di Indexer Management):

```
DELETE wazuh-alerts-4.x-sample-*
```

Verifikasi:

```
GET wazuh-alerts-4.x-sample-*/_count     → harus error index_not_found_exception
GET wazuh-alerts-4.x-2026.11.19/_count   → harus menampilkan jumlah event asli
```

**Buat visualisasi** (Explore → Visualize → Create new visualization), index `wazuh-alerts-*`:

| Nama visualisasi | Tipe | Konfigurasi |
|---|---|---|
| WENT - Top Source IP | Pie | Terms pada `data.src_ip`, size 10 |
| WENT - Alert Timeline by Level | Vertical bar | Date histogram `timestamp`, split series `rule.level` |
| WENT - Top Rules Triggered | Data table | Terms `rule.description`, size 10 |
| WENT - Alert Source Type (Network vs Endpoint) | Pie | Terms `rule.groups`, size 10 |
| WENT - Total Alerts | Metric | Count |
| WENT - Events by Agent | Data table | Terms `agent.name` |

Gabungkan ke dashboard **WENT-SOC-Overview**, atur time range **Last 24 hours**, lalu **Save** dengan opsi **Store time with dashboard**.

Hasil: keenam panel menampilkan data nyata dari Suricata dan endpoint Windows.

### 10.5 Notifikasi Telegram

**Langkah A. Buat bot**

1. Telegram → `@BotFather` → `/newbot` → catat **token**.
2. Buka bot Anda di Telegram, tekan **Start** atau kirim pesan apa saja.
3. Ambil chat ID (di SIEM):

```bash
TOKEN="<TELEGRAM_BOT_TOKEN>"
curl -s "https://api.telegram.org/bot${TOKEN}/getMe"
curl -s "https://api.telegram.org/bot${TOKEN}/getUpdates" | jq '.result[0].message.chat.id'
```

Jika hasil `getUpdates` kosong (`"result": []`), berarti bot belum menerima pesan. Kirim pesan ke bot dulu.

4. Tes kirim:

```bash
CHAT_ID="<CHAT_ID>"
curl -s -X POST "https://api.telegram.org/bot${TOKEN}/sendMessage" \
  -d chat_id="${CHAT_ID}" -d text="Tes dari WENT-SIEM-01"
```

**Langkah B. Script integrasi.** Wazuh sudah memiliki Python sendiri di `/var/ossec/framework/python/`. `requests` sudah tersedia di sana, jadi tidak perlu install apa pun. Lihat [Lampiran B](#b-custom-telegrampy) untuk isi script, dan [Lampiran C](#c-custom-telegram-wrapper) untuk wrapper shell.

```bash
sudo chown root:wazuh /var/ossec/integrations/custom-telegram
sudo chown root:wazuh /var/ossec/integrations/custom-telegram.py
sudo chmod 750 /var/ossec/integrations/custom-telegram
sudo chmod 750 /var/ossec/integrations/custom-telegram.py
```

**Langkah C. Daftarkan di `ossec.conf`**, sebelum `</ossec_config>`:

```xml
<integration>
  <name>custom-telegram</name>
  <hook_url>https://api.telegram.org/bot<TELEGRAM_BOT_TOKEN>/sendMessage</hook_url>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
```

```bash
sudo systemctl restart wazuh-manager
sudo tail -f /var/ossec/logs/integrations.log     # Ctrl+C untuk berhenti
```

**Langkah D. Uji.** Dari Kali: `nmap -sS -T4 -p 1-200 10.10.10.20`. Pesan Telegram harus masuk otomatis.

Contoh pesan yang diterima:

```
🚨 WENT SOC Alert

Level: 10
Rule: 110100 - WENT TI: Suricata alert dari IP malicious (10.10.10.30)
Agent: wazuhenterprise
Source IP: 10.10.10.30 → 10.10.10.20
Time: 2026-11-23T00:28:59.269+0700
```

**Catatan:** saat ini semua alert level 7 ke atas dikirim. Untuk produksi, filter perlu dipersempit per rule ID yang sudah diverifikasi.

### 10.6 AI dan SOAR: apa yang dicoba, apa yang dibatalkan

| Opsi | Hasil |
|---|---|
| **Ollama lokal + script (Jalur A)** | Pernah berfungsi penuh: script memanggil `llama3.2:3b` di laptop via `http://10.10.56.1:11434`, ringkasan AI terkirim ke Telegram. Namun CPU-only membuat respons lambat (sekitar 142 detik pada panggilan pertama). Diputuskan **dibatalkan** dan Ollama dihapus. |
| **Shuffle** | Dibatalkan, terlalu berat (4+ container, ~4 GB RAM). |
| **n8n** | Dibatalkan sebelum instalasi karena Docker Desktop butuh fitur Windows (Virtual Machine Platform). |

**Keputusan akhir:** SOAR berupa **script Python sederhana** yang menghubungkan Wazuh ke Telegram. Ini tetap memenuhi konsep orchestration, automation, dan response dalam skala kecil.

---

## 11. Keamanan dan Kebersihan Kredensial

Selama project ini, beberapa kredensial sempat tertulis di chat atau terminal. Praktik yang benar:

| Kredensial | Tindakan yang disarankan |
|---|---|
| Telegram bot token | Regenerate di BotFather (`/revoke`), lalu update `ossec.conf` dan script |
| OTX API key | Regenerate di Settings OTX, lalu update `went_otx_update.sh` |
| Password admin Wazuh | Simpan di password manager, jangan di file repo |
| Chat ID Telegram | Boleh dianggap tidak rahasia, tapi tetap jangan dipublikasikan |

Aturan untuk repo GitHub:
- Jangan commit `ossec.conf`, `custom-telegram.py`, `went_otx_update.sh` **dengan nilai asli**. Gunakan placeholder.
- Tambahkan `.gitignore` (lihat di bawah).
- Jangan commit file `wazuh-install-files.tar` (berisi password).

---

## 12. Tahap 5: WENT-WEB-01 (Juice Shop + ModSecurity WAF)

### 12.1 Tujuan

Membuat target web yang dilindungi WAF, supaya nanti bisa dilakukan simulasi serangan web (SQLi, XSS) dan dibaca dari log mentah WAF, Nginx, dan Juice Shop.

### 12.2 Arsitektur

```
Client (Kali / laptop) → WAF (Nginx + ModSecurity, 10.10.10.40:80) → Juice Shop (container, port 3000)
```

Juice Shop **tidak** diekspos langsung, hanya bisa dijangkau lewat WAF di jaringan Docker `went-web-net`.

### 12.3 Langkah yang sudah dikerjakan

**VM:** Ubuntu Server 24.04, `went-web-01`, IP `10.10.10.40` dan `10.10.56.40`, SSH dari laptop berhasil.

**Install Docker** (dijalankan di SSH WENT-WEB-01):

```bash
sudo apt update
sudo apt install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo docker run hello-world
```

**Jaringan Docker dan container:**

```bash
sudo docker network create went-web-net

sudo docker run -d --name juice-shop --restart unless-stopped \
  --network went-web-net \
  bkimminich/juice-shop

sudo docker run -d --name waf-modsec --restart unless-stopped \
  --network went-web-net \
  -p 10.10.10.40:80:8080 \
  -p 10.10.56.40:80:8080 \
  -e PROXY=1 \
  -e BACKEND="http://juice-shop:3000" \
  owasp/modsecurity-crs:nginx
```

**Hasil:** keduanya `Up`, WAF `healthy`. `curl http://10.10.10.40/` mengembalikan halaman Juice Shop, dan halaman yang sama bisa dibuka dari laptop di `http://10.10.56.40/`.

### 12.4 Pelajaran penting (kesalahan yang terjadi)

Konfigurasi awal memakai `BACKEND="http://127.0.0.1:3000"`. Ini salah, karena di dalam container `127.0.0.1` menunjuk ke **container WAF itu sendiri**, bukan ke Juice Shop. Solusinya: keduanya dijalankan dalam **network Docker yang sama** dan WAF memanggil Juice Shop lewat **nama container** (`juice-shop`).

### 12.5 Langkah berikutnya (belum selesai)

- Mount folder log dari container ke VM supaya bisa dibaca dan dikirim ke Wazuh:

```bash
mkdir -p ~/went-juiceshop/logs/nginx ~/went-juiceshop/logs/modsecurity
sudo docker stop waf-modsec && sudo docker rm waf-modsec
sudo docker run -d --name waf-modsec --restart unless-stopped \
  --network went-web-net \
  -p 10.10.10.40:80:8080 -p 10.10.56.40:80:8080 \
  -e PROXY=1 -e BACKEND="http://juice-shop:3000" \
  -v ~/went-juiceshop/logs/nginx:/var/log/nginx \
  -v ~/went-juiceshop/logs/modsecurity:/var/log/modsecurity \
  owasp/modsecurity-crs:nginx
```

- Pasang **Wazuh Agent** di WENT-WEB-01 dan tambahkan `localfile` untuk log Nginx dan ModSecurity.
- Aktifkan **audit log** ModSecurity (`SecAuditEngine RelevantOnly`) agar payload serangan tercatat.
- Simulasi serangan dari Kali (SQLi, XSS) dan baca log mentahnya.

---

## 13. Cara Membaca Log (Konseptual)

Bagian ini adalah inti kemampuan SOC. Prinsipnya: **selalu mulai dari log mentah**, lalu naik ke dashboard.

### 13.1 Metode membaca (urutan)

1. **Apa sumbernya?** Lihat field `location` atau `decoder.name`.
2. **Kapan terjadi?** Lihat `timestamp`. Bandingkan dengan waktu serangan.
3. **Siapa menyerang siapa?** `src_ip`, `dest_ip`, `src_port`, `dest_port`.
4. **Apa yang dilakukan?** `alert.signature`, `event_type`, `commandLine`, `url`.
5. **Berhasil atau gagal?** `action`, status HTTP, `EventID` (4624 sukses, 4625 gagal).
6. **Apa dampaknya?** Apakah ada proses baru, file baru, koneksi keluar?
7. **Apakah alert ini benar?** Triase: true positive atau false positive?

### 13.2 Contoh: Suricata `eve.json` (port scan)

```json
{"timestamp":"2026-11-23T00:19:46.074166+0700","in_iface":"enp0s8","event_type":"alert",
 "src_ip":"10.10.10.30","src_port":36098,"dest_ip":"10.10.10.20","dest_port":135,"proto":"TCP",
 "alert":{"signature_id":9000001,"signature":"WENT SCAN Possible TCP SYN Port Scan","category":"Attempted Information Leak","severity":2,"action":"allowed"},
 "flow":{"pkts_toserver":1,"pkts_toclient":0}}
```

**Cara membaca:**
- Satu paket SYN dari `10.10.10.30`, tanpa balasan (`pkts_toclient: 0`), berarti scan. Koneksi tidak terbentuk.
- `dest_port` berganti terus (135, 199, 201, 479, 667, ...), ciri khas port scan.
- `src_port` tetap sama (36098 atau 37356 dalam sesi berbeda), karena Nmap memakai source port tetap per batch.
- `action: allowed` berarti IDS hanya mengamati, tidak memblokir.

### 13.3 Contoh: Sysmon Event ID 1 (process create)

Field penting di Wazuh: `data.win.eventdata.image`, `commandLine`, `parentImage`, `user`, `hashes`.

**Cara membaca:**
- Cek `image`: program apa? Lokasi wajar atau tidak? (`C:\Windows\System32\svchost.exe` wajar, `C:\Users\...\Temp\` mencurigakan.)
- Cek `parentImage`: siapa yang memanggil? `services.exe` untuk service Windows, `explorer.exe` untuk user yang klik dua kali.
- Cek `commandLine`: argumen mencurigakan? `-EncodedCommand`, `-nop`, `-w hidden`, `DownloadString` adalah tanda bahaya.
- Cek `user`: `NT AUTHORITY\SYSTEM` atau user lab.

**Contoh false positive (dianalisis di lab):** rule 61618 level 12 pada `svchost.exe -k IsolationSession -p`. Path resmi, Microsoft signed, user SYSTEM, parent PID cocok dengan `services.exe`. Field `ParentImage` kosong (`-`) karena Sysmon tidak mencatatnya untuk proses ini, sehingga rule menganggap mencurigakan. Kesimpulan: **false positive**.

### 13.4 Contoh: Sysmon Event ID 11 (file create)

Rule 92213 (level 15) pada `__PSScriptPolicyTest_xxxx.ps1` di folder Temp. File ini dibuat otomatis oleh PowerShell untuk mengecek execution policy. **False positive**.

Rule 92205 (level 9) pada file yang dibuat di `C:\Windows\SystemTemp\`, oleh `NT AUTHORITY\SYSTEM`, berulang dalam 4 detik. Pola sistem otomatis, **false positive**.

**Pelajaran:** level tinggi tidak sama dengan insiden. Analis menilai path, parent, user, pola waktu, dan konteks.

### 13.5 Contoh: alert TI (rule 110100)

```
rule.id: 110100, level 10
data.src_ip: 10.10.10.30
mitre: T1595 Active Scanning
```

Alert ini menyatakan **IP sumber ada di daftar threat intel**. Analis perlu mengecek: apakah IP ini benar-benar milik penyerang, atau hanya IP internal yang salah masuk daftar?

### 13.6 Membaca log Windows Firewall (akan dipraktikkan)

Windows Firewall mencatat koneksi yang diblokir jika logging diaktifkan. Lokasi default: `C:\Windows\System32\LogFiles\Firewall\pfirewall.log`. Format: `date time action protocol src-ip dst-ip src-port dst-port ...`. Ini akan dipakai saat insiden untuk melihat paket yang ditolak.

### 13.7 Membaca log ModSecurity (akan dipraktikkan)

Audit log ModSecurity memuat request lengkap saat rule cocok: `Message`, `Rule ID`, `Matched Data`, `URI`. Ini cara melihat **payload asli** serangan (misal `' OR 1=1--`), yang tidak terlihat dari sisi Suricata.

### 13.8 Membaca log Nginx (akan dipraktikkan)

Format access log: `IP - - [waktu] "METHOD URI HTTP/1.1" status bytes "referer" "user-agent"`. Status 200 (berhasil), 403 (diblokir WAF), 500 (error aplikasi). Pola banyak request 403 dari satu IP adalah indikasi scanning.

### 13.9 Alur mental untuk insiden web (rencana)

```
1. Suricata  : ada scan / trafik mencurigakan ke 10.10.10.40?
2. Nginx     : request HTTP apa yang masuk? status code berapa?
3. ModSec    : rule mana yang cocok? payload apa?
4. Juice Shop: apakah request mencapai aplikasi? (kalau 403, tidak)
5. Wazuh     : apakah semua lapisan ini muncul sebagai alert? rule apa?
6. Triase    : true positive? dampaknya apa? tindakan apa?
```

---

## 14. Log Troubleshooting: Masalah Nyata dan Solusinya

Bagian ini mendokumentasikan kesalahan yang benar-benar terjadi. Pelajaran di sini sering lebih berharga daripada langkah yang berhasil.

| No | Gejala | Penyebab | Solusi |
|---|---|---|---|
| 1 | SSH ke `10.10.56.10` gagal | Adapter host-only (enp0s9) belum terpasang di netplan | Pasang adapter 3 di VirtualBox, set IP statis di netplan |
| 2 | `ip -br addr` tidak menampilkan adapter ketiga | VM belum dimatikan saat menambah adapter | Matikan VM, tambah adapter, nyalakan |
| 3 | Nmap dari Kali: `Host seems down` | Windows dimatikan | Nyalakan VM endpoint |
| 4 | Ping Kali ke `.20` gagal dengan `Destination Host Unreachable` dari `.10` | Kali punya IP `10.10.10.10` bekas profil lama (bentrok) | Hapus profil NetworkManager lama, set `.30` |
| 5 | Suricata tidak mendeteksi trafik internet (`curl testmyids.com`) | `enp0s8` tidak menerima trafik internet (keluar lewat NAT) | Gunakan trafik antar-VM, bukan internet |
| 6 | `curl testmynids.org` tidak memicu alert | Domain salah (domain parkir) | Gunakan `testmyids.com` atau abaikan karena sumbernya internet |
| 7 | Rule `110100` tidak pernah cocok | Field dirujuk sebagai `data.src_ip` di dalam rule | Di rule, gunakan `src_ip` (tanpa `data.`). `data.` hanya tampil di dashboard |
| 8 | Discover kosong padahal alert ada di `fast.log` | Alert sebelum blok `eve.json` ditambahkan tidak dibaca (Wazuh hanya membaca baris baru) | Buat alert baru setelah konfigurasi |
| 9 | `grep` pada `eve.json` menampilkan "binary file matches" | Ada byte non-ASCII | Gunakan `grep -a` |
| 10 | `wazuh-logtest` menampilkan `No decoder matched` | Input berupa teks contoh, bukan log JSON | Tempel satu baris JSON asli dari `eve.json` |
| 11 | Script Telegram: `IndexError: list index out of range` | Script membaca `sys.argv[3]`, padahal Wazuh mengirim argumen dengan urutan berbeda | Cari argumen yang diawali `http` |
| 12 | `tail -f integrations.log` tidak menampilkan apa pun | Log hanya ditulis saat integrasi dipanggil | Picu alert dulu, lalu cek |
| 13 | Script OTX tidak mencetak apa-apa | `OTX_KEY` masih placeholder; file nano terpotong saat paste | Tulis ulang file dengan heredoc (`sudo tee ... << 'EOF'`) |
| 14 | `curl` ke OTX `indicators/export` tidak terverifikasi | Endpoint tidak ada di dokumentasi | Gunakan `pulses/subscribed` |
| 15 | Ollama tidak bisa dihubungi dari VM1 (timeout) | Ollama bind ke `127.0.0.1` karena `OLLAMA_HOST` belum tersimpan | Set env var permanen via PowerShell (`SetEnvironmentVariable`), restart proses |
| 16 | Ollama mati setelah terminal ditutup | Dijalankan di foreground (`ollama serve`) | Jalankan dengan `Start-Process ... -WindowStyle Hidden` |
| 17 | Ollama pakai CPU, respons 142 detik | Bug deteksi ROCm karena iGPU AMD, GPU NVIDIA tidak dipakai | Diputuskan tidak diperbaiki (risiko), Ollama akhirnya dibatalkan |
| 18 | Docker Desktop gagal install | Fitur Windows *Virtual Machine Platform* belum aktif | Aktifkan via `wsl --install` / DISM, restart. Akhirnya n8n dibatalkan |
| 19 | WAF `curl` mengembalikan halaman Error | `BACKEND=127.0.0.1:3000` menunjuk ke container WAF sendiri | Pakai network Docker bersama dan nama container `juice-shop` |
| 20 | Alert Telegram `Source IP: N/A → N/A` | Rule endpoint (Sysmon) tidak punya field IP | Normal, bukan bug |

---

## 15. Status Saat Ini dan Roadmap

### 15.1 Status komponen

| Komponen (dari rencana awal) | Status | Catatan |
|---|---|---|
| SIEM (Wazuh 4.14) | ✅ | Manager, Indexer, Dashboard |
| IDS (Suricata 7.0.3) | ✅ | Mode IDS, rule ET Open + rule custom 9000001 |
| Firewall | 🟡 | UFW (Ubuntu) dan Windows Firewall, bukan appliance |
| Endpoint security (Defender) | ✅ | Event masuk Wazuh |
| Endpoint monitoring (Sysmon) | ✅ | Config SwiftOnSecurity |
| Wazuh Agent (Windows) | ✅ | Active, mengirim Sysmon, PowerShell, Defender |
| Threat intel | ✅ | CDB list + OTX (cron 6 jam) + rule 110100 |
| Dashboard custom | ✅ | WENT-SOC-Overview, 6 panel |
| Notifikasi (Telegram) | ✅ | Script `custom-telegram.py`, level ≥ 7 |
| AI (Ollama) | ⏸ | Dibatalkan, dihapus dari laptop |
| SOAR visual (Shuffle / n8n) | ⏸ | Dibatalkan |
| SOAR sederhana (script) | ✅ | Wazuh → script → Telegram |
| Attacker (Kali) | ✅ | nmap, hydra |
| Web target (Juice Shop + ModSec) | 🟡 | Container jalan, belum ada log terhubung ke Wazuh |
| Simulasi serangan web | ⬜ | Belum |
| Insiden pembuktian lengkap | ⬜ | Belum |

### 15.2 Roadmap berikutnya

1. Mount log WAF dan Nginx, pasang Wazuh Agent di WENT-WEB-01.
2. Aktifkan audit log ModSecurity.
3. Simulasi serangan dari Kali: scan (nmap), brute force (hydra ke Windows), SQLi/XSS ke Juice Shop.
4. Baca log mentah di setiap lapisan (Suricata, ModSecurity, Nginx, Sysmon, Windows Event Log, Windows Firewall).
5. Buat rule Wazuh untuk pola web attack.
6. Dokumentasikan insiden per fase dengan format: *Scenario, Objective, Lab Environment, Attack, Detection Evidence, Log Analysis, Investigation, Response, Conclusion*.
7. Regenerate semua kredensial (lihat [Bagian 11](#11-keamanan-dan-kebersihan-kredensial)).

---

## 16. Lampiran: Konfigurasi Lengkap

> Semua nilai rahasia diganti placeholder. Ganti dengan nilai Anda sendiri.

### A. `went_otx_update.sh`

Lokasi: `/usr/local/bin/went_otx_update.sh`

```bash
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
```

### B. `custom-telegram.py`

Lokasi: `/var/ossec/integrations/custom-telegram.py` (versi final, tanpa AI)

```python
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
```

### C. Wrapper `custom-telegram` (shell)

Lokasi: `/var/ossec/integrations/custom-telegram`

```bash
#!/bin/sh
WPYTHON_BIN="framework/python/bin/python3"
SCRIPT_PATH_NAME="$0"
DIR_NAME="$(cd $(dirname ${SCRIPT_PATH_NAME}); pwd -P)"
SCRIPT_NAME="$(basename ${SCRIPT_PATH_NAME})"

case ${DIR_NAME} in
    */integrations)
        if [ -z "${WAZUH_PATH}" ]; then
            WAZUH_PATH="$(cd ${DIR_NAME}/..; pwd)"
        fi
        PYTHON_SCRIPT="${DIR_NAME}/${SCRIPT_NAME}.py"
    ;;
    *)
        WAZUH_PATH="/var/ossec"
        PYTHON_SCRIPT="${WAZUH_PATH}/integrations/${SCRIPT_NAME}.py"
    ;;
esac

${WAZUH_PATH}/${WPYTHON_BIN} ${PYTHON_SCRIPT} $1 $2 $3 $4
```

### D. Rule custom Wazuh (`/var/ossec/etc/rules/local_rules.xml`)

```xml
<group name="local,went,threat_intel,">
  <rule id="110100" level="10">
    <if_sid>86601</if_sid>
    <list field="src_ip" lookup="address_match_key">etc/lists/went-malicious-ip</list>
    <description>WENT TI: Suricata alert dari IP malicious ($(src_ip))</description>
    <mitre>
      <id>T1595</id>
    </mitre>
  </rule>
</group>
```

### E. Bagian `<ruleset>` di `ossec.conf`

```xml
<ruleset>
  <decoder_dir>ruleset/decoders</decoder_dir>
  <rule_dir>ruleset/rules</rule_dir>
  <rule_exclude>0215-policy_rules.xml</rule_exclude>
  <list>etc/lists/audit-keys</list>
  <list>etc/lists/amazon/aws-eventnames</list>
  <list>etc/lists/security-eventchannel</list>
  <list>etc/lists/malicious-ioc/malware-hashes</list>
  <list>etc/lists/malicious-ioc/malicious-ip</list>
  <list>etc/lists/malicious-ioc/malicious-domains</list>
  <list>etc/lists/went-malicious-ip</list>

  <decoder_dir>etc/decoders</decoder_dir>
  <rule_dir>etc/rules</rule_dir>
</ruleset>
```

### F. Rule Suricata custom (`/var/lib/suricata/rules/local.rules`)

```
alert tcp any any -> $HOME_NET any (msg:"WENT SCAN Possible TCP SYN Port Scan"; flags:S; threshold: type both, track by_src, count 15, seconds 10; classtype:attempted-recon; sid:9000001; rev:1;)
```

### G. Integrasi Telegram di `ossec.conf`

```xml
<integration>
  <name>custom-telegram</name>
  <hook_url>https://api.telegram.org/bot<TELEGRAM_BOT_TOKEN>/sendMessage</hook_url>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
```

### H. Docker Compose untuk WENT-WEB-01 (ringkasan konfigurasi yang berjalan)

Container dijalankan dengan `docker run`. Versi `docker-compose.yml` yang setara:

```yaml
networks:
  went-web-net:
    name: went-web-net

services:
  juice-shop:
    image: bkimminich/juice-shop
    container_name: juice-shop
    restart: unless-stopped
    networks: [went-web-net]

  waf-modsec:
    image: owasp/modsecurity-crs:nginx
    container_name: waf-modsec
    restart: unless-stopped
    depends_on: [juice-shop]
    environment:
      PROXY: "1"
      BACKEND: "http://juice-shop:3000"
    ports:
      - "10.10.10.40:80:8080"
      - "10.10.56.40:80:8080"
    volumes:
      - ~/went-juiceshop/logs/nginx:/var/log/nginx
      - ~/went-juiceshop/logs/modsecurity:/var/log/modsecurity
    networks: [went-web-net]
```

---

## Struktur Repository GitHub yang Disarankan

```
went-enterprise/
├── README.md                      ← dokumen ini
├── docs/
│   ├── architecture.md
│   └── troubleshooting.md
├── configs/
│   ├── siem/
│   │   ├── local_rules.xml
│   │   ├── ossec-integration.example.xml
│   │   └── netplan-siem.example.yaml
│   ├── suricata/
│   │   ├── local.rules
│   │   └── suricata.yaml.diff.md
│   ├── endpoint/
│   │   └── ossec-agent-localfile.example.xml
│   └── web/
│       └── docker-compose.yml
├── scripts/
│   ├── custom-telegram.py
│   ├── custom-telegram
│   └── went_otx_update.sh
├── scenarios/                     ← diisi saat insiden dijalankan
└── .gitignore
```

**`.gitignore` yang disarankan:**

```
*.tar
wazuh-install-files.tar
*.env
secrets/
*_token*
*.key
logs/
```

### Perintah upload ke GitHub

**Dijalankan di:** PowerShell laptop, di folder repo yang sudah dibuat.

```powershell
git init
git add .
git commit -m "Initial commit: WENT-Enterprise SOC home lab writeup"
git branch -M main
git remote add origin https://github.com/<USERNAME>/went-enterprise.git
git push -u origin main
```

Sebelum `git add .`, pastikan file berisi placeholder, bukan token asli.

---

## Penutup

Project ini membuktikan alur SOC end-to-end dengan tool open-source: deteksi jaringan, SIEM, threat intel, dan notifikasi. Tahap berikutnya adalah membaca log serangan web dari sisi WAF dan aplikasi, lalu menyusun insiden pembuktian.

**Prinsip utama yang perlu diingat:** alert adalah titik awal investigasi, bukan kesimpulan. Log mentah adalah sumber kebenaran.
