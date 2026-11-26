# Troubleshooting

| No | Gejala | Penyebab | Solusi |
|---|---|---|---|
| 1 | SSH ke 10.10.56.10 gagal | Adapter host-only belum di netplan | Pasang adapter 3, set IP statis |
| 2 | ip -br addr tidak menampilkan adapter ketiga | VM belum dimatikan saat tambah adapter | Matikan VM, tambah adapter, nyalakan |
| 3 | Nmap: Host seems down | VM Windows mati | Nyalakan VM endpoint |
| 4 | Ping ke .20 gagal, error dari .10 | Kali punya IP 10.10.10.10 dari profil lama | Hapus profil NetworkManager lama |
| 5 | Suricata tidak lihat curl ke internet | enp0s8 tidak menerima trafik keluar (NAT) | Gunakan trafik antar-VM |
| 6 | curl testmynids.org tidak memicu alert | Domain salah (domain parkir) | Gunakan testmyids.com atau trafik internal |
| 7 | Rule 110100 tidak pernah cocok | Di dalam rule dipakai data.src_ip | Gunakan src_ip di rule (data. hanya tampil di dashboard) |
| 8 | Discover kosong padahal fast.log ada alert | Wazuh hanya membaca baris baru | Buat alert baru setelah konfigurasi |
| 9 | grep eve.json: binary file matches | Byte non-ASCII | Gunakan grep -a |
| 10 | wazuh-logtest: No decoder matched | Input bukan log JSON asli | Tempel satu baris JSON dari eve.json |
| 11 | IndexError: list index out of range (integrator) | Script membaca sys.argv[3] | Cari argumen yang diawali http |
| 12 | tail -f integrations.log kosong | Log hanya ditulis saat integrasi dipanggil | Picu alert dulu |
| 13 | Script OTX tidak mencetak apa-apa | OTX_KEY placeholder; paste nano terpotong | Tulis ulang file dengan sudo tee << 'EOF' |
| 14 | Endpoint indicators/export tidak terverifikasi | Endpoint tidak ada di dokumentasi | Gunakan pulses/subscribed |
| 15 | Ollama timeout dari VM1 | OLLAMA_HOST tidak tersimpan, bind 127.0.0.1 | Set env var permanen, restart proses |
| 16 | Ollama mati setelah terminal ditutup | Dijalankan foreground | Start-Process -WindowStyle Hidden |
| 17 | Ollama 142 detik per respons | CPU-only, GPU tidak terpakai | Dibatalkan |
| 18 | Docker Desktop gagal install | Virtual Machine Platform belum aktif | wsl --install / DISM, restart |
| 19 | WAF menampilkan halaman Error | BACKEND 127.0.0.1 menunjuk ke container WAF | Gunakan network Docker bersama dan nama container |
| 20 | Telegram: Source IP N/A → N/A | Rule endpoint tidak punya field IP | Normal, bukan bug |
