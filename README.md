# Vulnerator

**Vulnerator** adalah sebuah web vulnerability scanner yang dirancang untuk meng-crawl website dan mendeteksi berbagai jenis celah keamanan seperti SQL Injection, XSS, Open Redirect, Command Injection, File Upload vulnerability, Laravel debug mode exposure, CSRF token missing, Laravel mass assignment, OJS exploit, SQL login bypass, SSRF, RCE, dan LFI.

---

## Fitur Utama

- Melakukan crawling website secara rekursif dalam satu domain.
- Deteksi otomatis berbagai celah keamanan umum di web.
- Mendeteksi Laravel Debug Mode terbuka yang membocorkan informasi sensitif.
- Memeriksa form tanpa token CSRF.
- Eksploitasi PoC otomatis untuk beberapa kerentanan (SQLi, XSS, SSRF, OJS, dll).
- Mencatat semua URL yang terdeteksi memiliki celah dan menyimpan hasil eksploitasi ke file log.
- Memudahkan auditor keamanan melakukan penilaian keamanan secara cepat dan komprehensif.

---

## Instalasi

Pastikan Python 3 sudah terpasang pada sistem Anda.

```bash
git clone https://github.com/username/MarsHallVulnerator.git
cd MarsHallVulnerator
pip install -r requirements.txt
```

## Cara penggunaan
python vuln.py http://target-website.com hasil_scan.txt

- http://target-website.com : URL target yang ingin discan.
- hasil_scan.txt : File output tempat menyimpan URL hasil scan dan exploit.

## Output
- File output berisi daftar URL yang discan.
- Log eksploitasi celah disimpan di file yang sama.
- Ringkasan hasil scan ditampilkan di akhir proses.

## Peringatan
Gunakan tools ini hanya untuk website yang Anda miliki atau dengan izin eksplisit dari pemilik website.

Penggunaan tanpa izin dapat melanggar hukum yang berlaku.

## Kontribusi
Silakan buka isu (issue) atau buat pull request untuk pengembangan dan perbaikan fitur.
