<!-- markdownlint-disable-file MD024 -->

# Changelog

Semua perubahan penting pada proyek **TrustPositif Validator** didokumentasikan dalam berkas ini.

Format changelog ini mengacu pada [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
dan proyek ini mematuhi standar [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.5] - 2026-10-03

### Fitur Baru & Peningkatan (Features & Enhancements)

- **Dukungan Penuh IDN & Punycode Menggunakan `idn2` (IDNA2008)**:
  - Mengintegrasikan konversi otomatis nama domain berkarakter internasional (non-ASCII Unicode) ke format Punycode (`xn--...`) berbasis standar modern IDNA2008 (RFC 5890, 5891, 5892, 5893) menggunakan `idn2` (GNU Libidn2).
  - Pemrosesan stream per-chunk secara paralel dengan opsi `--no-tr46` sebelum tahap validasi RFC/TLD, memastikan domain IDN internasional divalidasi dengan tepat terhadap Root Zone Database resmi IANA (yang memuat ribuan TLD berkode `xn--...`).
  - Arsitektur fallback tangguh: mendukung `idn` (GNU Libidn) serta gracefully pass-through jika tools belum terpasang tanpa merusak alur data.
  - Pengaturan fleksibel via Environment Variable `USE_IDN2=1/0` dan opsi switch CLI (`--punycode`, `--no-punycode`, `--idn`, `--no-idn`).
  - Auto-detection dan instalasi dependensi paket `idn2` / `libidn2` / `libidn2-utils` pada berbagai package manager Linux (`apt`, `dnf`, `apk`, `zypper`, `brew`).
- **Pembersihan Subdomain Berdasarkan `DOMAINS_TO_CLEAN.txt`**:
  - Menghadirkan modul pembersihan subdomain berperforma tinggi yang memproses berkas eksternal `DOMAINS_TO_CLEAN.txt` menggunakan hash table lookup AWK (`FNR == NR`).
  - Mengeliminasi ribuan subdomain liar dan spam (`*.clean_domain`) dalam waktu sub-detik (<0.3 detik untuk 124.000+ domain) tanpa membebani heap memory bash (*zero bash array footprint*).
  - Berkas sumber dapat dikonfigurasi melalui variabel lingkungan `DOMAINS_TO_CLEAN_FILE` atau flag CLI `--clean-file=<path>`.
- **Opsi Fleksibel Enable / Disable Subdomain Cleanup**:
  - Menyediakan kendali penuh bagi pengguna untuk mengaktifkan atau menonaktifkan pembersihan subdomain melalui Environment Variable (`CLEAN_SUBDOMAINS=1` atau `0`) serta switch CLI flag (`--clean-subdomains`, `--no-clean-subdomains`).
  - Nilai default adalah `0` (dinonaktifkan) untuk menjaga kompatibilitas murni dengan alur eksekusi default.
- **Modernisasi Multi-Option CLI Argument Parser**:
  - Mengganti parser tunggal `${1-}` dengan loop `while [[ $# -gt 0 ]]` modular yang mendukung penerimaan kombinasi opsi baris perintah (`--clean-subdomains`, `--clean-file=...`, `--cut-subdomains`, `--punycode`, dll.) secara elegan tanpa mengganggu pemanggilan terjadwal di cron job.

### Keamanan & Integritas Data (Security & Data Integrity)

- **Perlindungan Root Domain (Apex Preservation Guard)**:
  - Menerapkan isolasi hierarki domain `for (i = n; i >= 2; i--)` pada parser AWK. Memastikan bahwa pembersihan hanya membuang *subdomain* dari domain target, sedangkan domain utama (*apex/root domain*) tetap dipertahankan pada blocklist DNS/RPZ agar proteksi keamanan situs target tidak bocor.
- **Validasi Keberadaan Berkas (File Existence Guard)**:
  - Menambahkan verifikasi `[[ -f "${DOMAINS_TO_CLEAN_FILE}" ]]` dengan log peringatan informatif jika berkas daftar pembersihan tidak ditemukan di sistem, sehingga skrip tidak crash dan tetap melanjutkan pemrosesan daftar validasi utama.

### Pembersihan Proyek (Project Cleanup & Deprecations)

- **Pembersihan Menyeluruh Tautan Ko-fi**:
  - Menghapus seluruh badge dan tautan donasi Ko-fi dari seluruh dokumentasi proyek (`README.md`), mempertahankan jalur donasi resmi PayPal.

### Kualitas Kode (Code Quality & Compliance)

- **Audit Komprehensif 13 Pilar Kode**:
  - Lulus evaluasi menyeluruh: Bug Review, Syntax Review, Runtime Review, Logic Review, Memory Review, Dead Code Review, Duplicate Code Review, Circular Dependency Review, Performance Bottleneck Review, Security Vulnerability Review, Maintainability Review, Scalability Review, dan Readability Review.
- **ShellCheck v0.11+ Certified**:
  - 100% lolos uji analisis statis ShellCheck tanpa satu pun warning (`zero warnings`) dengan penambahan anotasi pengaman SC2016 yang tepat pada sub-parser AWK.

---

## [1.0.4] - 2026-08-18

### Keamanan & Hardening (Security & Hardening)

- **TTY Guard pada Clear Screen (`isatty`)**:
  - Proteksi perintah `clear` agar hanya dieksekusi apabila `stdout` terhubung langsung ke terminal interaktif (`[[ -t 1 ]]`). Menghindari polusi escape code ANSI pada eksekusi otomatis via cron jobs, systemd services, dan redirection log file.
- **Dukungan Standar NO_COLOR**:
  - Mengimplementasikan spesifikasi industri [no-color.org](https://no-color.org/) (`NO_COLOR`). Saat variabel `NO_COLOR` terdefinisi, seluruh kode pewarnaan ANSI di-reset ke string kosong, menjamin output bersih untuk log analyzer dan CI/CD pipeline.
- **Izin Berkas Deterministik (`chmod 0644`)**:
  - Menetapkan permission `0644` secara eksplisit pada temporary staging file (`VALID_OUTPUT_TMP`) dan output final (`VALID_OUTPUT`). Memastikan berkas blocklist hasil validasi selalu dapat dibaca oleh service DNS (BIND9, Unbound, PowerDNS, Pi-hole, AdGuard Home) maupun Web Server (Nginx, Apache) meski script dijalankan di bawah umask sistem yang restriktif (`077` atau `027`).

### Perbaikan Bug & Parser (Bug Fixes & Parser)

- **Hardening AWK terhadap DOS/Windows CRLF (`\r`)**:
  - Menambahkan sanitasi eksplisit `gsub(/\r/, "", domain)` tepat di awal pemrosesan record AWK chunk parser. Mencegah kegagalan evaluasi regex dan korupsi karakter newline tersembunyi pada berkas unduhan sumber berformat Windows/DOS.
- **Perluasan Prefix Sanitizer**:
  - Memperluas regex pembersihan simbol awalan dari `sub(/^[*|]+/, "", domain)` menjadi `sub(/^[*|@.]+/, "", domain)` untuk membersihkan prefix karakter `@`, `*`, `|`, dan leading dots `.` pada input mentah.
- **Deduplikasi Path Pembersihan `force_cleanup`**:
  - Mengoptimalkan fungsi `force_cleanup` dengan array path dinamis agar tidak melakukan scanning dan pembersihan ganda pada direktori `/tmp` ketika `$TMPDIR` bernilai `/tmp` atau tidak didefinisikan.

### Performa & Portabilitas (Performance & Portability)

- **Deteksi Core CPU Lintas Platform (Sysctl Fallback)**:
  - Menambahkan fallback `sysctl -n hw.ncpu 2>/dev/null` pada fungsi `get_total_cores()` untuk memastikan deteksi jumlah core CPU berjalan optimal di macOS dan FreeBSD saat utility `nproc` maupun `getconf` tidak tersedia.

### Kualitas Kode (Code Quality & Compliance)

- **Verifikasi ShellCheck v0.11+**:
  - 100% lolos uji analisis statis ShellCheck tanpa peringatan (*zero warnings*) di bawah konfigurasi `set -Eeuo pipefail`.

---

## [1.0.3] - 2026-07-27

### Perbaikan Bug & Parser (Bug Fixes & Parser)

- **Urutan Sanitasi Path, Query, Hash & Port**:
  - Memperbaiki urutan parsing dengan memotong path, query string, hash, dan opsi AdGuard (`/`, `^`, `$`, `?`, `#`) *sebelum* evaluasi port dan titik dua. Memperbaiki bug di mana entri seperti `example.com:8080/path` sebelumnya terbuang.
- **Dukungan Sintaks Blocklist Modern**:
  - Menambahkan sanitasi prefix AdGuard/uBlock (`||`), wildcard (`*`), leading dot (`.`), serta suffix (`^`, `$options`) agar blocklist generasi modern dapat diproses tanpa kehilangan domain utama.
- **Pembersihan IPv6 Hosts Prefix**:
  - Memperluas pembuangan prefix IPv6 pada format file hosts (`::`, `::1`, `0:0:0:0:0:0:0:1`, `fe80::`).
- **Atomic Write Lintas Filesystem**:
  - Menggunakan staging file `VALID_OUTPUT_TMP` di dalam direktori target `OUTPUT_DIR` sebelum perintah penggantian atomic `mv`, menjamin atomisitas write 100% terjaga meskipun `/tmp` dan `OUTPUT_DIR` berada pada partisi/mount point yang berbeda.
- **Proteksi SORT_BUFFER BSD Sort**:
  - Menambahkan konversi otomatis nilai persentase (misal `50%`) menjadi nilai absolut (MiB) ketika mendeteksi BSD sort pada macOS dan FreeBSD untuk mencegah kegagalan eksekusi.

### Performa & Portabilitas (Performance & Portability)

- **Deteksi Memori FreeBSD Native**:
  - Menambahkan pemantauan RAM & alokasi memory page native FreeBSD melalui `sysctl hw.physmem` pada fungsi `show_system_resources()`.
- **Portabilitas force_cleanup**:
  - Memperluas cakupan pembersihan direktori temporer ke `$TMPDIR` dan `/tmp`.

### Kualitas Kode (Code Quality & Compliance)

- **Verifikasi ShellCheck**:
  - 100% lolos audit ShellCheck dengan status *zero warnings*.

---

## [1.0.2] - 2026-07-17

### Perbaikan Bug & Portabilitas (Bug Fixes & Portability)

- **Portabilitas POSIX Pipeline Sort**:
  - Mengganti flag non-standar `sort -z` (NUL-delimited, tidak didukung BSD sort) dengan kombinasi pipeline `find -print0 | xargs -0 printf '%s\n' | sort` yang mematuhi standar POSIX.
- **SORT_BUFFER Portability**:
  - Mengatur buffer default `2G` untuk platform non-GNU (macOS/FreeBSD) guna menggantikan format persentase yang eksklusif untuk GNU coreutils.
- **Keamanan Direktori Kerja (`DOMAIN_FILE`)**:
  - Memindahkan penyimpanan berkas unduhan `DOMAIN_FILE` dari working directory saat ini (`CWD`) ke dalam direktori terisolasi `TEMP_DIR` demi keamanan dan pembersihan atomic.
- **Sanitasi Nilai Integer System Resources**:
  - Menambahkan validasi regex numerik `^[0-9]+$` pada variabel `page_size`, `free_pages`, dan `inactive_pages` sebelum operasi aritmetika shell di fungsi `show_system_resources()`.
- **Perbaikan Typo Dokumentasi**:
  - Memperbaiki penulisan istilah internal dari `KEBUTUUM` menjadi `KEBUTUHAN`.

### CI/CD & Otomasi (Automation)

- **GitHub Pages Deployment Workflow**:
  - Menambahkan automasi Jekyll deployment pada `.github/workflows/jekyll-gh-pages.yml`.
- **Dependabot Configuration**:
  - Menambahkan `.github/dependabot.yml` untuk monitoring otomatis dependensi GitHub Actions.

---

## [1.0.1] - 2026-07-17

### Fitur Baru & Peningkatan (Features & Enhancements)

- **Kompatibilitas Native macOS**:
  - Menambahkan modul perhitungan total dan ketersediaan RAM untuk macOS menggunakan `sysctl -n hw.memsize` dan `vm_stat`.
- **Optimalisasi Validasi Regex URL Sumber**:
  - Memperbarui pola regex verifikasi URL sumber blocklist agar mendukung format skema dan query string lengkap secara akurat.

---

## [1.0.0] - 2026-07-15

### Rilis Awal (Initial Release)

- **Inisialisasi Proyek TrustPositif Validator**:
  - Rilis perdana mesin agregasi dan validasi blocklist TrustPositif/Komdigi.
- **Arsitektur High-Performance AWK & GNU Parallel**:
  - Integrasi deteksi runtime otomatis `mawk` -> `gawk` -> `awk` dengan fallback GNU Parallel.
- **Verifikasi IANA TLD & RFC Compliance**:
  - Validasi ketat terhadap IANA Root Zone Database dan standar RFC 1034, RFC 1035, RFC 1123, RFC 3490, serta RFC 5890.
- **Zero Array Memory Footprint**:
  - Menggantikan array memory-heavy `DOMAINS_TO_CLEAN` dengan stream processing berbasis chunk file untuk performa maksimal dan efisiensi RAM.
- **Defensive Shell Standards**:
  - Penerapan `set -Eeuo pipefail`, signal trap cleanup, atomic rename, dan SSL fallback.
- **ShellCheck Certified**:
  - Lolos uji statis ShellCheck v0.11+ dengan status *clean*.
