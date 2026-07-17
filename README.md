# TrustPositif Validator

> **Enterprise-grade domain validation and aggregation pipeline for TrustPositif/Komdigi blocklists.**
> High-performance · Standards-compliant · Cross-platform · ShellCheck Certified

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![ShellCheck](https://img.shields.io/badge/ShellCheck-Certified-brightgreen.svg)](https://www.shellcheck.net)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20FreeBSD-informational.svg)](https://github.com/alsyundawy/TrustPositif-Validator)
[![Version](https://img.shields.io/badge/Version-1.0.2-orange.svg)](https://github.com/alsyundawy/TrustPositif-Validator/releases)
[![Standards](https://img.shields.io/badge/RFC-1034%20%7C%201035%20%7C%201123%20%7C%203490%20%7C%205890-lightgrey.svg)](https://github.com/alsyundawy/TrustPositif-Validator)

---

## Overview

**TrustPositif Validator** is a production-ready Bash/Shell script that downloads, sanitizes, validates, deduplicates, and exports domain blocklists from TrustPositif/Komdigi and configurable public sources. It validates every domain against the official [IANA Root Zone Database](https://data.iana.org/TLD/tlds-alpha-by-domain.txt) and multiple RFC standards, producing a deterministic, DNS/RPZ-ready output file optimized for automated deployments at scale.

### Key Capabilities

| Feature | Detail |
| --- | --- |
| **Multi-Source Input** | Aggregates from `TRUSTPOSITIF_URLS` array — easily extensible |
| **IANA TLD Validation** | Validates every domain against the live IANA Root Zone Database |
| **RFC Compliance** | RFC 1034, RFC 1035, RFC 1123, RFC 3490, RFC 5890 + IDN/Punycode |
| **Advanced Sanitization** | Strips IPv4/IPv6, URL schemes, ports, wildcards, comments, path segments |
| **Parallel Processing** | GNU Parallel with adaptive core/chunk auto-tuning |
| **AWK Auto-Fallback** | `mawk` → `gawk` → `awk` with functional validation |
| **Atomic Output** | Temporary file + rename pattern — no partial writes |
| **Cross-Platform** | Debian/Ubuntu, RHEL/CentOS/Fedora, Alpine, Arch, macOS, FreeBSD |
| **Auto Dependency Install** | Detects `apt`/`dnf`/`yum`/`zypper`/`apk` and installs missing tools |
| **ShellCheck Certified** | 100% warning-free on ShellCheck v0.11+ |

---

## Standards Compliance

- **RFC 1034** — Domain names: concepts and facilities
- **RFC 1035** — Domain names: implementation and specification
- **RFC 1123** — Requirements for Internet hosts
- **RFC 3490** — Internationalizing Domain Names in Applications (IDNA)
- **RFC 5890** — Internationalized Domain Names for Applications (IDNA 2008)
- **IANA Root Zone Database** — Live TLD validation
- **IDN / Punycode** — Full `xn--` label support

---

## Quick Start

### Option 1 — Direct Execution via `curl`

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/alsyundawy/TrustPositif-Validator/main/trustpositif-validator.sh)
```

### Option 2 — Direct Execution via `wget`

```bash
bash <(wget -qO- https://raw.githubusercontent.com/alsyundawy/TrustPositif-Validator/main/trustpositif-validator.sh)
```

### Option 3 — Download and Run

```bash
# via curl
curl -fsSL -o trustpositif-validator.sh \
  https://raw.githubusercontent.com/alsyundawy/TrustPositif-Validator/main/trustpositif-validator.sh
chmod +x trustpositif-validator.sh
bash trustpositif-validator.sh

# via wget
wget -q -O trustpositif-validator.sh \
  https://raw.githubusercontent.com/alsyundawy/TrustPositif-Validator/main/trustpositif-validator.sh
chmod +x trustpositif-validator.sh
bash trustpositif-validator.sh
```

### Option 4 — Git Clone

```bash
git clone https://github.com/alsyundawy/TrustPositif-Validator.git
cd TrustPositif-Validator
chmod +x trustpositif-validator.sh
bash trustpositif-validator.sh
```

---

## Usage

```bash
bash trustpositif-validator.sh                   # Normal run
bash trustpositif-validator.sh --help            # Full documentation
bash trustpositif-validator.sh --version         # Show version
bash trustpositif-validator.sh --force-cleanup   # Clean up leftover temp files
```

### Environment Variable Overrides

```bash
# Process only subdomains' parent domain (aggressive mode)
CUT_SUBDOMAINS=1 bash trustpositif-validator.sh

# Override parallelism and chunk size
NUM_CORES=8 CHUNK_SIZE=28000 bash trustpositif-validator.sh

# Override sort buffer (useful on memory-constrained systems)
SORT_BUFFER=256M bash trustpositif-validator.sh

# Override output directory
OUTPUT_DIR=/data/blocklists bash trustpositif-validator.sh

# Disable SSL bypass (enforce strict TLS verification)
CURL_INSECURE=0 bash trustpositif-validator.sh

# Force a specific AWK engine
AWK_CMD=/usr/bin/mawk bash trustpositif-validator.sh
```

---

## Output

```text
/var/www/html/trustpositif/domain-trustpositif_valid.txt
```

- One valid domain per line
- UTF-8 encoded, no BOM
- Alphabetically sorted, case-insensitive
- Fully deduplicated
- Ready for use in **BIND RPZ**, **Unbound**, **Pi-hole**, **AdGuard**, **dnsmasq**, or any DNS-based blocklist system

---

## System Requirements

### Hardware Specifications

| Component | Minimum | Recommended | Optimal |
| --- | --- | --- | --- |
| **CPU** | 2 cores / 1.5 GHz | 4 cores / 2.5 GHz | 8+ cores / 3.0 GHz+ |
| **RAM** | 512 MB | 2 GB | 8 GB+ |
| **Disk Space** | 200 MB free | 1 GB free (SSD) | 5 GB free (NVMe SSD) |
| **Network** | 10 Mbps, stable | 100 Mbps | 1 Gbps, low-latency |
| **OS** | Linux kernel 4.x+ / macOS 11+ / FreeBSD 13+ | Ubuntu 22.04 / Debian 12 | Debian 12 / RHEL 9 |
| **Bash** | 4.4+ | 5.1+ | 5.2+ |

> **Catatan Performa:**
>
> - Pada sistem dengan **< 2 GB RAM**, script otomatis menurunkan `NUM_CORES=1` dan `CHUNK_SIZE` minimum.
> - Pada sistem dengan **4–8 GB RAM**, throughput optimal sekitar 35.000–45.000 domain/detik.
> - Pada sistem dengan **8+ GB RAM** dan **NVMe SSD**, throughput dapat mencapai 60.000+ domain/detik.
> - `TEMP_DIR` ditempatkan di `/tmp` secara default — gunakan filesystem berbasis **RAM (`tmpfs`)** untuk performa maksimal.

---

### Required Packages — Per Platform

#### Ubuntu / Debian / Linux Mint / Pop!_OS

```bash
sudo apt update
sudo apt install -y bash curl wget mawk gawk parallel coreutils procps findutils grep
```

#### RHEL 9 / CentOS Stream / AlmaLinux / Rocky Linux

```bash
sudo dnf install -y bash curl wget gawk parallel coreutils procps-ng findutils grep
```

#### CentOS 7 / RHEL 7 (yum)

```bash
sudo yum install -y bash curl wget gawk parallel coreutils procps-ng findutils grep
```

#### Fedora

```bash
sudo dnf install -y bash curl wget gawk parallel coreutils procps-ng findutils grep
```

#### openSUSE Leap / SUSE Linux Enterprise

```bash
sudo zypper --non-interactive install bash curl wget gawk parallel coreutils procps findutils grep
```

#### Alpine Linux

```bash
sudo apk add --no-cache bash curl wget mawk gawk parallel coreutils procps findutils grep
```

#### Arch Linux / Manjaro

```bash
sudo pacman -Sy --noconfirm bash curl wget gawk parallel coreutils procps-ng findutils grep
```

#### Gentoo Linux

```bash
sudo emerge --ask=n net-misc/curl net-misc/wget sys-apps/gawk sys-apps/parallel \
  sys-apps/coreutils sys-apps/procps sys-apps/findutils sys-apps/grep
```

#### FreeBSD 13 / 14

```bash
# Install package manager tools
pkg install -y bash curl wget gawk p5-parallel coreutils findutils gnugrep gsed

# Pastikan bash tersedia dan set sebagai shell eksekusi
ln -sf /usr/local/bin/bash /usr/local/bin/bash

# Jalankan script secara eksplisit dengan bash
bash trustpositif-validator.sh
```

> **FreeBSD Notes:**
>
> - `parallel` di FreeBSD dipasang melalui paket `p5-parallel` (GNU Parallel berbasis Perl).
> - Gunakan `gawk` (bukan `nawk` bawaan FreeBSD) — script mendeteksinya secara otomatis.
> - `sort` di FreeBSD tidak mendukung `--version` dan `--buffer-size`; script otomatis menggunakan nilai absolut untuk `SORT_BUFFER`.
> - Jalankan selalu dengan `bash trustpositif-validator.sh`, bukan `sh trustpositif-validator.sh`.

#### macOS (via Homebrew)

```bash
brew install bash gawk parallel coreutils wget curl

# Pastikan GNU coreutils diutamakan di PATH
export PATH="/usr/local/opt/coreutils/libexec/gnubin:$PATH"
bash trustpositif-validator.sh
```

> **Note:** Script mendeteksi dan mencoba menginstal dependency yang hilang secara otomatis menggunakan package manager yang tersedia di sistem.

---

## Configuration

The script auto-tunes the following parameters based on detected system resources:

| Parameter | Auto Logic | Override |
| --- | --- | --- |
| `NUM_CORES` | `nproc` capped to 4–32, reduced on low-RAM systems | `NUM_CORES=8` |
| `CHUNK_SIZE` | `20000 + (NUM_CORES × 1000)`, capped 1000–50000 | `CHUNK_SIZE=30000` |
| `SORT_BUFFER` | 128M / 256M / 512M / 1G / 2G (50% on GNU sort) | `SORT_BUFFER=512M` |
| `AWK_CMD` | Auto-detect: `mawk` → `gawk` → `awk` | `AWK_CMD=/usr/bin/gawk` |
| `CURL_INSECURE` | `1` (bypass SSL) for legacy server compat | `CURL_INSECURE=0` |

### Adding Domain Sources

Edit the `TRUSTPOSITIF_URLS` array in the script:

```bash
TRUSTPOSITIF_URLS=(
    "https://repo.alsyundawy.com/TrustPositif/domains_isp"
    "https://example.com/my-custom-blocklist.txt"
    "https://another-source.net/domains.txt"
)
```

---

## Architecture

```text
┌─────────────────────────────────────────────────┐
│             TrustPositif Validator               │
├──────────────┬──────────────────────────────────┤
│  Phase 1     │  Download TLD IANA + all sources  │
│  Phase 2     │  Split into adaptive chunks       │
│  Phase 3     │  Parallel AWK validation (RFC)    │
│  Phase 4     │  Sort + global deduplication      │
│  Phase 5     │  Atomic write to output file      │
│  Phase 6     │  Cleanup all temp files via trap  │
└──────────────┴──────────────────────────────────┘
```

### Log Format

| Prefix | Level | Description |
| --- | --- | --- |
| `[>] [PROSES]` | Progress | Active operation in progress |
| `[i] [INFO]` | Info | Configuration and system info |
| `[OK] [BERHASIL]` | Success | Operation completed successfully |
| `[!] [PERINGATAN]` | Warning | Non-critical issue, execution continues |
| `[X] [ERROR]` | Error | Critical failure, execution halts |

---

## Security

- `set -Eeuo pipefail` — strict error propagation
- `trap` on `EXIT`, `INT`, `TERM` — guaranteed cleanup
- `mktemp` isolated temp directory — no CWD pollution
- Atomic rename pattern — prevents partial/corrupt output
- Input validation on all URLs, paths, and numeric variables
- No credentials, tokens, or secrets in log output
- Child process termination on abort

---

## Performance Benchmarks

> Reference system: 8 cores, 16 GB RAM, NVMe SSD, 1 Gbps network

| Phase | Duration |
| --- | --- |
| Download | 10–15 seconds |
| Parallel AWK Processing | 30–60 seconds (1.5M domains) |
| Sort + Deduplication | 5–15 seconds |
| Cleanup | < 1 second |
| **Total** | **~1–1.5 minutes** |
| Throughput | ~35,000–45,000 domains/second |
| Memory Usage | ~100 MB |

---

## Changelog

### v1.0.2 — 17 Juli 2026 — Portabilitas & Security Hardening

- **[FIX]** Portabilitas `sort`: Mengganti `sort -z` (NUL-delimited, tidak didukung BSD/macOS sort) dengan pipeline `xargs + sort` POSIX-compatible untuk pemrosesan chunk paralel.
- **[FIX]** Portabilitas `SORT_BUFFER`: Mengganti nilai `"50%"` (GNU sort only) dengan `"2G"` pada platform non-GNU (macOS/FreeBSD).
- **[FIX]** FreeBSD RAM Detection: Menambahkan deteksi RAM native FreeBSD via `sysctl hw.physmem` sebagai fallback setelah macOS (`hw.memsize`).
- **[FIX]** `DOMAIN_FILE` Path Safety: Memindahkan `DOMAIN_FILE` dari CWD ke dalam `TEMP_DIR` untuk keamanan direktori kerja dan atomic cleanup.
- **[FIX]** `page_size` Guard: Validasi `^[0-9]+$` pada `page_size`, `free_pages`, `inactive_pages` sebelum aritmetika di `show_system_resources` — mencegah error pada `set -e`.
- **[FIX]** `mem_bytes` Guard: Validasi `^[0-9]+$` pada `mem_bytes` di `show_system_resources`, konsisten dengan `get_mem_mib`.
- **[FIX]** Typo Dokumentasi: `KEBUTUUM` → `KEBUTUHAN`.
- **[LINT]** 100% lulus ShellCheck v0.11 tanpa peringatan baru.

### v1.0.1 — 17 Juli 2026 — Kompatibilitas macOS & Validasi URL

- **[BARU]** Deteksi RAM native macOS via `sysctl hw.memsize` dan `vm_stat`.
- **[FIX]** Regex validasi URL mendukung query parameters, port, dan hash.
- **[LINT]** 100% lulus ShellCheck tanpa peringatan.

### v1.0.0 — 15 Juli 2026 — Initial Release

- **[BARU]** Inisialisasi script TrustPositif-Validator.sh.
- **[BARU]** Multi-source input via `TRUSTPOSITIF_URLS` array.
- **[BARU]** Pemrosesan paralel via GNU Parallel + AWK engine auto-fallback.
- **[BARU]** Strict mode: `set -Eeuo pipefail`, `trap`, atomic rename, SSL bypass.
- **[LINT]** 100% lulus ShellCheck.

---

## Troubleshooting

| Masalah | Solusi |
| --- | --- |
| Script terjebak/hang | `bash trustpositif-validator.sh --force-cleanup` kemudian jalankan ulang |
| Error dependency | `sudo apt install -y curl mawk gawk parallel coreutils` |
| Unduhan gagal | Periksa koneksi, firewall, DNS resolver; script auto-retry 5× |
| Memori tidak cukup | Tutup aplikasi lain; tambahkan swap; set `CHUNK_SIZE=5000` |
| Output tidak sesuai | Periksa TLD IANA; lakukan `diff` dengan output sebelumnya |
| Permission denied | `chmod +x trustpositif-validator.sh`; periksa izin `OUTPUT_DIR` |

---

## License

```text
Copyright (c) 2024–2026
Harry Dertin Sutisna Alsyundawy

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

**Lisensi: MIT License** — Anda bebas untuk mengubah, mendistribusikan, dan menggunakan script ini untuk keperluan apa pun. 📝

See [LICENSE](LICENSE) for full text.

---

## Author

### HARRY DERTIN SUTISNA ALSYUNDAWY

- Email   : [alsyundawy@gmail.com](mailto:alsyundawy@gmail.com)
- Phone   : +62 856-8515-212
- Website : [alsyundawy.com](https://alsyundawy.com)

---

## Donasi / Support ☕

Jika Anda merasa terbantu dan ingin mendukung proyek ini, pertimbangkan untuk berdonasi. Terima kasih atas dukungannya!

### Donasi via PayPal

[Klik di sini untuk donasi via PayPal](https://www.paypal.me/alsyundawy)

### Donasi via QRIS

![QRIS Donation](https://github.com/user-attachments/assets/a0126f28-6dde-43da-ba14-d7c9a27de0df)

---

## Catatan Penggunaan Domain List

> **Perhatian:** Daftar domain yang dihasilkan hanya dapat digunakan untuk konfigurasi **wildcard** pada DNS/RPZ.
> Pastikan sistem DNS Anda mendukung format wildcard blocklist sebelum menggunakan output script ini.

---

## Pesan dari Penulis 🤣

> **Jangan semangat, tetaplah putus asa.**
> Tetap mengeluh, walau tak ada yang merasa.
>
> Ketika yang lain bisa, **kenapa harus saya?**
> Ketika yang lain tidak bisa, **apalagi saya.**
>
> Tetaplah hidup, meski kontribusi tak seberapa.
> Tetaplah hadir, walau cuma jadi beban suasana.
>
> **Maju tak gentar, membela yang bayar.**
> Kalau gratisan, nanti dulu saudara.
>
> Yoi...
> **Ya begitulah hidup: kadang absurd, kadang lapar, kadang pura-pura tegar.** 🤣

### ✨ ANDA MEMANG LUAR BIASA | HARRY DS ALSYUNDAWY | KAUM REBAHAN GARIS KERAS & MILITAN ✨

---

## Analytics

![Repobeats](https://repobeats.axiom.co/api/embed/06cb45618374fd127021d7c32321a60acabd626e.svg "Repobeats analytics image")

---

*Built with precision for enterprise-scale DNS/RPZ blocklist automation.*
